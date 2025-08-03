
#include <fmt/format.h>

#include "utils.hpp"
#include "paging.hpp"
#include "emulator.hpp"

Emulator g_Emulator;
TimeFrames_t g_TimeFrames;

std::size_t g_LastInstructionExecuted = 0;

long long g_RelativeOffset = 1;
bool CreateCheckPoint_ = true;
constexpr bool BochsDebugging = false;
constexpr uint32_t MaxBreakpointCount = 300;

template <typename... Args_t>
void BochsDbg(const char* Format, const Args_t &...args) {
	if constexpr (BochsDebugging) {
		fmt::print("bochs: ");
		fmt::print(fmt::runtime(Format), args...);
	}
}

Emulator::Emulator() {
	std::memset(&Hooks_, 0, sizeof(Hooks_));
	std::memset(&HookChain_, 0, sizeof(HookChain_));
}

static constexpr std::uint64_t PageAlign(std::uint64_t Address) {
	return Address & ~0xfff;
}

void Emulator::StaticGpaMissingHandler(const std::uint64_t Gpa) {

	BochsDbg("Mapping GPA: {:#x}\n", Gpa);

	//
	// Align the GPA.
	//

	const std::uint64_t AlignedGpa = PageAlign(Gpa);

	const void* PhyPage
		= g_Emulator.GetPhysicalPage(AlignedGpa);
	if (PhyPage == nullptr) {
		BochsDbg("Failed to fetch memory for {:#x}\n", Gpa);
	}

	static std::size_t Left = 0;
	static std::uint8_t* Current = nullptr;
	if (!Left) {

		//
		// It's time to reserve a 64KB region.
		//

		const std::uint64_t _64KB = 1024 * 64;
		Left = _64KB;
		Current =
			(std::uint8_t*)VirtualAlloc(nullptr, Left, MEM_RESERVE, PAGE_READWRITE);
	}

	//
	// Commit a page off the reserved region.
	//

	std::uint8_t* Page
		= (std::uint8_t*)VirtualAlloc(Current, Page::Size, MEM_COMMIT, PAGE_READWRITE);

	Left -= Page::Size;
	Current += Page::Size;

	if (Page == nullptr) {
		BochsDbg("Failed to allocate memory in GpaMissingHandler.\n");
		__debugbreak();
	}

	if (PhyPage) {
		//
		// Copy the dump page into the new page.
		//

		std::memcpy(Page, PhyPage, Page::Size);
	}
	else {
		std::memset(Page, 0, Page::Size);
	}

	g_Emulator.MappedPhyPages_.insert(AlignedGpa);
	bochscpu_mem_page_insert(AlignedGpa, Page);
}

bool Emulator::IsGvaMapped(std::uint64_t VirtualAddress) const {
	std::uint64_t Gpa = 0;
	if (!VirtTranslate(VirtualAddress, Gpa)) {
		BochsDbg("[*] Translation for GVA {:#x} failed\n", VirtualAddress);
		return false;
	}
	return MappedPhyPages_.contains(AlignPage(Gpa)); 
}

void Emulator::StaticPhyAccessHook(void* Context, uint32_t Id, uint64_t PhysicalAddress,
	uintptr_t Len, uint32_t MemType, uint32_t MemAccess) {

	g_Emulator.PhyAccessHook(Id, PhysicalAddress, Len, MemType, MemAccess);
}

void Emulator::StaticAfterExecutionHook(void* Context, uint32_t Id, void* Ins) {
	g_Emulator.AfterExecutionHook(Id, Ins);
}

void Emulator::StaticBeforeExecutionHook(void* Context, uint32_t Id, void* Ins) {
	g_Emulator.BeforeExecutionHook(Id, Ins);
}

void Emulator::StaticLinAccessHook(void* Context, uint32_t Id, uint64_t VirtualAddress,
	uint64_t PhysicalAddress, uintptr_t Len,
	uint32_t MemType, uint32_t MemAccess) {

	g_Emulator.LinAccessHook(Id, VirtualAddress, PhysicalAddress, Len, MemType, MemAccess);
}

void Emulator::StaticInterruptHook(void* Context, uint32_t Id, uint32_t Vector) {

	g_Emulator.InterruptHook(Id, Vector);
}

void Emulator::StaticExceptionHook(void* Context, uint32_t Id, uint32_t Vector,
	uint32_t ErrorCode) {

	g_Emulator.ExceptionHook(Id, Vector, ErrorCode);
}

void Emulator::StaticTlbControlHook(void* Context, uint32_t Id, uint32_t What,
	uint64_t NewCrValue) {

	g_Emulator.TlbControlHook(Id, What, NewCrValue);
}

void Emulator::StaticOpcodeHook(void* Context, uint32_t Id, const void* i,
	const uint8_t* opcode, uintptr_t len, bool is32,
	bool is64) {

	// TODO
}

void Emulator::StaticHltHook(void* Context, uint32_t Cpu) {
	// TODO
}

void Emulator::StaticCNearBranchHook(void* Context, uint32_t Cpu, uint64_t Rip,
	uint64_t NextRip) {

	g_Emulator.CNearBranchHook(Cpu, Rip, NextRip);
}

void Emulator::StaticUcNearBranchHook(void* Context, uint32_t Cpu, uint32_t What,
	uint64_t Rip, uint64_t NextRip) {
	
	g_Emulator.UcNearBranchHook(Cpu, What, Rip, NextRip);
}

void Emulator::StaticUcFarBranchHook(void* Context, uint32_t Cpu, uint32_t What,
	uint16_t a1, uint64_t Rip, uint16_t a2, uint64_t NextRip) {

	g_Emulator.UcFarBranchHook(Cpu, What, a1, Rip, a2, NextRip);
}

// //vgk+0x95754
bool Emulator::Initialize(const CpuState_t& State) {
	//
	// Create a cpu.
	//

	Cpu_ = bochscpu_cpu_new(0);

	//
	// Preapare the hooks.
	//

	Hooks_.ctx = this;
	Hooks_.after_execution = StaticAfterExecutionHook;
	Hooks_.before_execution = StaticBeforeExecutionHook;
	Hooks_.lin_access = StaticLinAccessHook;
	Hooks_.interrupt = StaticInterruptHook;
	Hooks_.exception = StaticExceptionHook;
	Hooks_.phy_access = StaticPhyAccessHook;
	Hooks_.tlb_cntrl = StaticTlbControlHook;
	Hooks_.hlt = StaticHltHook;
	Hooks_.cnear_branch_not_taken = StaticCNearBranchHook;
	Hooks_.cnear_branch_taken = StaticCNearBranchHook;
	Hooks_.ucnear_branch = StaticUcNearBranchHook;

	CheckPoints_.clear();

	HookChain_[0] = &Hooks_;
	HookChain_[1] = nullptr;

	bochscpu_mem_missing_page(StaticGpaMissingHandler);

	//
	// Load the state into the CPU.
	//

	LoadState(State);
	AddNewCheckPoint();

	//
	// Install bugcheck callback
	//
	AddHook(g_Debugger.GetDbgSymbol("nt!KeBugCheck2"), [&](Emulator* Emu) {
		if (DisableBugCheckHook_) {
			return;
		}

		const uint32_t BCode = uint32_t(GetArg(0));
		const uint64_t B0 = GetArg(1);
		const uint64_t B1 = GetArg(2);
		const uint64_t B2 = GetArg(3);
		const uint64_t B3 = GetArg(4);

		std::println("*** Fatal System Error: {:#08x}", BCode);
		std::println("\tKeBugCheckEx({:#016x}, {:#016x}, {:#016x}, {:#016x}, {:#016x})",
			BCode, B0, B1, B2, B3);
		std::println("\tError Type: {}", BugCheckCodeNames.at(BCode));
		std::print("\n");
		std::println("A fatal system error has occurred.");
		std::println("\tUse !unshadow to return to the original debugger, or run g-, t-, or p- to unwind machine state.");
		Stop(1);
	});

	return true;
}

std::uint64_t Emulator::GetArgAddress(const uint64_t Idx) const {
	if (Idx <= 3) {
		fmt::print("The first four arguments are stored in registers (@rcx, @rdx, "
			"@r8, @r9) which means you cannot get their addresses.\n");
		std::abort();
	}

	return bochscpu_cpu_rsp(Cpu_) + (8 + (Idx * 8));
}

std::uint64_t Emulator::GetArg(unsigned int Index) const {
	switch (Index) {
	case 0:
		return bochscpu_cpu_rcx(Cpu_);
	case 1:
		return bochscpu_cpu_rdx(Cpu_);
	case 2:
		return bochscpu_cpu_r8(Cpu_);
	case 3:
		return bochscpu_cpu_r9(Cpu_);
	default: {
		return VirtRead8(GetArgAddress(Index));
	}
	}
}

void Emulator::Run(const std::uint64_t EndAddress) {

	//
	// Clear revert status
	//
	ReachedRevertEnd_ = false;

	//
	// Set end point
	//
	ExecEndAddress_ = EndAddress;
	g_LastInstructionExecuted = 0;

	//
	// Lift off.
	//

	BochsDbg("Emulation start.\n");

	bochscpu_cpu_run(Cpu_, HookChain_);
}

bool Emulator::VirtTranslate(const std::uint64_t Gva, std::uint64_t& Gpa) const {
	const uint64_t Cr3 = bochscpu_cpu_cr3(Cpu_);
	Gpa = bochscpu_mem_virt_translate(Cr3, Gva);
	return Gpa != 0xffffffffffffffff;
}

uint8_t* Emulator::PhysTranslate(const std::uint64_t Gpa) const {
	return bochscpu_mem_phy_translate(Gpa);
}

#undef min

bool Emulator::VirtRead(const std::uint64_t Gva, std::uint8_t* Buffer, const std::uint64_t BufferSize) const {
	std::uint64_t Size = BufferSize;
	std::uint64_t CurrentGva = Gva;
	while (Size > 0) {
		std::uint64_t Gpa;
		const bool Translate =
			VirtTranslate(CurrentGva, Gpa);

		if (!Translate) {
			std::print("Translation of GVA {:#x} failed\n", CurrentGva);
			return false;
		}

		const std::uint64_t GvaOffset = CurrentGva & 0xfff;
		const uint64_t BytesReadable = Page::Size - GvaOffset;
		const uint64_t Size2Read = std::min(Size, BytesReadable);
		const uint8_t* Hva = PhysTranslate(Gpa);
		memcpy(Buffer, Hva, Size2Read);
		Size -= Size2Read;
		CurrentGva += Size2Read;
		Buffer += Size2Read;
	}

	return true;
}

std::uint64_t Emulator::VirtRead8(std::uint64_t Gva) const {
	std::uint64_t Value;
	VirtRead(Gva, (std::uint8_t*)&Value, 8);
	return Value;
}

std::uint32_t Emulator::VirtRead4(std::uint64_t Gva) const {
	std::uint32_t Value;
	VirtRead(Gva, (std::uint8_t*)&Value, 4);
	return Value;
}

std::uint16_t Emulator::VirtRead2(std::uint64_t Gva) const {
	std::uint16_t Value;
	VirtRead(Gva, (std::uint8_t*)&Value, 2);
	return Value;
}

std::uint8_t Emulator::VirtRead1(std::uint64_t Gva) const {
	std::uint8_t Value;
	VirtRead(Gva, (std::uint8_t*)&Value, 1);
	return Value;
}

void Emulator::StepInto() {
	ExecutionVector_ = ExecutionVector::Foward;

	InstructionLimit_ = 1;
	Run();
	InstructionLimit_ = 0;
}

void Emulator::StepOver() {
	ExecutionVector_ = ExecutionVector::Foward;

	StepOver_ = true;
	InstructionLimit_ = 1;
	
	Run();

	StepOver_ = false;
	InstructionLimit_ = 0;
}

bool Emulator::VirtWrite(const std::uint64_t Gva, const uint8_t* Buffer,
	const uint64_t BufferSize) {

	std::uint64_t Size = BufferSize;
	std::uint64_t CurrentGva = Gva;
	while (Size > 0) {
		std::uint64_t Gpa;
		const bool Translate = VirtTranslate(
			CurrentGva, Gpa);

		if (!Translate) {
			BochsDbg("Translation of GVA {:#x} failed\n", CurrentGva);
			return false;
		}

		const std::uint64_t GvaOffset = CurrentGva & 0xfff;
		const std::uint64_t BytesWriteable = Page::Size - GvaOffset;
		const std::uint64_t Size2Write = std::min(Size, BytesWriteable);
		std::uint8_t* Hva = PhysTranslate(Gpa);
		std::memcpy(Hva, Buffer, Size2Write);

		Size -= Size2Write;
		CurrentGva += Size2Write;
		Buffer += Size2Write;
	}

	return true;
}

void Emulator::PrintSimpleStepStatus() const {
	if (const auto& AddressName = g_Debugger.GetName(Rip(), true); !AddressName.empty()) {
		std::println("{}", AddressName);
	}
	std::print("{}", g_Debugger.Disassemble(Rip()).value_or("???"));
}

bool Emulator::VirtWrite8(const std::uint64_t Gva, const std::uint64_t Value) {
	return VirtWrite(Gva, (std::uint8_t*)&Value, 8);
}

bool Emulator::VirtWrite4(const std::uint64_t Gva, const std::uint32_t Value) {
	return VirtWrite(Gva, (std::uint8_t*)&Value, 4);
}

bool Emulator::VirtWrite2(const std::uint64_t Gva, const std::uint16_t Value) {
	return VirtWrite(Gva, (std::uint8_t*)&Value, 2);
}

bool Emulator::VirtWrite1(const std::uint64_t Gva, const std::uint8_t Value) {
	return VirtWrite(Gva, (std::uint8_t*)&Value, 1);
}

void Emulator::AfterExecutionHook(uint32_t, void*) {
	InstructionExecutedCount_ += 1;
	g_LastInstructionExecuted += 1;

	PrevPrevRip_ = PrevRip_;
	PrevRip_	 = Rip();

	if (InstructionExecutedCount_ > MaxiumInstructionLimit_) {
		std::println("Reached execution limit, stopping");
		Stop(0);
	}
}

bool IsCallinstruction(std::uint8_t* Code) {
	int OpcodeOffset = 0;

	if (Code[0] >> 4 == 0b0100) {
		OpcodeOffset += 1;
	}

	return Code[OpcodeOffset] == 0xE8 || Code[OpcodeOffset] == 0xFF
		|| Code[OpcodeOffset] == 0x9A;
}

bool IsRetInstruction(std::uint8_t* Code) {
	int OpcodeOffset = 0;

	if (Code[0] >> 4 == 0b0100) {
		OpcodeOffset += 1;
	}

	return Code[OpcodeOffset] == 0xC3 || Code[OpcodeOffset] == 0xCB || Code[OpcodeOffset] == 0xC2
		|| Code[OpcodeOffset] == 0xCA || Code[OpcodeOffset] == 0xCF; 
}

void Emulator::BeforeExecutionHook(uint32_t, void* Ins) {

	//
	// Stop if exceed maxium instruction executed allowed
	//
	if (InstructionLimit_ && InstructionExecutedCount_ >= InstructionLimit_) {
		BochsDbg("Reached execution limit, stopping emulator...\n");
		Stop(0);
	}

	//
	// Stop the cpu if we reached end address.
	//
	if (bochscpu_cpu_rip(Cpu_) == ExecEndAddress_) [[unlikely]] {
		BochsDbg("Reached end address, stopping emulator...\n");
		Stop(0);
	}

	//
	// If user have installed a hook at this address, invoke them:
	//

	if (UserHooks_.contains(Rip())) {
		UserHooks_.at(Rip())(this);
	}
}

static std::string Hexdump(const std::uint8_t* Data, std::size_t Size) {
	if (Size == 8) {
		return std::format("{:#016x}", *(std::uint64_t*)Data);
	}

	std::string Format = "";
	for (int i = 0; i < Size; i++) {
		Format += std::format("{:02x} ", Data[i]);
	}
	return Format;
}

void Emulator::LinAccessHook(uint32_t,
	uint64_t VirtualAddress,
	uint64_t PhysicalAddress, uintptr_t Len,
	uint32_t, uint32_t MemAccess) {

	if (MemAccess != BOCHSCPU_HOOK_MEM_WRITE &&
		MemAccess != BOCHSCPU_HOOK_MEM_RW) {
		return;
	}
	
	AddDirtyToCheckPoint(VirtualAddress, Len);
	// DirtyPhysicalMemoryRange(PhysicalAddress, Len);
}

bool Emulator::DirtyGpaPage(const std::uint64_t Gpa) {
	auto AlignGpa = AlignPage(Gpa);
	if (DirtiedPage_.contains(AlignGpa)) {
		return false;
	}

	BochsDbg(
		"DirtyPhysicalMemoryRange: Adding GPA {:#x} to the dirty set..\n",
		Gpa);

	auto OriginalPage = std::make_unique<std::uint8_t[]>(Page::Size);
	const std::uint8_t* OriginalPageData
		= g_Debugger.GetPhysicalPage(Gpa);

	if (!OriginalPageData) {
		return false; // Don't store this page!
	}

	memcpy(OriginalPage.get(), OriginalPageData, Page::Size);
	DirtiedPage_[AlignGpa] = std::move(OriginalPage);
	return true;
}

void Emulator::PhyAccessHook(uint32_t,
	uint64_t PhysicalAddress, uintptr_t Len,
	uint32_t, uint32_t MemAccess) {


	if (MemAccess != BOCHSCPU_HOOK_MEM_WRITE &&
		MemAccess != BOCHSCPU_HOOK_MEM_RW) {
		return;
	}

	// DirtyPhysicalMemoryRange(PhysicalAddress, Len);
}

void Emulator::InterruptHook(uint32_t, uint32_t Vector) {

	//
	// Hit an exception, dump it on stdout.
	//

	BochsDbg("InterruptHook: Vector({:#x})\n", Vector);

	//
	// If we trigger a breakpoint it's probably time to stop the cpu.
	//
}

void Emulator::ExceptionHook(uint32_t,
	uint32_t Vector, uint32_t ErrorCode) {

	BochsDbg("ExceptionHook: Vector({:#x}), ErrorCode({:#x})\n",
		Vector, ErrorCode);
}

void Emulator::TlbControlHook(uint32_t,
	uint32_t What, uint64_t NewCrValue) {

	// TODO
}

void Emulator::CNearBranchHook(uint32_t Cpu, uint64_t Rip,
	uint64_t NextRip) {

	AddNewCheckPoint();

	if (RunTillBranch_) {
		BochsDbg("[*] Reached branch instruction, stopping cpu...\n");
		Stop(0);
	}
}

void Emulator::Stop(int value) {
	InstructionExecutedCount_ = 0;
	ExecEndAddress_ = 0;

	RunTillBranch_ = false;
	GoingUp_ = false;
	StepOver_ = false;
	ReverseStepOver_ = false;
	IsReverseStepInto_ = false;
	ReachedRevertEnd_ = false;
	DisableBugCheckHook_ = false;


	bochscpu_cpu_stop(Cpu_); 
}

std::optional<uint32_t> Emulator::LocateFreeBreakpointId() {
	uint32_t index = 0;
	for (index = 0; index < MaxBreakpointCount; index++) {
		if (!BreakpointIdToAddress_.contains(index)) {
			return index;
		}
	}

	return {};
}

void Emulator::ListBreakpoint() const {
	for (const auto& [Id, Address] : BreakpointIdToAddress_) {
		std::println("     {} e\t\t{:016x}\t{}",
			Id, Address, g_Debugger.GetName(Address, true));
	}
}

const std::unordered_map<uint32_t, std::uint64_t>&
Emulator::GetBreakpoints() const {
	return BreakpointIdToAddress_;
}

bool Emulator::RemoveCodeBreakpoint(uint32_t Index) {
	if (!BreakpointIdToAddress_.contains(Index)) {
		return false;
	}

	const auto BreakpointAddress = BreakpointIdToAddress_.at(Index);
	BreakpointIdToAddress_.erase(Index);

	UserHooks_.erase(BreakpointAddress);
	return true;
}

bool Emulator::InsertCodeBreakpoint(std::uint64_t Address) {
	std::optional<uint32_t> FreeBreakpointIndex = std::nullopt;
	if (FreeBreakpointIndex = LocateFreeBreakpointId(); !FreeBreakpointIndex.has_value()) {
		return false;
	}

	BreakpointIdToAddress_[FreeBreakpointIndex.value()] = Address;
	if (!UserHooks_.emplace(Address, [this, FreeBreakpointIndex](Emulator* Emu) {
		std::println("Breakpoint {} hit", FreeBreakpointIndex.value());
		Emu->Stop(0);
		PrintSimpleStepStatus();
	}).second) {
		std::println("breakpoint {} redefined", Address);
		return false;
	}
	return true;
}

void Emulator::UcNearBranchHook(uint32_t Cpu, uint32_t What,
	uint64_t Rip, uint64_t NextRip) {

	uint16_t Opcode = VirtRead2(Rip);
	if (StepOver_ && IsCallinstruction((uint8_t*)&Opcode)) {
		auto ReturnAddress = VirtRead8(bochscpu_cpu_rsp(Cpu_));
		InstructionLimit_ = 0;
		if (!ExecEndAddress_) {
			ExecEndAddress_ = ReturnAddress;
		}
	}

	if (IsCallinstruction((uint8_t*)&Opcode)) [[unlikely]] {
		CallTrace_.emplace_back(
			bochscpu_cpu_rsp(Cpu_),
			VirtRead8(bochscpu_cpu_rsp(Cpu_)),
			NextRip);
	}

	if (IsRetInstruction((uint8_t*)&Opcode)) {
		if (!CallTrace_.empty()) {
			CallTrace_.pop_back();
		}
	}

	Opcode = VirtRead2(PrevRip_);
	if (GoingUp_ && IsRetInstruction((uint8_t*)&Opcode)) {
		BochsDbg("[*] Reached branch instruction, stopping cpu...\n");
		Stop(0);
	}

	AddNewCheckPoint();

	bool GoingUpEnd = (What == BOCHSCPU_INSTR_IS_IRET || What == BOCHSCPU_INSTR_IS_RET && GoingUp_);
	if (RunTillBranch_ || GoingUpEnd) {
		BochsDbg("[*] Reached branch instruction, stopping cpu...\n");
		Stop(0);
	}
}

void Emulator::UcFarBranchHook(uint32_t Cpu, uint32_t What,
	uint16_t a1, uint64_t Rip, uint16_t a2, uint64_t NextRip) {

	uint16_t Opcode = VirtRead2(Rip);
	if (IsCallinstruction((uint8_t*)&Opcode) && StepOver_) {
		auto ReturnAddress = VirtRead8(bochscpu_cpu_rsp(Cpu_));
		InstructionLimit_ = 0;
		ExecEndAddress_ = ReturnAddress;
	}

	if (GoingUp_ && IsRetInstruction((uint8_t*)&Opcode)) {
		BochsDbg("[*] Reached branch instruction, stopping cpu...\n");
		Stop(0);
	}

	AddNewCheckPoint();

	bool GoingUpEnd = (What == BOCHSCPU_INSTR_IS_IRET || What == BOCHSCPU_INSTR_IS_RET && GoingUp_);
	if (RunTillBranch_ || GoingUpEnd) {
		BochsDbg("[*] Reached branch instruction (far), stopping cpu...\n");
		Stop(0);
	}
}

void Emulator::GoUp() {
	GoingUp_ = true;
	Run();
	GoingUp_ = false;

	if (const auto& AddressName = g_Debugger.GetName(Rip(), true); !AddressName.empty()) {
		std::println("{}", AddressName);
	}

	std::print("{}", g_Debugger.Disassemble(Rip()).value_or("???"));
}


void Emulator::ReverseGo() {
	if (ReachedRevertEnd_) {
		return;
	}

	DisableBugCheckHook_ = true;

	while (CheckPoints_.size() > 1) {
		auto PrevState = CheckPoints_.back(); 
		CheckPoints_.pop_back();

		for (const auto& [Address, Dirty] : PrevState.DirtiedBytes_) {
			VirtWrite(Address, Dirty.data(), Dirty.size());
		}
		
		const auto& PrevCpuState = RestoreCpuStateFromDelta(PrevState.CpuStateDelta_);

		bochscpu_cpu_set_state(
			Cpu_,
			&PrevCpuState);
		ReverseStepInto();
	}

	DisableBugCheckHook_ = false;

	const auto& PInitial = CheckPoints_.back();
	const auto& PrevState = RestoreCpuStateFromDelta(PInitial.CpuStateDelta_);
	for (const auto& [Address, Dirty] : PInitial.DirtiedBytes_) {
		VirtWrite(Address, Dirty.data(), Dirty.size());
	}

	bochscpu_cpu_set_state(Cpu_, &PrevState);
}

void Emulator::ReverseStepInto() {
	ExecutionVector_ = ExecutionVector::Reverse;

	if (ReachedRevertEnd_) {
		return;
	}

	const auto& PrevState = CheckPoints_.empty() ? QueuedCheckPoint_.value() : CheckPoints_.back();
	for (const auto& [Address, Dirty] : PrevState.DirtiedBytes_) {
		VirtWrite(Address, Dirty.data(), Dirty.size());
	}

	const auto& PrevCpuState = RestoreCpuStateFromDelta(PrevState.CpuStateDelta_);
	bochscpu_cpu_set_state(Cpu_, &PrevCpuState);

	IsReverseStepInto_ = true;
	CreateCheckPoint_ = false;

	Run(PrevPrevRip_);

	IsReverseStepInto_ = false;
	CreateCheckPoint_ = true;

	//
	// Simulate windbg output
	//
	if (g_LastInstructionExecuted < 2) {
		if (CheckPoints_.size() <= 1) {
			std::println("Reached backstep end");
			ReachedRevertEnd_ = true;
			return;
		}

		PrevPrevRip_ = GetPcFromDeltaState(CheckPoints_.back().CpuStateDelta_);
		CheckPoints_.pop_back();
	}
}

void Emulator::ReverseStepOver() {
	auto Instr = VirtRead2(PrevPrevRip_);

	if (IsRetInstruction((uint8_t*)&Instr)) {
		int Offset = 1;
		while (Offset && !ReachedRevertEnd_) {
			ReverseStepInto();
			Instr = VirtRead2(Rip());

			if (IsCallinstruction((uint8_t*)&Instr)) { Offset -= 1; }
			else if (IsRetInstruction((uint8_t*)&Instr)) { Offset += 1; }
		}

		return;
	}

	ReverseStepInto();
}

void Emulator::PrintStackTrace() const {
	std::println("# Child-SP          RetAddr               Call Site");
	int Index = 0;
	for (auto CallInfo = CallTrace_.rbegin(); CallInfo != CallTrace_.rend(); ++CallInfo) {
		auto CallSiteFmt = std::format("{:016x}", CallInfo->Callsite);
		if (const auto& Sym = g_Debugger.GetName(CallInfo->Callsite, true); !Sym.empty()) {
			CallSiteFmt = Sym;
		}

		std::println("{} {:016x}  {:016x}      {}",
			Index,
			CallInfo->ChildSp,
			CallInfo->RetAddr,
			CallSiteFmt);
		
		Index += 1;
	}
}

const std::uint8_t* Emulator::GetPhysicalPage(const std::uint64_t PhysicalAddress) const {
	return g_Debugger.GetPhysicalPage(PhysicalAddress);
}

using BochscpuGetReg_t = uint64_t(*)(bochscpu_cpu_t);
static const std::unordered_map<Registers_t, BochscpuGetReg_t>
RegisterMappingGetters = { 
	{Registers_t::Rax, bochscpu_cpu_rax},
	{Registers_t::Rbx, bochscpu_cpu_rbx},
	{Registers_t::Rcx, bochscpu_cpu_rcx},
	{Registers_t::Rdx, bochscpu_cpu_rdx},
	{Registers_t::Rsi, bochscpu_cpu_rsi},
	{Registers_t::Rdi, bochscpu_cpu_rdi},
	{Registers_t::Rip, bochscpu_cpu_rip},
	{Registers_t::Rsp, bochscpu_cpu_rsp},
	{Registers_t::Rbp, bochscpu_cpu_rbp},
	{Registers_t::R8, bochscpu_cpu_r8},
	{Registers_t::R9, bochscpu_cpu_r9},
	{Registers_t::R10, bochscpu_cpu_r10},
	{Registers_t::R11, bochscpu_cpu_r11},
	{Registers_t::R12, bochscpu_cpu_r12},
	{Registers_t::R13, bochscpu_cpu_r13},
	{Registers_t::R14, bochscpu_cpu_r14},
	{Registers_t::R15, bochscpu_cpu_r15},
	{Registers_t::Rflags, bochscpu_cpu_rflags},
	{Registers_t::Cr2, bochscpu_cpu_cr2},
	{Registers_t::Cr3, bochscpu_cpu_cr3} 
};


using BochscpuSetReg_t = void (*)(bochscpu_cpu_t, uint64_t);
static const std::unordered_map<Registers_t, BochscpuSetReg_t>
Register64MappingSetters = { 
	{Registers_t::Rax, bochscpu_cpu_set_rax},
	{Registers_t::Rbx, bochscpu_cpu_set_rbx},
	{Registers_t::Rcx, bochscpu_cpu_set_rcx},
	{Registers_t::Rdx, bochscpu_cpu_set_rdx},
	{Registers_t::Rsi, bochscpu_cpu_set_rsi},
	{Registers_t::Rdi, bochscpu_cpu_set_rdi},
	{Registers_t::Rip, bochscpu_cpu_set_rip},
	{Registers_t::Rsp, bochscpu_cpu_set_rsp},
	{Registers_t::Rbp, bochscpu_cpu_set_rbp},
	{Registers_t::R8,  bochscpu_cpu_set_r8},
	{Registers_t::R9,  bochscpu_cpu_set_r9},
	{Registers_t::R10, bochscpu_cpu_set_r10},
	{Registers_t::R11, bochscpu_cpu_set_r11},
	{Registers_t::R12, bochscpu_cpu_set_r12},
	{Registers_t::R13, bochscpu_cpu_set_r13},
	{Registers_t::R14, bochscpu_cpu_set_r14},
	{Registers_t::R15, bochscpu_cpu_set_r15},
	{Registers_t::Rflags, bochscpu_cpu_set_rflags},
	{Registers_t::Cr2, bochscpu_cpu_set_cr2},
	{Registers_t::Cr3, bochscpu_cpu_set_cr3} 
};

using BochscpuSetSegReg_t = void (*)(bochscpu_cpu_t, const bochscpu_cpu_seg_t*);
static const std::unordered_map<Registers_t, BochscpuSetSegReg_t>
RegisterSelMappingSetters = {
	{Registers_t::Cs,   bochscpu_cpu_set_cs},
	{Registers_t::Ds,   bochscpu_cpu_set_ds},
	{Registers_t::Es,   bochscpu_cpu_set_es},
	{Registers_t::Fs,   bochscpu_cpu_set_fs},
	{Registers_t::Gs,   bochscpu_cpu_set_gs},
	{Registers_t::Ss,   bochscpu_cpu_set_ss},
	{Registers_t::Tr,   bochscpu_cpu_set_tr},
	{Registers_t::Ldtr, bochscpu_cpu_set_ldtr},
};

using BochscpuGetSegReg_t = void(*)(bochscpu_cpu_t, bochscpu_cpu_seg_t*);
static const std::unordered_map<Registers_t, BochscpuGetSegReg_t>
RegisterSelMappingGetters = {
	{Registers_t::Cs,   bochscpu_cpu_cs},
	{Registers_t::Ds,   bochscpu_cpu_ds},
	{Registers_t::Es,   bochscpu_cpu_es},
	{Registers_t::Fs,   bochscpu_cpu_fs},
	{Registers_t::Gs,   bochscpu_cpu_gs},
	{Registers_t::Ss,   bochscpu_cpu_ss},
	{Registers_t::Tr,   bochscpu_cpu_tr},
	{Registers_t::Ldtr, bochscpu_cpu_ldtr},
};

bool Emulator::GetReg(const Registers_t Reg, REGVAL* Value) const {
	if (RegisterMappingGetters.contains(Reg)) {
		const BochscpuGetReg_t& Getter = RegisterMappingGetters.at(Reg);
		Value->Type = REGVAL_TYPE_I64;
		Value->u.I64 = Getter(Cpu_);
		return true;
	}

	if (RegisterSelMappingGetters.contains(Reg)) {
		bochscpu_cpu_seg_t Seg;
		RegisterSelMappingGetters.at(Reg)(Cpu_, &Seg);

		Value->Type = REGVAL_TYPE_I16;
		Value->u.I16 = Seg.selector;
		return true;
	}

	if (Registers_t::Xmm0 <= Reg && Reg <= Registers_t::Xmm15) {
		bochscpu_cpu_zmm_t ZmmN;
		bochscpu_cpu_zmm(Cpu_, Reg - Registers_t::Xmm0, &ZmmN);
		
		Value->Type = REGVAL_TYPE_VF128;
		Value->u.VF128 = ZmmN;

		return true;
	}

	if (Registers_t::Ymm0 <= Reg && Reg <= Registers_t::Ymm15) {
		bochscpu_cpu_zmm_t ZmmN;
		bochscpu_cpu_zmm(Cpu_, Reg - Registers_t::Ymm0, &ZmmN);

		Value->Type = REGVAL_TYPE_VF256;
		Value->u.VF256 = ZmmN;

		return true;
	}

	if (Registers_t::Zmm0 <= Reg && Reg <= Registers_t::Zmm31) {
		Value->Type = REGVAL_TYPE_VF512;
		static_assert(sizeof(bochscpu_cpu_zmm_t) == sizeof(Value->u.VF512));
		bochscpu_cpu_zmm(Cpu_, Reg - Registers_t::Zmm0, (bochscpu_cpu_zmm_t*)&Value->u.VF512);

		return true;
	}

	BochsDbg("There is no mapping for register {:#x}.\n", (uint64_t)Reg);
	return false;
}

void Emulator::AddDirtyToCheckPoint(std::uint64_t Address, std::size_t Size) {
	std::vector<uint8_t> OriginalData(Size);
	VirtRead(Address, OriginalData.data(), Size);

	if (CheckPoints_.empty()) {
		QueuedCheckPoint_.value().DirtiedBytes_[Address] = OriginalData;
		return;
	}

	if (!CheckPoints_.back().DirtiedBytes_.contains(Address)) {
		CheckPoints_.back().DirtiedBytes_[Address] = OriginalData;
	}
}

bool Emulator::SetReg(const Registers_t Reg,
	const REGVAL* Value) {
	
	if (Register64MappingSetters.contains(Reg) && RegisterMappingGetters.contains(Reg)) {
		const BochscpuSetReg_t& Setter = Register64MappingSetters.at(Reg);
		const BochscpuGetReg_t& Getter = RegisterMappingGetters.at(Reg);

		uint64_t original = Getter(Cpu_);
		uint64_t result = original;

		//
		// Save original RIP for further use
		//
		if (Reg == Registers_t::Rip) {
			PrevRip_ = original;
		}

		switch (Value->Type) {
		case REGVAL_TYPE_I16:
			result = (original & ~0xFFFFull) | (Value->u.I16 & 0xFFFF);
			break;

		case REGVAL_TYPE_I32:
			result = (original & ~0xFFFFFFFFull) | (Value->u.I32 & 0xFFFFFFFF);
			break;

		case REGVAL_TYPE_I64:
			result = Value->u.I64;
			break;

		default:
			std::println("[!] Unsupported REGVAL type {} for register write", static_cast<int>(Value->Type));
			return false;
		}

		Setter(Cpu_, result);
		return true;
	}

	if (RegisterSelMappingSetters.contains(Reg) && RegisterSelMappingGetters.contains(Reg)) {
		bochscpu_cpu_seg_t Seg;
		RegisterSelMappingGetters.at(Reg)(Cpu_, &Seg);

		Seg.selector = Value->u.I16;
		RegisterSelMappingSetters.at(Reg)(Cpu_, &Seg);

		return true;
	}

	std::print("There is no mapping for register {:#x}.\n", (int)Reg);
	return false;
}

void Emulator::Reset() {
	MappedPhyPages_.clear();
	DirtiedPage_.clear();
	ExecEndAddress_		= 0;
	InstructionLimit_	= 0;
	
	InstructionExecutedCount_ = 0;
	MappedPhyPages_.clear();
	PrevPrevRip_		= 0;
	PrevRip_			= 0;
	RunTillBranch_		= false;
	GoingUp_			= false;
	StepOver_			= false;
	ReverseStepOver_	= false;
	IsReverseStepInto_	= false;
	ReachedRevertEnd_	= false;
	CheckPoints_.clear();

	bochscpu_cpu_delete(Cpu_);
}

std::size_t TotalCheckPointRecorded = 0;

std::string ToHuman(std::uint64_t value) {
	constexpr std::array units{ "B", "KB", "MB", "GB", "TB", "PB", "EB" };
	double size = static_cast<double>(value);
	std::size_t unitIndex = 0;

	while (size >= 1024.0 && unitIndex < units.size() - 1) {
		size /= 1024.0;
		++unitIndex;
	}

	return std::format("{:.{}f} {}", size, size < 10.0 ? 2 : 1, units[unitIndex]);
}

void Emulator::AddNewCheckPoint() {
	if(!CreateCheckPoint_){
		return;
	}

	TotalCheckPointRecorded += 1;
	if ((TotalCheckPointRecorded & 0xffff) == 0) {

		// std::println("Writing trace onto disk : {}...", FileStream_.GetFilePath());
		// FileStream_.WriteTraceToFile(CheckPoints_);

		std::println("[*] Recorded {} checkpoints ~{}", TotalCheckPointRecorded,
			ToHuman(TotalCheckPointRecorded * sizeof(Checkpoint_t) + 40));
	}


	if (QueuedCheckPoint_) {
		CheckPoints_.push_back(QueuedCheckPoint_.value());
	}

	bochscpu_cpu_state_t State;
	bochscpu_cpu_state(Cpu_, &State);

	// QueuedCheckPoint_ = Checkpoint_t{ State, {} };
	QueuedCheckPoint_ = Checkpoint_t{ CreateCpuStateDelta(State), {} };
}

CpuStateDelta_t Emulator::CreateCpuStateDelta(const bochscpu_cpu_state_t& PostState) const {
	CpuStateDelta_t DeltaState;

	for (int i = 0; i < sizeof(bochscpu_cpu_state_t); i += 8) {
		if (*(uint64_t*)((uint8_t*)&PostState + i) != *(uint64_t*)((uint8_t*)&InitialCpuState_ + i)) {
			DeltaState.emplace(i, *(uint64_t*)((uint8_t*)&PostState + i));
		}
	}

	return DeltaState;
}

bochscpu_cpu_state_t Emulator::RestoreCpuStateFromDelta(const CpuStateDelta_t& Delta) const {
	bochscpu_cpu_state_t RestoredState = InitialCpuState_;
	for (const auto& [Offset, Value] : Delta) {
		std::memcpy((uint8_t*)&RestoredState + Offset, &Value, 8);
	}
	return RestoredState;
}

std::uint64_t Emulator::GetPcFromDeltaState(const CpuStateDelta_t& Delta) const {
	constexpr auto RipFieldOffset = offsetof(bochscpu_cpu_state_t, rip);

	if (Delta.contains(RipFieldOffset)) [[likely]] {
		return Delta.at(RipFieldOffset);
	}

	return InitialCpuState_.rip;
}

bool Emulator::AddHook(std::uint64_t Address, Hook_t HookFunc) {
	return UserHooks_.emplace(Address, HookFunc).second;
}

void Emulator::LoadState(const CpuState_t& State) {
	bochscpu_cpu_state_t Bochs;
	std::memset(&Bochs, 0, sizeof(Bochs));

	Bochs.rax = State.Rax;
	Bochs.rbx = State.Rbx;
	Bochs.rcx = State.Rcx;
	Bochs.rdx = State.Rdx;
	Bochs.rsi = State.Rsi;
	Bochs.rdi = State.Rdi;
	Bochs.rip = State.Rip;
	Bochs.rsp = State.Rsp;
	Bochs.rbp = State.Rbp;
	Bochs.r8 = State.R8;
	Bochs.r9 = State.R9;
	Bochs.r10 = State.R10;
	Bochs.r11 = State.R11;
	Bochs.r12 = State.R12;
	Bochs.r13 = State.R13;
	Bochs.r14 = State.R14;
	Bochs.r15 = State.R15;
	Bochs.rflags = State.Rflags;
	Bochs.tsc = State.Tsc;
	Bochs.apic_base = State.ApicBase;
	Bochs.sysenter_cs = State.SysenterCs;
	Bochs.sysenter_esp = State.SysenterEsp;
	Bochs.sysenter_eip = State.SysenterEip;
	Bochs.pat = State.Pat;
	Bochs.efer = std::uint32_t(State.Efer.Flags);
	Bochs.star = State.Star;
	Bochs.lstar = State.Lstar;
	Bochs.cstar = State.Cstar;
	Bochs.sfmask = State.Sfmask;
	Bochs.kernel_gs_base = State.KernelGsBase;
	Bochs.tsc_aux = State.TscAux;
	Bochs.fpcw = State.Fpcw;
	Bochs.fpsw = State.Fpsw;
	Bochs.fptw = State.Fptw.Value;
	Bochs.cr0 = std::uint32_t(State.Cr0.Flags);
	Bochs.cr2 = State.Cr2;
	Bochs.cr3 = State.Cr3;
	Bochs.cr4 = std::uint32_t(State.Cr4.Flags);
	Bochs.cr8 = State.Cr8;
	Bochs.xcr0 = State.Xcr0;
	Bochs.dr0 = State.Dr0;
	Bochs.dr1 = State.Dr1;
	Bochs.dr2 = State.Dr2;
	Bochs.dr3 = State.Dr3;
	Bochs.dr6 = State.Dr6;
	Bochs.dr7 = State.Dr7;
	Bochs.mxcsr = State.Mxcsr;
	Bochs.mxcsr_mask = 0xffbf;//State.MxcsrMask;
	Bochs.fpop = 0; // State.Fpop;
	Bochs.cet_control_u = 0; // State.CetControlU;
	Bochs.cet_control_s = 0; // State.CetControlS;
	Bochs.pl0_ssp = 0; // State.Pl0Ssp;
	Bochs.pl1_ssp = 0; // State.Pl1Ssp;
	Bochs.pl2_ssp = 0; // State.Pl2Ssp;
	Bochs.pl3_ssp = 0; // State.Pl3Ssp;
	Bochs.interrupt_ssp_table = 0; // State.InterruptSspTable;
	Bochs.ssp = 0; // State.Ssp;

#define SEG(_Bochs_, _Whv_)                                                    \
	{                                                                            \
		Bochs._Bochs_.attr = State._Whv_.Attr;                                     \
		Bochs._Bochs_.base = State._Whv_.Base;                                     \
		Bochs._Bochs_.limit = State._Whv_.Limit;                                   \
		Bochs._Bochs_.present = State._Whv_.Present;                               \
		Bochs._Bochs_.selector = State._Whv_.Selector;                             \
	}

	SEG(es, Es);
	SEG(cs, Cs);
	SEG(ss, Ss);
	SEG(ds, Ds);
	SEG(fs, Fs);
	SEG(gs, Gs);
	SEG(tr, Tr);
	SEG(ldtr, Ldtr);

#undef SEG

#define GLOBALSEG(_Bochs_, _Whv_)                                              \
	{                                                                            \
		Bochs._Bochs_.base = State._Whv_.Base;                                     \
		Bochs._Bochs_.limit = State._Whv_.Limit;                                   \
	}

	GLOBALSEG(gdtr, Gdtr);
	GLOBALSEG(idtr, Idtr);

#undef GLOBALSEG

	for (std::uint64_t i = 0; i < 8; i++) {
		Bochs.fpst[i] = State.Fpst[i];
	}

	for (std::uint64_t i = 0; i < 10; i++) {
		std::memcpy(Bochs.zmm[i].q, State.Zmm[i].Q, sizeof(Zmm_t::Q));
	}

	bochscpu_cpu_set_state(Cpu_, &Bochs);
}