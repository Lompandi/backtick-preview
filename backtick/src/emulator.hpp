#pragma once

#include <map>
#include <deque>
#include <functional>
#include <unordered_set>
#include <unordered_map>

#include <bochscpu.hpp>

#include "globals.hpp"
#include <set>

//
// Stolen from Axel Souchet - 0verclock's snapshot emulator project :p
// https://github.com/0vercl0k/wtf/blob/main/src/wtf/bochscpu_backend.cc
//

class Emulator;

using Hook_t = std::function<void(Emulator*)>;

using CpuStateDelta_t = std::unordered_map<std::uint64_t, std::uint64_t>;

struct Checkpoint_t {
	// bochscpu_cpu_state_t CpuState;
	CpuStateDelta_t CpuStateDelta_;
	std::unordered_map<std::uint64_t, std::vector<std::uint8_t>> DirtiedBytes_;
};

struct CallInfoFrame {
	std::uint64_t ChildSp;
	std::uint64_t RetAddr;
	std::uint64_t Callsite;
};


enum ExecutionVector : uint8_t {
	Foward,
	Reverse,
};

class Emulator {
public:
	Emulator();

	bool Initialize(const CpuState_t& State);

	void Run(const std::uint64_t EndAddress = 0);

	void Stop(int value);

	void Reset();

	const std::uint8_t* GetPhysicalPage(const std::uint64_t PhysicalAddress) const;

	bool VirtTranslate(const std::uint64_t Gva, std::uint64_t& Gpa) const;

	std::uint8_t* PhysTranslate(const std::uint64_t Gpa) const;

	bool VirtWrite(const std::uint64_t Gva, const uint8_t* Buffer,
		const uint64_t BufferSize);

	bool VirtWrite8(const std::uint64_t Gva, const std::uint64_t Value);

	bool VirtWrite4(const std::uint64_t Gva, const std::uint32_t Value);

	bool VirtWrite2(const std::uint64_t Gva, const std::uint16_t Value);

	bool VirtWrite1(const std::uint64_t Gva, const std::uint8_t Value);

	bool VirtRead(const std::uint64_t Gva, std::uint8_t* Buffer, const std::uint64_t BufferSize) const;

	std::uint64_t VirtRead8(std::uint64_t Gva) const;

	std::uint32_t VirtRead4(std::uint64_t Gva) const;

	std::uint16_t VirtRead2(std::uint64_t Gva) const;

	std::uint8_t VirtRead1(std::uint64_t Gva)  const;

	bool DirtyGpaPage(const std::uint64_t Gpa);

	const auto GetDirtedPage() const { return &DirtiedPage_; }

	bool SetReg(const Registers_t Reg, const REGVAL* Value);

	bool GetReg(const Registers_t Reg, REGVAL* Value) const;

	std::uint64_t Rip() const { return bochscpu_cpu_rip(Cpu_); }

	void Rip(std::uint64_t Value) const { return bochscpu_cpu_set_rip(Cpu_, Value); }

	bool IsGvaMapped(std::uint64_t VirtualAddress) const;

	void ListBreakpoint() const;

	const std::unordered_map<uint32_t, std::uint64_t>& GetBreakpoints() const;

	bool RemoveCodeBreakpoint(uint32_t Index);

	bool InsertCodeBreakpoint(std::uint64_t Address);

	void ReverseGo();

	void ReverseStepInto();

	void ReverseStepOver();

	void GoUp();

	void StepInto();

	void StepOver();

	bool AddHook(std::uint64_t Address, Hook_t HookFunc);

	void PrintStackTrace() const;

	std::uint64_t GetArg(unsigned int Index) const;

	std::uint64_t GetArgAddress(const uint64_t Idx) const;

	void PrintSimpleStepStatus() const;

	bool ReachRevertEnd() const { return ReachedRevertEnd_; }

	ExecutionVector GetExecutionDirection() const { return ExecutionVector_; };

private:

	CpuStateDelta_t CreateCpuStateDelta(const bochscpu_cpu_state_t& PostState) const;

	bochscpu_cpu_state_t RestoreCpuStateFromDelta(const CpuStateDelta_t& Delta) const;

	std::uint64_t GetPcFromDeltaState(const CpuStateDelta_t& Delta) const;

	void LoadState(const CpuState_t& State);
	
	void AddDirtyToCheckPoint(std::uint64_t Address, std::size_t Size);

	void PhyAccessHook(uint32_t,
		uint64_t PhysicalAddress, uintptr_t Len,
		uint32_t, uint32_t MemAccess);

	void AfterExecutionHook(uint32_t, void*);

	void BeforeExecutionHook(uint32_t, void* Ins);

	void LinAccessHook(uint32_t,
		uint64_t VirtualAddress,
		uint64_t PhysicalAddress, uintptr_t Len,
		uint32_t, uint32_t MemAccess);

	void InterruptHook(uint32_t, uint32_t Vector);

	void ExceptionHook(uint32_t,
		uint32_t Vector, uint32_t ErrorCode);

	void TlbControlHook(uint32_t,
		uint32_t What, uint64_t NewCrValue);

	void CNearBranchHook(uint32_t Cpu, uint64_t Rip,
		uint64_t NextRip);

	void UcNearBranchHook(uint32_t Cpu, uint32_t What,
		uint64_t Rip, uint64_t NextRip);

	void UcFarBranchHook(uint32_t Cpu, uint32_t What,
		uint16_t a1, uint64_t Rip, uint16_t a2, uint64_t NextRip);

	void AddNewCheckPoint();

	static void StaticGpaMissingHandler(const std::uint64_t Gpa);

	static void StaticPhyAccessHook(void* Context, uint32_t Id, uint64_t PhysicalAddress,
		uintptr_t Len, uint32_t MemType, uint32_t MemAccess);

	static void StaticAfterExecutionHook(void* Context, uint32_t Id, void* Ins);

	static void StaticBeforeExecutionHook(void* Context, uint32_t Id, void* Ins);

	static void StaticLinAccessHook(void* Context, uint32_t Id, uint64_t VirtualAddress,
		uint64_t PhysicalAddress, uintptr_t Len,
		uint32_t MemType, uint32_t MemAccess);

	static void StaticInterruptHook(void* Context, uint32_t Id, uint32_t Vector);

	static void StaticExceptionHook(void* Context, uint32_t Id, uint32_t Vector,
		uint32_t ErrorCode);

	static void StaticTlbControlHook(void* Context, uint32_t Id, uint32_t What,
		uint64_t NewCrValue);

	static void StaticOpcodeHook(void* Context, uint32_t Id, const void* i,
		const uint8_t* opcode, uintptr_t len, bool is32,
		bool is64);

	static void StaticHltHook(void* Context, uint32_t Cpu);

	static void StaticCNearBranchHook(void* Context, uint32_t Cpu, uint64_t Rip,
		uint64_t NextRip);

	static void StaticUcNearBranchHook(void* Context, uint32_t Cpu, uint32_t What,
		uint64_t Rip, uint64_t NextRip);

	static void StaticUcFarBranchHook(void* Context, uint32_t Cpu, uint32_t What,
		uint16_t a1, uint64_t Rip, uint16_t a2, uint64_t NextRip);

	std::optional<uint32_t> LocateFreeBreakpointId();

	bochscpu_cpu_t Cpu_ = nullptr;

	bochscpu_hooks_t Hooks_ = {};

	bochscpu_hooks_t* HookChain_[2] = {};

	std::uint64_t InstructionExecutedCount_;

	std::uint64_t MaxiumInstructionLimit_ = 1550000;

	std::uint64_t InstructionLimit_ = 0;

	std::uint64_t ExecEndAddress_ = 0;

	std::unordered_map<uint32_t, std::uint64_t> BreakpointIdToAddress_;

	std::unordered_set<std::uint64_t> MappedPhyPages_;

	std::unordered_map<std::uint64_t, Hook_t> UserHooks_;

	std::unordered_map<std::uint64_t, std::unique_ptr<std::uint8_t[]>> DirtiedPage_;

	std::uint64_t PrevPrevRip_ = 0;

	std::uint64_t PrevRip_ = 0;

	bool RunTillBranch_ = false;

	bool GoingUp_	= false; //stop after return

	bool StepOver_	= false;

	bool ReverseStepOver_		= false;

	bool IsReverseStepInto_		= false;

	bool ReachedRevertEnd_		= false;

	bool DisableBugCheckHook_	= false;

	std::optional<Checkpoint_t> QueuedCheckPoint_ = std::nullopt;

	std::deque<Checkpoint_t>	CheckPoints_;

	std::vector<CallInfoFrame>  CallTrace_;

	bochscpu_cpu_state_t InitialCpuState_;

	ExecutionVector ExecutionVector_;
};

using TimeFrames_t = std::map<unsigned int, CpuState_t>;

extern Emulator g_Emulator;

extern TimeFrames_t g_TimeFrames;