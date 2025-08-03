
#include <cassert>

#include "../pch.h"

#include "utils.hpp"
#include "globals.hpp"
#include "debugger.hpp"

Debugger_t g_Debugger;

bool Debugger_t::Init() {
	char ExePathBuffer[MAX_PATH];
	if (!GetModuleFileNameA(nullptr, &ExePathBuffer[0],
		sizeof(ExePathBuffer))) {
		std::println("GetModuleFileNameA failed.");
		return false;
	}

	const fs::path ExePath(ExePathBuffer);
	const fs::path ParentDir(ExePath.parent_path());
	const std::vector<std::string_view> Dlls = { "dbghelp.dll", "symsrv.dll",
												"dbgeng.dll", "dbgcore.dll" };
	const fs::path DefaultDbgDllLocation(
		R"(c:\program Files (x86)\windows kits\10\debuggers\x64)");

    for (const auto& Dll : Dlls) {
        if (fs::exists(ParentDir / Dll)) {
            continue;
        }

        const fs::path DbgDllLocation(DefaultDbgDllLocation / Dll);
        if (!fs::exists(DbgDllLocation)) {

            std::println("The debugger class expects debug dlls in the "
                "directory "
                "where the application is running from.");
            return false;
        }

        fs::copy(DbgDllLocation, ParentDir);
        std::println("Copied {} into the "
            "executable directory..",
            DbgDllLocation.generic_string());
    }

    HRESULT Status = DebugCreate(__uuidof(IDebugClient), (void**)&Client_);
    if (FAILED(Status)) {
        std::println("DebugCreate failed with hr={:#x}", Status);
        return false;
    }

    Status =
        Client_->QueryInterface(__uuidof(IDebugControl), (void**)&Control_);
    if (FAILED(Status)) {
        std::println("QueryInterface/IDebugControl failed with hr={:#x}", Status);
        return false;
    }

    Status = Client_->QueryInterface(__uuidof(IDebugRegisters),
        (void**)&Registers_);
    if (FAILED(Status)) {
        std::println("QueryInterface/IDebugRegisters failed with hr={:#x}",
            Status);
        return false;
    }

    Status = Client_->QueryInterface(__uuidof(IDebugDataSpaces),
        (void**)&DataSpaces_);
    if (FAILED(Status)) {
        std::println("QueryInterface/IDebugDataSpaces failed with hr={:#x}",
            Status);
        return false;
    }

    Status =
        Client_->QueryInterface(__uuidof(IDebugSymbols3), (void**)&Symbols_);
    if (FAILED(Status)) {
        std::println("QueryInterface/IDebugSymbols failed with hr={:#x}", Status);
        return false;
    }

    Symbols_->Reload("");

    return true;
}

void Debugger_t::Print(const char* Msg) {
    Control_->ControlledOutput(DEBUG_OUTCTL_AMBIENT_DML, DEBUG_OUTPUT_NORMAL, Msg);
}

bool Debugger_t::ReadVirtualMemory(const std::uint64_t VirtualAddress, const void* Buffer, std::size_t Size) const {
    ULONG BytesRead = 0;
    HRESULT Status = DataSpaces_->ReadVirtual(VirtualAddress, (uint8_t*)Buffer, Size, &BytesRead);

    return (BytesRead == Size && Status == S_OK);
}

bool Debugger_t::ReadPhysicalMemory(const std::uint64_t PhysicalAddress, const void* Buffer, std::size_t Size) {
    ULONG BytesRead = 0;
    HRESULT Status = DataSpaces_->ReadPhysical(PhysicalAddress, (uint8_t*)Buffer, Size, &BytesRead);

    return (BytesRead == Size && Status == S_OK);
}

bool Debugger_t::WritePhysicalMemory(const std::uint64_t PhysicalAddress, const void* Buffer, std::size_t Size) {
    ULONG BytesWritten = 0;
    HRESULT Status = DataSpaces_->WritePhysical(PhysicalAddress, (uint8_t*)Buffer, Size, &BytesWritten);

    return (BytesWritten == Size && Status == S_OK);
}

const std::uint8_t* Debugger_t::GetPhysicalPage(const std::uint64_t PhysicalAddress) {
    const auto AlignedPa = AlignPage(PhysicalAddress);
    
    if (!LoadedPhysicalPage_.contains(AlignedPa)) {

        auto Buffer = std::make_unique<std::uint8_t[]>(0x1000);

        ULONG BytesRead = 0;
        HRESULT Status = DataSpaces_->ReadPhysical(AlignedPa, Buffer.get(), 0x1000, &BytesRead);

        if (BytesRead != 0x1000 || Status != S_OK) {

            // std::println("Reading physical memory {:#x} failed", PhysicalAddress);

            return nullptr;
        }

        LoadedPhysicalPage_[AlignedPa] = std::move(Buffer);
    }

    return LoadedPhysicalPage_.at(AlignedPa).get();
}

std::unordered_map<std::string, std::uint64_t>
Debugger_t::Regs64(const std::vector<std::string_view>& Targets) const {
    std::unordered_map<std::string, std::uint64_t> RegisterValues;
    RegisterValues.reserve(Targets.size());

    for (const auto& Name : Targets) {
        ULONG Index;
        if (Registers_->GetIndexByName(Name.data(), &Index) != S_OK) {
            std::println("Failed to get register {}", Name.data());
            RegisterValues.emplace(Name.data(), 0ull);
            continue;
        }

        DEBUG_VALUE RegValue;
        Registers_->GetValue(Index, &RegValue);
        RegisterValues.emplace(Name.data(), RegValue.I64);
    }

    return RegisterValues;
}

std::vector<DEBUG_VALUE>
Debugger_t::Regs(const std::vector<std::string_view>& Targets) const {
    std::vector<DEBUG_VALUE> RegisterValues;
    RegisterValues.reserve(Targets.size());

    for (const auto& Name : Targets) {
        ULONG Index;
        if (Registers_->GetIndexByName(Name.data(), &Index) != S_OK) {
            std::println("Failed to get register {}", Name.data());
            RegisterValues.push_back(DEBUG_VALUE{ 0 });
            continue;
        }

        DEBUG_VALUE RegValue;
        Registers_->GetValue(Index, &RegValue);
        RegisterValues.push_back(RegValue);
    }

    return RegisterValues;
}

std::uint64_t Debugger_t::Msr(std::uint32_t Index) const {
    ULONG64 Value;
    if (DataSpaces_->ReadMsr(Index, &Value) != S_OK) {
        std::println("Failed to read msr: {:#x}", Index);
        return 0;
    }

    return Value;
}

std::vector<std::string> Debugger_t::Disassemble(std::uint64_t Address, std::uint32_t Lines) {
    std::vector<std::string> disassembledLines;

    std::uint64_t currentAddress = Address;

    for (std::uint32_t i = 0; i < Lines; ++i) {
        std::string buffer;
        buffer.resize(1024);

        ULONG disasmSize = 0;
        ULONG64 nextAddress = 0;

        HRESULT hr = Control_->Disassemble(
            currentAddress,
            DEBUG_DISASM_EFFECTIVE_ADDRESS,
            buffer.data(),
            static_cast<ULONG>(buffer.size()),
            &disasmSize,
            &nextAddress
        );

        if (hr == S_FALSE || FAILED(hr)) {
            disassembledLines.push_back("???");
        }
        else {
            buffer.resize(disasmSize);
            StripAllControlChars(buffer);
            disassembledLines.push_back(buffer);
        }
        currentAddress = nextAddress;
    }

    return disassembledLines;
}

std::optional<std::string> Debugger_t::Disassemble(std::uint64_t Address) {
    std::string Buffer;
    Buffer.resize(1024);

    ULONG DisassemblySize = 0;
    ULONG64 EndOffset = 0;

    if (Control_->Disassemble(
        Address,
        DEBUG_DISASM_EFFECTIVE_ADDRESS,
        Buffer.data(),
        Buffer.size(),
        &DisassemblySize,
        &EndOffset
    ) == S_FALSE) {
        // TODO: rezie the buffer and disassemble again
        std::println("Instruction Output exceed 1024 bytes");
        return {};
    }

    Buffer.resize(DisassemblySize);
    return Buffer;
}

bool Debugger_t::SetReg64(std::string_view Name, std::uint64_t Value) {
    ULONG Index;
    if (Registers_->GetIndexByName(Name.data(), &Index) != S_OK) {
        std::println("Failed to get register {}", Name.data());
        return false;
    }

    DEBUG_VALUE RegValue {};
    RegValue.I64 = Value;
    RegValue.Type = DEBUG_VALUE_INT64;
    if (auto Status = Registers_->SetValue(Index, &RegValue); Status != S_OK) {
        std::println("SetValue failed with {:#x}", (unsigned long)Status);
        return false;
    }

    return true;
}

std::uint64_t Debugger_t::Reg64(std::string_view Name) const {
    ULONG Index;
    if (Registers_->GetIndexByName(Name.data(), &Index) != S_OK) {
        std::println("Failed to get register {}", Name.data());
        return 0;
    }

    DEBUG_VALUE RegValue;
    Registers_->GetValue(Index, &RegValue);

    return RegValue.I64;
}

const std::string Debugger_t::GetName(const uint64_t SymbolAddress,
    const bool Symbolized) {

    const size_t NameSizeMax = MAX_PATH;
    char Buffer[NameSizeMax];
    uint64_t Offset = 0;

    if (Symbolized) {
        const HRESULT Status = Symbols_->GetNameByOffset(
            SymbolAddress, Buffer, NameSizeMax, nullptr, &Offset);
        if (FAILED(Status)) {
            return "";
        }
    }
    else {
        ULONG Index;
        ULONG64 Base;
        HRESULT Status =
            Symbols_->GetModuleByOffset(SymbolAddress, 0, &Index, &Base);

        if (FAILED(Status)) {
            return "";
        }

        ULONG NameSize;
        Status = Symbols_->GetModuleNameString(DEBUG_MODNAME_MODULE, Index, Base,
            Buffer, NameSizeMax, &NameSize);

        if (FAILED(Status)) {
            return "";
        }

        Offset = SymbolAddress - Base;
    }

    const auto& SymbolFormat
        = std::format("{}{}", Buffer, Offset ? std::format("+{:#x}", Offset) : "");
    return SymbolFormat;
}

DEBUG_VALUE Debugger_t::Reg(std::string_view Name) const {
    ULONG Index;
    if (Registers_->GetIndexByName(Name.data(), &Index) != S_OK) {
        std::println("Failed to get register {}", Name.data());
        return { 0 };
    }

    DEBUG_VALUE RegValue;
    Registers_->GetValue(Index, &RegValue);

    return RegValue;
}

Seg_t Debugger_t::GdtEntry(std::uint64_t GdtBase, std::uint16_t GdtLimit, std::uint64_t Selector) const {
    auto Ti = ExtractBit(Selector, 2ull);
    if (Ti) {
        std::println("Expected a GDT table indicator when reading segment descriptor");
        return {};
    }

    auto Index = ExtractBits(Selector, 3ull, 15ull);

    auto GdtLimit64 = uint64_t(GdtLimit);
    assert((GdtLimit64 + 1) % 8 == 0);
    auto MaxIndex = (GdtLimit64 + 1) / 8;
    if (Index > MaxIndex) {
        std::println("The selector {:#x} has an index ({}) larger than the maximum allowed ({})",
            Selector, Index, MaxIndex);
        return {};
    }

    std::array<std::uint8_t, 16> Descriptor;
    auto EntryAddr = GdtBase + (Index * 8ull);

    ReadVirtualMemory(EntryAddr, Descriptor.data(), Descriptor.size());

    return Seg_t::FromDescriptor(Selector, Descriptor);
}

std::uint64_t FptwTranslate(std::uint64_t DbgFptw) {
    uint64_t Out = 0;
    for (int BitIndex = 0; BitIndex < 8; BitIndex++) {
        auto Bits = (DbgFptw >> BitIndex) & 0b1;
        Out |= (Bits == 1) ? 0b00 : 0b11 << (BitIndex * 2);
    }

    return Out;
}

uint64_t Debugger_t::GetDbgSymbol(const char* Name) const {
    uint64_t Offset = 0;
    HRESULT Status = Symbols_->GetOffsetByName(Name, &Offset);
    if (FAILED(Status)) {
        if (Status == S_FALSE) {
            __debugbreak();
        }
    }

    return Offset;
}

DEBUG_VALUE Debugger_t::Evaluate(std::string_view Expr, ULONG DesireType) const {
    DEBUG_VALUE Value = { 0 };
    Control_->Evaluate(Expr.data(), DesireType, &Value, NULL);
    return Value;
}

void Debugger_t::StartCaptureOutputToBuffer() {
    Client_->SetOutputCallbacks((PDEBUG_OUTPUT_CALLBACKS)&g_OutputCb);
}

DefaultRegistersState Debugger_t::GetDefaultRegisterState() const {
    DefaultRegistersState State{};
    State.Rax = Reg64("rax");
    State.Rbx = Reg64("rbx");
    State.Rcx = Reg64("rcx");
    State.Rdx = Reg64("rdx");
    State.Rsi = Reg64("rsi");
    State.Rdi = Reg64("rdi");
    State.Rip = Reg64("rip");
    State.Rsp = Reg64("rsp");
    State.Rbp = Reg64("rbp");
    State.R8 = Reg64("r8");
    State.R9 = Reg64("r9");
    State.R10 = Reg64("r10");
    State.R11 = Reg64("r11");
    State.R12 = Reg64("r12");
    State.R13 = Reg64("r13");
    State.R14 = Reg64("r14");
    State.R15 = Reg64("r15");
    State.Rflags = Reg64("efl");
    State.Cs = Reg64("cs");
    State.Ds = Reg64("ds");
    State.Es = Reg64("es");
    State.Fs = Reg64("fs");
    State.Gs = Reg64("gs");
    State.Ss = Reg64("ss");

    return State;
}

bool Debugger_t::LoadCpuStateTo(CpuState_t& State) const {
    State.Rax = Reg64("rax");
    State.Rbx = Reg64("rbx");
    State.Rcx = Reg64("rcx");
    State.Rdx = Reg64("rdx");
    State.Rsi = Reg64("rsi");
    State.Rdi = Reg64("rdi");
    State.Rip = Reg64("rip");
    State.Rsp = Reg64("rsp");
    State.Rbp = Reg64("rbp");
    State.R8  = Reg64("r8");
    State.R9  = Reg64("r9");
    State.R10 = Reg64("r10");
    State.R11 = Reg64("r11");
    State.R12 = Reg64("r12");
    State.R13 = Reg64("r13");
    State.R14 = Reg64("r14");
    State.R15 = Reg64("r15");
    State.Rflags      = Reg64("efl");
    State.Tsc         = Msr(msr::TSC);
    State.ApicBase    = Msr(msr::APIC_BASE);
    State.SysenterCs  = Msr(msr::IA32_SYSENTER_CS);
    State.SysenterEsp = Msr(msr::IA32_SYSENTER_ESP);
    State.SysenterEip = Msr(msr::IA32_SYSENTER_EIP);
    State.Pat         = Msr(msr::IA32_PAT);
    State.Efer        = Msr(msr::IA32_EFER);
    State.Star        = Msr(msr::IA32_STAR);
    State.Lstar       = Msr(msr::IA32_LSTAR);
    State.Cstar       = Msr(msr::IA32_CSTAR);
    State.Sfmask      = Msr(msr::IA32_FMASK);
    State.KernelGsBase = Msr(msr::IA32_KERNEL_GSBASE);
    State.TscAux      = Msr(msr::IA32_TSC_AUX);
    State.Fpcw = Reg64("fpcw");
    State.Fpsw = Reg64("fpsw");
    State.Fptw = FptwTranslate(Reg64("fptw"));
    State.Cr0 = Reg64("cr0");
    State.Cr2 = Reg64("cr2");
    State.Cr3 = Reg64("cr3");
    State.Cr4 = Reg64("cr4");
    State.Cr8 = Reg64("cr8");
    State.Xcr0 = Reg64("xcr0");
    State.Dr0 = Reg64("dr0");
    State.Dr1 = Reg64("dr1");
    State.Dr2 = Reg64("dr2");
    State.Dr3 = Reg64("dr3");
    State.Dr6 = Reg64("dr6");
    State.Dr7 = Reg64("dr7");
    State.Mxcsr = Reg64("mxcsr");
    // State.MxcsrMask = 0xffbf;
    // State.Fpop = 0;
    // State.CetControlU = 0;
    // State.CetControlS = 0;
    // State.Pl0Ssp = 0;
    // State.Pl1Ssp = 0;
    // State.Pl2Ssp = 0;
    // State.Pl3Ssp = 0;
    // State.InterruptSspTable = 0;
    // State.Ssp = 0;

    State.Gdtr.Base = Reg64("gdtr");
    State.Gdtr.Limit = Reg64("gdtl");

    State.Idtr.Base = Reg64("idtr");
    State.Idtr.Limit = Reg64("idtl");

    std::uint64_t GdtBase = State.Gdtr.Base;
    std::uint64_t GdtLimit = State.Gdtr.Limit;

#define GET_SEG(_Seg_) \
    GdtEntry(GdtBase, GdtLimit, Reg64(#_Seg_))

    State.Es = GET_SEG(es);
    State.Cs = GET_SEG(cs);
    State.Ss = GET_SEG(ss);
    State.Ds = GET_SEG(ds);
    State.Tr = GET_SEG(tr);
    State.Gs = GET_SEG(gs);
    State.Fs = GET_SEG(fs);
    State.Ldtr = GET_SEG(ldtr);

    State.Gs.Base = Msr(msr::IA32_GS_BASE);
    State.Fs.Base = Msr(msr::IA32_FS_BASE);

    for (int i = 0; i < 8; i++) {
        State.Fpst[i] = Reg(std::format("st{}", i));
    }

    return true;
}