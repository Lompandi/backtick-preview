#pragma once

#include <memory>
#include <optional>
#include <filesystem>
#include <unordered_map>

#include "../pch.h"

namespace fs = std::filesystem;

struct uint128_t {
	std::uint64_t Low;
	std::uint64_t High;

	uint128_t(const DEBUG_VALUE& Other) {
		memcpy(this, &Other.F128Bytes, 16);
	}
};

struct PFNEntry {
	USHORT ReferenceCount;
	USHORT ShareCount;
	USHORT Flags;
	ULONG64 PteAddress;
	ULONG64 OriginalPteValue;
};

struct DefaultRegistersState {
	std::uint64_t Rax;
	std::uint64_t Rbx;
	std::uint64_t Rcx;
	std::uint64_t Rdx;
	std::uint64_t Rsi;
	std::uint64_t Rdi;
	std::uint64_t Rip;
	std::uint64_t Rsp;
	std::uint64_t Rbp;
	std::uint64_t R8;
	std::uint64_t R9;
	std::uint64_t R10;
	std::uint64_t R11;
	std::uint64_t R12;
	std::uint64_t R13;
	std::uint64_t R14;
	std::uint64_t R15;
	std::uint64_t Iopl;
	std::uint16_t Cs;
	std::uint16_t Ds;
	std::uint16_t Es;
	std::uint16_t Fs;
	std::uint16_t Gs;
	std::uint16_t Ss;
	std::uint64_t Rflags;
};

struct CpuState_t;
struct Seg_t;

class Debugger_t {
public:
	explicit Debugger_t() = default;

	~Debugger_t() {
		if (Client_) {
			Client_->EndSession(DEBUG_END_ACTIVE_DETACH);
			Client_->Release();
		}

		if (Control_) {
			Control_->Release();
		}

		if (Registers_) {
			Registers_->Release();
		}

		if (Symbols_) {
			Symbols_->Release();
		}
	}

	Debugger_t(const Debugger_t&) = delete;
	Debugger_t& operator=(const Debugger_t&) = delete;

	[[nodiscard]] bool Init();

	void Print(const char* Msg);

	bool ReadVirtualMemory(const std::uint64_t VirtualAddress, const void* Buffer, std::size_t Size) const;

	bool ReadPhysicalMemory(const std::uint64_t PhysicalAddress, const void* Buffer, std::size_t Size);

	bool WritePhysicalMemory(const std::uint64_t PhysicalAddress, const void* Buffer, std::size_t Size);

	const std::uint8_t* GetPhysicalPage(const std::uint64_t PhysicalAddress);

	bool LoadCpuStateTo(CpuState_t& State) const;

	Seg_t GdtEntry(std::uint64_t Base, std::uint16_t Limit, std::uint64_t Selector) const;

	bool SetReg64(std::string_view Name, std::uint64_t Value);

	std::unordered_map<std::string, std::uint64_t>
		Regs64(const std::vector<std::string_view>& Targets) const;

	std::uint64_t Reg64(std::string_view Name) const;
	
	DEBUG_VALUE Reg(std::string_view Name) const;

	DEBUG_VALUE Evaluate(std::string_view Expr, ULONG DesireType) const;

	std::vector<DEBUG_VALUE>
		Regs(const std::vector<std::string_view>& Targets) const;

	DefaultRegistersState GetDefaultRegisterState() const;

	std::uint64_t Msr(std::uint32_t Index) const;

	std::optional<std::string> Disassemble(std::uint64_t Address);

	std::vector<std::string> Disassemble(std::uint64_t Address, std::uint32_t Lines);

	const std::string GetName(const uint64_t SymbolAddress,
		const bool Symbolized);

	uint64_t GetDbgSymbol(const char* Name) const;

	void StartCaptureOutputToBuffer();

private:
	IDebugClient* Client_ = nullptr;
	IDebugControl* Control_ = nullptr;
	IDebugRegisters* Registers_ = nullptr;
	IDebugSymbols3* Symbols_ = nullptr;
	IDebugDataSpaces* DataSpaces_ = nullptr;
	IDebugOutputCallbacks* Callbacks_ = nullptr;

	std::vector<std::wstring> OutputLineBuffer_;

	std::unordered_map<std::uint64_t, std::unique_ptr<std::uint8_t[]>> LoadedPhysicalPage_;
};

extern Debugger_t g_Debugger;

//
// Reversed from dbgeng.dll
//

struct Breakpoint {
	std::uint64_t Vtable;					// this+0x0

	std::uint32_t MatchThreadId;			// this+0x20
	std::uint32_t Id;						// this+0x2c
	GUID		  Guid;						// this+0x30
	std::uint32_t BreakType;				// this+0x40  (0: code breakpoint, 1: data breakpoint, )
	std::uint8_t  Flags;					// this+0x44

		
	std::uint32_t DataSize;					// this+0x54
	std::uint32_t DataAccessType;			// this+0x58
	std::uint32_t PassCount;				// this+0x5c
	std::uint32_t CurrentPassCount;			// this+0x60

	unsigned short* CommandStringWide;		// this+0x68
	unsigned short* ConditionString;		// this+0x70
	std::uint64_t   pAssociatedThread;		// this+0x78
	std::uint64_t   GlobalProcess;			// this+0x80
	unsigned short* OffsetExpressionWide;	// this+0x88
	std::uint32_t   OffsetExpressionSize;   // this+0x90

	std::uint32_t AdderId;					// this+0xc0

	std::uint32_t ProcType;					// this+0x144
	std::uint32_t MachineTypeIndex;			// this+0x148

	std::uint64_t Offset;					// this+0x160
	std::uint32_t CommandSize;				// this+0x180

	std::uint64_t CurrentUniqueId;			// this+0x198
};

enum Registers_t {
	Rax = 1,
	Rbx,
	Rcx,
	Rdx,
	Rsi,
	Rdi,
	Rsp,
	Rbp,
	Rip,
	Rflags,
	Cs,
	Ds,
	Es,
	Fs,
	Gs,
	Ss,
	R8,
	R9,
	R10,
	R11,
	R12,
	R13,
	R14,
	R15,
	Cr0,
	Cr2,
	Cr3,
	Cr4,
	Cr8,
	Dr0,
	Dr1,
	Dr2,
	Dr3,
	Dr6,
	Dr7,
	Gdtr,
	Gdtl,
	Idtr,
	Idtl,
	Tr,
	Ldtr,
	XCr0 = 0x31,
	Fpcw,
	Fpsw,
	Fptw,
	St0,
	St1,
	St2,
	St3,
	St4,
	St5,
	St6,
	St7,
	Mm0,
	Mm1,
	Mm2,
	Mm3,
	Mm4,
	Mm5,
	Mm6,
	Mm7,
	Mxcsr,
	Xmm0 = 0x46,
	Xmm1,
	Xmm2,
	Xmm3,
	Xmm4,
	Xmm5,
	Xmm6,
	Xmm7,
	Xmm8,
	Xmm9,
	Xmm10,
	Xmm11,
	Xmm12,
	Xmm13,
	Xmm14,
	Xmm15,
	Ymm0 = 0x64,
	Ymm1,
	Ymm2,
	Ymm3,
	Ymm4,
	Ymm5,
	Ymm6,
	Ymm7,
	Ymm8,
	Ymm9,
	Ymm10,
	Ymm11,
	Ymm12,
	Ymm13,
	Ymm14,
	Ymm15,
	Zmm0 = 0x74,
	Zmm1,
	Zmm2,
	Zmm3,
	Zmm4,
	Zmm5,
	Zmm6,
	Zmm7,
	Zmm8,
	Zmm9,
	Zmm10,
	Zmm11,
	Zmm12,
	Zmm13,
	Zmm14,
	Zmm15,
	Zmm16,
	Zmm17,
	Zmm18,
	Zmm19,
	Zmm20,
	Zmm21,
	Zmm22,
	Zmm23,
	Zmm24,
	Zmm25,
	Zmm26,
	Zmm27,
	Zmm28,
	Zmm29,
	Zmm30,
	Zmm31,
};

// IA32_MSRS
namespace msr {
	constexpr std::uint32_t P5_MC_ADDR = 0x0;
	constexpr std::uint32_t IA32_P5_MC_ADDR = 0x0;
	constexpr std::uint32_t P5_MC_TYPE = 0x1;
	constexpr std::uint32_t IA32_P5_MC_TYPE = 0x1;
	constexpr std::uint32_t IA32_MONITOR_FILTER_SIZE = 0x6;
	constexpr std::uint32_t IA32_MONITOR_FILTER_LINE_SIZE = 0x6;
	constexpr std::uint32_t IA32_TIME_STAMP_COUNTER = 0x10;
	constexpr std::uint32_t TSC = 0x10;
	constexpr std::uint32_t MSR_PLATFORM_ID = 0x17;
	constexpr std::uint32_t IA32_PLATFORM_ID = 0x17;
	constexpr std::uint32_t APIC_BASE = 0x1b;
	constexpr std::uint32_t IA32_APIC_BASE = 0x1b;
	constexpr std::uint32_t EBL_CR_POWERON = 0x2a;
	constexpr std::uint32_t MSR_EBL_CR_POWERON = 0x2a;
	constexpr std::uint32_t MSR_EBC_HARD_POWERON = 0x2a;
	constexpr std::uint32_t MSR_EBC_SOFT_POWERON = 0x2b;
	constexpr std::uint32_t MSR_EBC_FREQUENCY_ID = 0x2c;
	constexpr std::uint32_t TEST_CTL = 0x33;
	constexpr std::uint32_t MSR_SMI_COUNT = 0x34;
	constexpr std::uint32_t IA32_FEATURE_CONTROL = 0x3a;
	constexpr std::uint32_t IA32_TSC_ADJUST = 0x3b;
	constexpr std::uint32_t MSR_LASTBRANCH_0_FROM_IP = 0x40;
	constexpr std::uint32_t MSR_LASTBRANCH_1 = 0x41;
	constexpr std::uint32_t MSR_LASTBRANCH_1_FROM_IP = 0x41;
	constexpr std::uint32_t MSR_LASTBRANCH_2_FROM_IP = 0x42;
	constexpr std::uint32_t MSR_LASTBRANCH_3_FROM_IP = 0x43;
	constexpr std::uint32_t MSR_LASTBRANCH_4 = 0x44;
	constexpr std::uint32_t MSR_LASTBRANCH_4_FROM_IP = 0x44;
	constexpr std::uint32_t MSR_LASTBRANCH_5 = 0x45;
	constexpr std::uint32_t MSR_LASTBRANCH_5_FROM_IP = 0x45;
	constexpr std::uint32_t MSR_LASTBRANCH_6 = 0x46;
	constexpr std::uint32_t MSR_LASTBRANCH_6_FROM_IP = 0x46;
	constexpr std::uint32_t MSR_LASTBRANCH_7 = 0x47;
	constexpr std::uint32_t MSR_LASTBRANCH_7_FROM_IP = 0x47;
	constexpr std::uint32_t MSR_LASTBRANCH_0_TO_IP = 0x6c0;
	constexpr std::uint32_t MSR_LASTBRANCH_1_TO_IP = 0x61;
	constexpr std::uint32_t MSR_LASTBRANCH_2_TO_IP = 0x62;
	constexpr std::uint32_t MSR_LASTBRANCH_3_TO_IP = 0x63;
	constexpr std::uint32_t MSR_LASTBRANCH_4_TO_IP = 0x64;
	constexpr std::uint32_t MSR_LASTBRANCH_5_TO_IP = 0x65;
	constexpr std::uint32_t MSR_LASTBRANCH_6_TO_IP = 0x66;
	constexpr std::uint32_t MSR_LASTBRANCH_7_TO_IP = 0x67;
	constexpr std::uint32_t IA32_BIOS_UPDT_TRIG = 0x79;
	constexpr std::uint32_t BIOS_UPDT_TRIG = 0x79;
	constexpr std::uint32_t IA32_BIOS_SIGN_ID = 0x8b;
	constexpr std::uint32_t IA32_SMM_MONITOR_CTL = 0x9b;
	constexpr std::uint32_t IA32_SMBASE = 0x9e;
	constexpr std::uint32_t MSR_SMRR_PHYSMASK = 0xa1;
	constexpr std::uint32_t IA32_PMC0 = 0xc1;
	constexpr std::uint32_t IA32_PMC1 = 0xc2;
	constexpr std::uint32_t IA32_PMC2 = 0xc3;
	constexpr std::uint32_t IA32_PMC3 = 0xc4;
	constexpr std::uint32_t IA32_PMC4 = 0xc5;
	constexpr std::uint32_t IA32_PMC5 = 0xc6;
	constexpr std::uint32_t IA32_PMC6 = 0xc7;
	constexpr std::uint32_t IA32_PMC7 = 0xc8;
	constexpr std::uint32_t MSR_FSB_FREQ = 0xcd;
	constexpr std::uint32_t MSR_PLATFORM_INFO = 0xce;
	constexpr std::uint32_t MSR_PKG_CST_CONFIG_CONTROL = 0xe2;
	constexpr std::uint32_t MSR_PMG_IO_CAPTURE_BASE = 0xe4;
	constexpr std::uint32_t IA32_MPERF = 0xe7;
	constexpr std::uint32_t IA32_APERF = 0xe8;
	constexpr std::uint32_t IA32_MTRRCAP = 0xfe;
	constexpr std::uint32_t MSR_BBL_CR_CTL = 0x119;
	constexpr std::uint32_t MSR_BBL_CR_CTL3 = 0x11e;
	constexpr std::uint32_t MSR_IA32_TSX_CTRL = 0x122;
	constexpr std::uint32_t IA32_SYSENTER_CS = 0x174;
	constexpr std::uint32_t SYSENTER_CS_MSR = 0x174;
	constexpr std::uint32_t IA32_SYSENTER_ESP = 0x175;
	constexpr std::uint32_t SYSENTER_ESP_MSR = 0x175;
	constexpr std::uint32_t IA32_SYSENTER_EIP = 0x176;
	constexpr std::uint32_t SYSENTER_EIP_MSR = 0x176;
	constexpr std::uint32_t MCG_CAP = 0x179;
	constexpr std::uint32_t IA32_MCG_CAP = 0x179;
	constexpr std::uint32_t IA32_MCG_STATUS = 0x17a;
	constexpr std::uint32_t MCG_STATUS = 0x17a;
	constexpr std::uint32_t MCG_CTL = 0x17b;
	constexpr std::uint32_t IA32_MCG_CTL = 0x17b;
	constexpr std::uint32_t MSR_SMM_MCA_CAP = 0x17d;
	constexpr std::uint32_t MSR_ERROR_CONTROL = 0x17f;
	constexpr std::uint32_t MSR_MCG_RAX = 0x180;
	constexpr std::uint32_t MSR_MCG_RBX = 0x181;
	constexpr std::uint32_t MSR_MCG_RCX = 0x182;
	constexpr std::uint32_t MSR_MCG_RDX = 0x183;
	constexpr std::uint32_t MSR_MCG_RSI = 0x184;
	constexpr std::uint32_t MSR_MCG_RDI = 0x185;
	constexpr std::uint32_t MSR_MCG_RBP = 0x186;
	constexpr std::uint32_t IA32_PERFEVTSEL0 = 0x186;
	constexpr std::uint32_t IA32_PERFEVTSEL1 = 0x187;
	constexpr std::uint32_t IA32_PERFEVTSEL2 = 0x188;
	constexpr std::uint32_t MSR_MCG_RFLAGS = 0x188;
	constexpr std::uint32_t IA32_PERFEVTSEL3 = 0x189;
	constexpr std::uint32_t MSR_MCG_RIP = 0x189;
	constexpr std::uint32_t MSR_MCG_MISC = 0x18a;
	constexpr std::uint32_t IA32_PERFEVTSEL4 = 0x18a;
	constexpr std::uint32_t IA32_PERFEVTSEL5 = 0x18b;
	constexpr std::uint32_t IA32_PERFEVTSEL6 = 0x18c;
	constexpr std::uint32_t IA32_PERFEVTSEL7 = 0x18d;
	constexpr std::uint32_t MSR_MCG_R8 = 0x190;
	constexpr std::uint32_t MSR_MCG_R9 = 0x191;
	constexpr std::uint32_t MSR_MCG_R10 = 0x192;
	constexpr std::uint32_t MSR_MCG_R11 = 0x193;
	constexpr std::uint32_t MSR_MCG_R12 = 0x194;
	constexpr std::uint32_t MSR_MCG_R13 = 0x195;
	constexpr std::uint32_t MSR_MCG_R14 = 0x196;
	constexpr std::uint32_t MSR_PERF_STATUS = 0x198;
	constexpr std::uint32_t IA32_PERF_STATUS = 0x198;
	constexpr std::uint32_t IA32_PERF_CTL = 0x199;
	constexpr std::uint32_t IA32_CLOCK_MODULATION = 0x19a;
	constexpr std::uint32_t IA32_THERM_INTERRUPT = 0x19b;
	constexpr std::uint32_t IA32_THERM_STATUS = 0x19c;
	constexpr std::uint32_t MSR_THERM2_CTL = 0x19d;
	constexpr std::uint32_t IA32_MISC_ENABLE = 0x1a0;
	constexpr std::uint32_t MSR_PLATFORM_BRV = 0x1a1;
	constexpr std::uint32_t MSR_TEMPERATURE_TARGET = 0x1a2;
	constexpr std::uint32_t MSR_OFFCORE_RSP_0 = 0x1a6;
	constexpr std::uint32_t MSR_OFFCORE_RSP_1 = 0x1a7;
	constexpr std::uint32_t MSR_MISC_PWR_MGMT = 0x1aa;
	constexpr std::uint32_t MSR_TURBO_POWER_CURRENT_LIMIT = 0x1ac;
	constexpr std::uint32_t MSR_TURBO_RATIO_LIMIT = 0x1ad;
	constexpr std::uint32_t IA32_ENERGY_PERF_BIAS = 0x1b0;
	constexpr std::uint32_t IA32_PACKAGE_THERM_STATUS = 0x1b1;
	constexpr std::uint32_t IA32_PACKAGE_THERM_INTERRUPT = 0x1b2;
	constexpr std::uint32_t MSR_LBR_SELECT = 0x1c8;
	constexpr std::uint32_t MSR_LASTBRANCH_TOS = 0x1da;
	constexpr std::uint32_t DEBUGCTLMSR = 0x1d9;
	constexpr std::uint32_t MSR_DEBUGCTLA = 0x1d9;
	constexpr std::uint32_t MSR_DEBUGCTLB = 0x1d9;
	constexpr std::uint32_t IA32_DEBUGCTL = 0x1d9;
	constexpr std::uint32_t LASTBRANCHFROMIP = 0x1db;
	constexpr std::uint32_t MSR_LASTBRANCH_0 = 0x1db;
	constexpr std::uint32_t LASTBRANCHTOIP = 0x1dc;
	constexpr std::uint32_t LASTINTFROMIP = 0x1dd;
	constexpr std::uint32_t MSR_LASTBRANCH_2 = 0x1dd;
	constexpr std::uint32_t MSR_LER_FROM_LIP = 0x1de;
	constexpr std::uint32_t LASTINTTOIP = 0x1de;
	constexpr std::uint32_t MSR_LASTBRANCH_3 = 0x1de;
	constexpr std::uint32_t MSR_LER_TO_LIP = 0x1dd;
	constexpr std::uint32_t ROB_CR_BKUPTMPDR6 = 0x1e0;
	constexpr std::uint32_t IA32_SMRR_PHYSBASE = 0x1f2;
	constexpr std::uint32_t IA32_SMRR_PHYSMASK = 0x1f3;
	constexpr std::uint32_t IA32_PLATFORM_DCA_CAP = 0x1f8;
	constexpr std::uint32_t IA32_CPU_DCA_CAP = 0x1f9;
	constexpr std::uint32_t IA32_DCA_0_CAP = 0x1fa;
	constexpr std::uint32_t MSR_POWER_CTL = 0x1fc;
	constexpr std::uint32_t IA32_MTRR_PHYSBASE0 = 0x200;
	constexpr std::uint32_t IA32_MTRR_PHYSMASK0 = 0x201;
	constexpr std::uint32_t IA32_MTRR_PHYSBASE1 = 0x202;
	constexpr std::uint32_t IA32_MTRR_PHYSMASK1 = 0x203;
	constexpr std::uint32_t IA32_MTRR_PHYSBASE2 = 0x204;
	constexpr std::uint32_t IA32_MTRR_PHYSMASK2 = 0x205;
	constexpr std::uint32_t IA32_MTRR_PHYSBASE3 = 0x206;
	constexpr std::uint32_t IA32_MTRR_PHYSMASK3 = 0x207;
	constexpr std::uint32_t IA32_MTRR_PHYSBASE4 = 0x208;
	constexpr std::uint32_t IA32_MTRR_PHYSMASK4 = 0x209;
	constexpr std::uint32_t IA32_MTRR_PHYSBASE5 = 0x20a;
	constexpr std::uint32_t IA32_MTRR_PHYSMASK5 = 0x20b;
	constexpr std::uint32_t IA32_MTRR_PHYSBASE6 = 0x20c;
	constexpr std::uint32_t IA32_MTRR_PHYSMASK6 = 0x20d;
	constexpr std::uint32_t IA32_MTRR_PHYSBASE7 = 0x20e;
	constexpr std::uint32_t IA32_MTRR_PHYSMASK7 = 0x20f;
	constexpr std::uint32_t IA32_MTRR_PHYSBASE8 = 0x210;
	constexpr std::uint32_t IA32_MTRR_PHYSMASK8 = 0x211;
	constexpr std::uint32_t IA32_MTRR_PHYSBASE9 = 0x212;
	constexpr std::uint32_t IA32_MTRR_PHYSMASK9 = 0x213;
	constexpr std::uint32_t IA32_MTRR_FIX64K_00000 = 0x250;
	constexpr std::uint32_t IA32_MTRR_FIX16K_80000 = 0x258;
	constexpr std::uint32_t IA32_MTRR_FIX16K_A0000 = 0x259;
	constexpr std::uint32_t IA32_MTRR_FIX4K_C0000 = 0x268;
	constexpr std::uint32_t IA32_MTRR_FIX4K_C8000 = 0x269;
	constexpr std::uint32_t IA32_MTRR_FIX4K_D0000 = 0x26a;
	constexpr std::uint32_t IA32_MTRR_FIX4K_D8000 = 0x26b;
	constexpr std::uint32_t IA32_MTRR_FIX4K_E0000 = 0x26c;
	constexpr std::uint32_t IA32_MTRR_FIX4K_E8000 = 0x26d;
	constexpr std::uint32_t IA32_MTRR_FIX4K_F0000 = 0x26e;
	constexpr std::uint32_t IA32_MTRR_FIX4K_F8000 = 0x26f;
	constexpr std::uint32_t IA32_PAT = 0x277;
	constexpr std::uint32_t IA32_MC0_CTL2 = 0x280;
	constexpr std::uint32_t IA32_MC1_CTL2 = 0x281;
	constexpr std::uint32_t IA32_MC2_CTL2 = 0x282;
	constexpr std::uint32_t IA32_MC3_CTL2 = 0x283;
	constexpr std::uint32_t IA32_MC4_CTL2 = 0x284;
	constexpr std::uint32_t MSR_MC4_CTL2 = 0x284;
	constexpr std::uint32_t IA32_MC5_CTL2 = 0x285;
	constexpr std::uint32_t IA32_MC6_CTL2 = 0x286;
	constexpr std::uint32_t IA32_MC7_CTL2 = 0x287;
	constexpr std::uint32_t IA32_MC8_CTL2 = 0x288;
	constexpr std::uint32_t IA32_MC9_CTL2 = 0x289;
	constexpr std::uint32_t IA32_MC10_CTL2 = 0x28a;
	constexpr std::uint32_t IA32_MC11_CTL2 = 0x28b;
	constexpr std::uint32_t IA32_MC12_CTL2 = 0x28c;
	constexpr std::uint32_t IA32_MC13_CTL2 = 0x28d;
	constexpr std::uint32_t IA32_MC14_CTL2 = 0x28e;
	constexpr std::uint32_t IA32_MC15_CTL2 = 0x28f;
	constexpr std::uint32_t IA32_MC16_CTL2 = 0x290;
	constexpr std::uint32_t IA32_MC17_CTL2 = 0x291;
	constexpr std::uint32_t IA32_MC18_CTL2 = 0x292;
	constexpr std::uint32_t IA32_MC19_CTL2 = 0x293;
	constexpr std::uint32_t IA32_MC20_CTL2 = 0x294;
	constexpr std::uint32_t IA32_MC21_CTL2 = 0x295;
	constexpr std::uint32_t IA32_MTRR_DEF_TYPE = 0x2ff;
	constexpr std::uint32_t MSR_BPU_COUNTER0 = 0x300;
	constexpr std::uint32_t MSR_GQ_SNOOP_MESF = 0x301;
	constexpr std::uint32_t MSR_BPU_COUNTER1 = 0x301;
	constexpr std::uint32_t MSR_BPU_COUNTER2 = 0x302;
	constexpr std::uint32_t MSR_BPU_COUNTER3 = 0x303;
	constexpr std::uint32_t MSR_MS_COUNTER0 = 0x304;
	constexpr std::uint32_t MSR_MS_COUNTER1 = 0x305;
	constexpr std::uint32_t MSR_MS_COUNTER2 = 0x306;
	constexpr std::uint32_t MSR_MS_COUNTER3 = 0x307;
	constexpr std::uint32_t MSR_FLAME_COUNTER0 = 0x308;
	constexpr std::uint32_t MSR_PERF_FIXED_CTR0 = 0x309;
	constexpr std::uint32_t IA32_FIXED_CTR0 = 0x309;
	constexpr std::uint32_t MSR_FLAME_COUNTER1 = 0x309;
	constexpr std::uint32_t MSR_PERF_FIXED_CTR1 = 0x30a;
	constexpr std::uint32_t IA32_FIXED_CTR1 = 0x30a;
	constexpr std::uint32_t MSR_FLAME_COUNTER2 = 0x30a;
	constexpr std::uint32_t MSR_PERF_FIXED_CTR2 = 0x30b;
	constexpr std::uint32_t IA32_FIXED_CTR2 = 0x30b;
	constexpr std::uint32_t MSR_FLAME_COUNTER3 = 0x30b;
	constexpr std::uint32_t MSR_IQ_COUNTER4 = 0x310;
	constexpr std::uint32_t MSR_IQ_COUNTER5 = 0x311;
	constexpr std::uint32_t IA32_PERF_CAPABILITIES = 0x345;
	constexpr std::uint32_t MSR_PERF_CAPABILITIES = 0x345;
	constexpr std::uint32_t MSR_BPU_CCCR0 = 0x360;
	constexpr std::uint32_t MSR_BPU_CCCR1 = 0x361;
	constexpr std::uint32_t MSR_BPU_CCCR2 = 0x362;
	constexpr std::uint32_t MSR_BPU_CCCR3 = 0x363;
	constexpr std::uint32_t MSR_MS_CCCR0 = 0x364;
	constexpr std::uint32_t MSR_MS_CCCR1 = 0x365;
	constexpr std::uint32_t MSR_MS_CCCR2 = 0x366;
	constexpr std::uint32_t MSR_MS_CCCR3 = 0x367;
	constexpr std::uint32_t MSR_FLAME_CCCR0 = 0x368;
	constexpr std::uint32_t MSR_FLAME_CCCR1 = 0x369;
	constexpr std::uint32_t MSR_FLAME_CCCR2 = 0x36a;
	constexpr std::uint32_t MSR_FLAME_CCCR3 = 0x36b;
	constexpr std::uint32_t MSR_IQ_CCCR0 = 0x36c;
	constexpr std::uint32_t MSR_IQ_CCCR1 = 0x36d;
	constexpr std::uint32_t MSR_IQ_CCCR2 = 0x36e;
	constexpr std::uint32_t MSR_IQ_CCCR3 = 0x36f;
	constexpr std::uint32_t MSR_IQ_CCCR4 = 0x370;
	constexpr std::uint32_t MSR_IQ_CCCR5 = 0x371;
	constexpr std::uint32_t MSR_PERF_FIXED_CTR_CTRL = 0x38d;
	constexpr std::uint32_t IA32_FIXED_CTR_CTRL = 0x38d;
	constexpr std::uint32_t MSR_PERF_GLOBAL_STAUS = 0x38e;
	constexpr std::uint32_t IA32_PERF_GLOBAL_STAUS = 0x38e;
	constexpr std::uint32_t MSR_PERF_GLOBAL_CTRL = 0x38f;
	constexpr std::uint32_t IA32_PERF_GLOBAL_CTRL = 0x38f;
	constexpr std::uint32_t MSR_PERF_GLOBAL_OVF_CTRL = 0x390;
	constexpr std::uint32_t IA32_PERF_GLOBAL_OVF_CTRL = 0x390;
	constexpr std::uint32_t MSR_UNCORE_PERF_GLOBAL_CTRL = 0x391;
	constexpr std::uint32_t MSR_UNC_PERF_GLOBAL_CTRL = 0x391;
	constexpr std::uint32_t MSR_UNCORE_PERF_GLOBAL_STATUS = 0x392;
	constexpr std::uint32_t MSR_UNC_PERF_GLOBAL_STATUS = 0x392;
	constexpr std::uint32_t MSR_UNCORE_PERF_GLOBAL_OVF_CTRL = 0x393;
	constexpr std::uint32_t MSR_UNCORE_FIXED_CTR0 = 0x394;
	constexpr std::uint32_t MSR_W_PMON_FIXED_CTR = 0x394;
	constexpr std::uint32_t MSR_UNC_PERF_FIXED_CTRL = 0x394;
	constexpr std::uint32_t MSR_UNCORE_FIXED_CTR_CTRL = 0x395;
	constexpr std::uint32_t MSR_W_PMON_FIXED_CTR_CTL = 0x395;
	constexpr std::uint32_t MSR_UNC_PERF_FIXED_CTR = 0x395;
	constexpr std::uint32_t MSR_UNCORE_ADDR_OPCODE_MATCH = 0x396;
	constexpr std::uint32_t MSR_UNC_CBO_CONFIG = 0x396;
	constexpr std::uint32_t MSR_PEBS_NUM_ALT = 0x39c;
	constexpr std::uint32_t MSR_BSU_ESCR0 = 0x3a0;
	constexpr std::uint32_t MSR_BSU_ESCR1 = 0x3a1;
	constexpr std::uint32_t MSR_FSB_ESCR0 = 0x3a2;
	constexpr std::uint32_t MSR_FSB_ESCR1 = 0x3a3;
	constexpr std::uint32_t MSR_FIRM_ESCR0 = 0x3a4;
	constexpr std::uint32_t MSR_FIRM_ESCR1 = 0x3a5;
	constexpr std::uint32_t MSR_FLAME_ESCR0 = 0x3a6;
	constexpr std::uint32_t MSR_FLAME_ESCR1 = 0x3a7;
	constexpr std::uint32_t MSR_DAC_ESCR0 = 0x3a8;
	constexpr std::uint32_t MSR_DAC_ESCR1 = 0x3a9;
	constexpr std::uint32_t MSR_MOB_ESCR0 = 0x3aa;
	constexpr std::uint32_t MSR_MOB_ESCR1 = 0x3ab;
	constexpr std::uint32_t MSR_PMH_ESCR0 = 0x3ac;
	constexpr std::uint32_t MSR_PMH_ESCR1 = 0x3ad;
	constexpr std::uint32_t MSR_SAAT_ESCR0 = 0x3ae;
	constexpr std::uint32_t MSR_SAAT_ESCR1 = 0x3af;
	constexpr std::uint32_t MSR_U2L_ESCR0 = 0x3b0;
	constexpr std::uint32_t MSR_UNCORE_PMC0 = 0x3b0;
	constexpr std::uint32_t MSR_UNC_ARB_PER_CTR0 = 0x3b0;
	constexpr std::uint32_t MSR_U2L_ESCR1 = 0x3b1;
	constexpr std::uint32_t MSR_UNCORE_PMC1 = 0x3b1;
	constexpr std::uint32_t MSR_UNC_ARB_PER_CTR1 = 0x3b1;
	constexpr std::uint32_t MSR_BPU_ESCR0 = 0x3b2;
	constexpr std::uint32_t MSR_UNCORE_PMC2 = 0x3b2;
	constexpr std::uint32_t MSR_UNC_ARB_PERFEVTSEL0 = 0x3b2;
	constexpr std::uint32_t MSR_BPU_ESCR1 = 0x3b3;
	constexpr std::uint32_t MSR_UNCORE_PMC3 = 0x3b3;
	constexpr std::uint32_t MSR_UNC_ARB_PERFEVTSEL1 = 0x3b3;
	constexpr std::uint32_t MSR_IS_ESCR0 = 0x3b4;
	constexpr std::uint32_t MSR_UNCORE_PMC4 = 0x3b4;
	constexpr std::uint32_t MSR_IS_ESCR1 = 0x3b5;
	constexpr std::uint32_t MSR_UNCORE_PMC5 = 0x3b5;
	constexpr std::uint32_t MSR_ITLB_ESCR0 = 0x3b6;
	constexpr std::uint32_t MSR_UNCORE_PMC6 = 0x3b6;
	constexpr std::uint32_t MSR_ITLB_ESCR1 = 0x3b7;
	constexpr std::uint32_t MSR_UNCORE_PMC7 = 0x3b7;
	constexpr std::uint32_t MSR_CRU_ESCR0 = 0x3b8;
	constexpr std::uint32_t MSR_CRU_ESCR1 = 0x3b9;
	constexpr std::uint32_t MSR_IQ_ESCR0 = 0x3ba;
	constexpr std::uint32_t MSR_IQ_ESCR1 = 0x3bb;
	constexpr std::uint32_t MSR_RAT_ESCR0 = 0x3bc;
	constexpr std::uint32_t MSR_RAT_ESCR1 = 0x3bd;
	constexpr std::uint32_t MSR_SSU_ESCR0 = 0x3be;
	constexpr std::uint32_t MSR_MS_ESCR0 = 0x3c0;
	constexpr std::uint32_t MSR_UNCORE_PERFEVTSEL0 = 0x3c0;
	constexpr std::uint32_t MSR_MS_ESCR1 = 0x3c1;
	constexpr std::uint32_t MSR_UNCORE_PERFEVTSEL1 = 0x3c1;
	constexpr std::uint32_t MSR_TBPU_ESCR0 = 0x3c2;
	constexpr std::uint32_t MSR_UNCORE_PERFEVTSEL2 = 0x3c2;
	constexpr std::uint32_t MSR_TBPU_ESCR1 = 0x3c3;
	constexpr std::uint32_t MSR_UNCORE_PERFEVTSEL3 = 0x3c3;
	constexpr std::uint32_t MSR_TC_ESCR0 = 0x3c4;
	constexpr std::uint32_t MSR_UNCORE_PERFEVTSEL4 = 0x3c4;
	constexpr std::uint32_t MSR_TC_ESCR1 = 0x3c5;
	constexpr std::uint32_t MSR_UNCORE_PERFEVTSEL5 = 0x3c5;
	constexpr std::uint32_t MSR_UNCORE_PERFEVTSEL6 = 0x3c6;
	constexpr std::uint32_t MSR_UNCORE_PERFEVTSEL7 = 0x3c7;
	constexpr std::uint32_t MSR_IX_ESCR0 = 0x3c8;
	constexpr std::uint32_t MSR_ALF_ESCR0 = 0x3ca;
	constexpr std::uint32_t MSR_ALF_ESCR1 = 0x3cb;
	constexpr std::uint32_t MSR_CRU_ESCR2 = 0x3cc;
	constexpr std::uint32_t MSR_CRU_ESCR3 = 0x3cd;
	constexpr std::uint32_t MSR_CRU_ESCR4 = 0x3e0;
	constexpr std::uint32_t MSR_CRU_ESCR5 = 0x3e1;
	constexpr std::uint32_t IA32_PEBS_ENABLE = 0x3f1;
	constexpr std::uint32_t MSR_PEBS_ENABLE = 0x3f1;
	constexpr std::uint32_t MSR_PEBS_MATRIX_VERT = 0x3f2;
	constexpr std::uint32_t MSR_PEBS_LD_LAT = 0x3f6;
	constexpr std::uint32_t MSR_PKG_C3_RESIDENCY = 0x3f8;
	constexpr std::uint32_t MSR_PKG_C2_RESIDENCY = 0x3f8;
	constexpr std::uint32_t MSR_PKG_C6C_RESIDENCY = 0x3f9;
	constexpr std::uint32_t MSR_PKG_C4_RESIDENCY = 0x3f9;
	constexpr std::uint32_t MSR_PKG_C7_RESIDENCY = 0x3fa;
	constexpr std::uint32_t MSR_PKG_C6_RESIDENCY = 0x3fa;
	constexpr std::uint32_t MSR_CORE_C3_RESIDENCY = 0x3fc;
	constexpr std::uint32_t MSR_CORE_C4_RESIDENCY = 0x3fc;
	constexpr std::uint32_t MSR_CORE_C6_RESIDENCY = 0x3fd;
	constexpr std::uint32_t MSR_CORE_C7_RESIDENCY = 0x3fe;
	constexpr std::uint32_t MC0_CTL = 0x400;
	constexpr std::uint32_t IA32_MC0_CTL = 0x400;
	constexpr std::uint32_t MC0_STATUS = 0x401;
	constexpr std::uint32_t IA32_MC0_STATUS = 0x401;
	constexpr std::uint32_t MC0_ADDR = 0x402;
	constexpr std::uint32_t IA32_MC0_ADDR1 = 0x402;
	constexpr std::uint32_t IA32_MC0_ADDR = 0x402;
	constexpr std::uint32_t MC0_MISC = 0x403;
	constexpr std::uint32_t IA32_MC0_MISC = 0x403;
	constexpr std::uint32_t MSR_MC0_MISC = 0x403;
	constexpr std::uint32_t MC1_CTL = 0x404;
	constexpr std::uint32_t IA32_MC1_CTL = 0x404;
	constexpr std::uint32_t MC1_STATUS = 0x405;
	constexpr std::uint32_t IA32_MC1_STATUS = 0x405;
	constexpr std::uint32_t MC1_ADDR = 0x406;
	constexpr std::uint32_t IA32_MC1_ADDR2 = 0x406;
	constexpr std::uint32_t IA32_MC1_ADDR = 0x406;
	constexpr std::uint32_t MC1_MISC = 0x407;
	constexpr std::uint32_t IA32_MC1_MISC = 0x407;
	constexpr std::uint32_t MSR_MC1_MISC = 0x407;
	constexpr std::uint32_t MC2_CTL = 0x408;
	constexpr std::uint32_t IA32_MC2_CTL = 0x408;
	constexpr std::uint32_t MC2_STATUS = 0x409;
	constexpr std::uint32_t IA32_MC2_STATUS = 0x409;
	constexpr std::uint32_t MC2_ADDR = 0x40a;
	constexpr std::uint32_t IA32_MC2_ADDR1 = 0x40a;
	constexpr std::uint32_t IA32_MC2_ADDR = 0x40a;
	constexpr std::uint32_t MC2_MISC = 0x40b;
	constexpr std::uint32_t IA32_MC2_MISC = 0x40b;
	constexpr std::uint32_t MSR_MC2_MISC = 0x40b;
	constexpr std::uint32_t MC4_CTL = 0x40c;
	constexpr std::uint32_t IA32_MC3_CTL = 0x40c;
	constexpr std::uint32_t MSR_MC4_CTL = 0x40c;
	constexpr std::uint32_t MC4_STATUS = 0x40d;
	constexpr std::uint32_t IA32_MC3_STATUS = 0x40d;
	constexpr std::uint32_t MSR_MC4_STATUS = 0x40d;
	constexpr std::uint32_t MC4_ADDR = 0x40e;
	constexpr std::uint32_t IA32_MC3_ADDR1 = 0x40e;
	constexpr std::uint32_t IA32_MC3_ADDR = 0x40e;
	constexpr std::uint32_t MSR_MC4_ADDR = 0x412;
	constexpr std::uint32_t MC4_MISC = 0x40f;
	constexpr std::uint32_t IA32_MC3_MISC = 0x40f;
	constexpr std::uint32_t MC3_CTL = 0x410;
	constexpr std::uint32_t IA32_MC4_CTL = 0x410;
	constexpr std::uint32_t MSR_MC3_CTL = 0x410;
	constexpr std::uint32_t MC3_STATUS = 0x411;
	constexpr std::uint32_t IA32_MC4_STATUS = 0x411;
	constexpr std::uint32_t MSR_MC3_STATUS = 0x411;
	constexpr std::uint32_t MC3_ADDR = 0x412;
	constexpr std::uint32_t IA32_MC4_ADDR1 = 0x412;
	constexpr std::uint32_t IA32_MC4_ADDR = 0x412;
	constexpr std::uint32_t MSR_MC3_ADDR = 0x412;
	constexpr std::uint32_t MSR_MC3_MISC = 0x40f;
	constexpr std::uint32_t MC3_MISC = 0x413;
	constexpr std::uint32_t IA32_MC4_MISC = 0x413;
	constexpr std::uint32_t MSR_MC4_MISC = 0x413;
	constexpr std::uint32_t MSR_MC5_CTL = 0x414;
	constexpr std::uint32_t IA32_MC5_CTL = 0x414;
	constexpr std::uint32_t MSR_MC5_STATUS = 0x415;
	constexpr std::uint32_t IA32_MC5_STATUS = 0x415;
	constexpr std::uint32_t MSR_MC5_ADDR = 0x416;
	constexpr std::uint32_t IA32_MC5_ADDR1 = 0x416;
	constexpr std::uint32_t MSR_MC5_MISC = 0x417;
	constexpr std::uint32_t IA32_MC5_MISC = 0x417;
	constexpr std::uint32_t IA32_MC6_CTL = 0x418;
	constexpr std::uint32_t MSR_MC6_CTL = 0x418;
	constexpr std::uint32_t IA32_MC6_STATUS = 0x419;
	constexpr std::uint32_t MSR_MC6_STATUS = 0x419;
	constexpr std::uint32_t IA32_MC6_ADDR1 = 0x41a;
	constexpr std::uint32_t MSR_MC6_ADDR = 0x41a;
	constexpr std::uint32_t IA32_MC6_MISC = 0x41b;
	constexpr std::uint32_t MSR_MC6_MISC = 0x41b;
	constexpr std::uint32_t IA32_MC7_CTL = 0x41c;
	constexpr std::uint32_t MSR_MC7_CTL = 0x41c;
	constexpr std::uint32_t IA32_MC7_STATUS = 0x41d;
	constexpr std::uint32_t MSR_MC7_STATUS = 0x41d;
	constexpr std::uint32_t IA32_MC7_ADDR1 = 0x41e;
	constexpr std::uint32_t MSR_MC7_ADDR = 0x41e;
	constexpr std::uint32_t IA32_MC7_MISC = 0x41f;
	constexpr std::uint32_t MSR_MC7_MISC = 0x41f;
	constexpr std::uint32_t IA32_MC8_CTL = 0x420;
	constexpr std::uint32_t MSR_MC8_CTL = 0x420;
	constexpr std::uint32_t IA32_MC8_STATUS = 0x421;
	constexpr std::uint32_t MSR_MC8_STATUS = 0x421;
	constexpr std::uint32_t IA32_MC8_ADDR1 = 0x422;
	constexpr std::uint32_t MSR_MC8_ADDR = 0x422;
	constexpr std::uint32_t IA32_MC8_MISC = 0x423;
	constexpr std::uint32_t MSR_MC8_MISC = 0x423;
	constexpr std::uint32_t IA32_MC9_CTL = 0x424;
	constexpr std::uint32_t MSR_MC9_CTL = 0x424;
	constexpr std::uint32_t IA32_MC9_STATUS = 0x425;
	constexpr std::uint32_t MSR_MC9_STATUS = 0x425;
	constexpr std::uint32_t IA32_MC9_ADDR1 = 0x426;
	constexpr std::uint32_t MSR_MC9_ADDR = 0x426;
	constexpr std::uint32_t IA32_MC9_MISC = 0x427;
	constexpr std::uint32_t MSR_MC9_MISC = 0x427;
	constexpr std::uint32_t IA32_MC10_CTL = 0x428;
	constexpr std::uint32_t MSR_MC10_CTL = 0x428;
	constexpr std::uint32_t IA32_MC10_STATUS = 0x429;
	constexpr std::uint32_t MSR_MC10_STATUS = 0x429;
	constexpr std::uint32_t IA32_MC10_ADDR1 = 0x42a;
	constexpr std::uint32_t MSR_MC10_ADDR = 0x42a;
	constexpr std::uint32_t IA32_MC10_MISC = 0x42b;
	constexpr std::uint32_t MSR_MC10_MISC = 0x42b;
	constexpr std::uint32_t IA32_MC11_CTL = 0x42c;
	constexpr std::uint32_t MSR_MC11_CTL = 0x42c;
	constexpr std::uint32_t IA32_MC11_STATUS = 0x42d;
	constexpr std::uint32_t MSR_MC11_STATUS = 0x42d;
	constexpr std::uint32_t IA32_MC11_ADDR1 = 0x42e;
	constexpr std::uint32_t MSR_MC11_ADDR = 0x42e;
	constexpr std::uint32_t IA32_MC11_MISC = 0x42f;
	constexpr std::uint32_t MSR_MC11_MISC = 0x42f;
	constexpr std::uint32_t IA32_MC12_CTL = 0x430;
	constexpr std::uint32_t MSR_MC12_CTL = 0x430;
	constexpr std::uint32_t IA32_MC12_STATUS = 0x431;
	constexpr std::uint32_t MSR_MC12_STATUS = 0x431;
	constexpr std::uint32_t IA32_MC12_ADDR1 = 0x432;
	constexpr std::uint32_t MSR_MC12_ADDR = 0x432;
	constexpr std::uint32_t IA32_MC12_MISC = 0x433;
	constexpr std::uint32_t MSR_MC12_MISC = 0x433;
	constexpr std::uint32_t IA32_MC13_CTL = 0x434;
	constexpr std::uint32_t MSR_MC13_CTL = 0x434;
	constexpr std::uint32_t IA32_MC13_STATUS = 0x435;
	constexpr std::uint32_t MSR_MC13_STATUS = 0x435;
	constexpr std::uint32_t IA32_MC13_ADDR1 = 0x436;
	constexpr std::uint32_t MSR_MC13_ADDR = 0x436;
	constexpr std::uint32_t IA32_MC13_MISC = 0x437;
	constexpr std::uint32_t MSR_MC13_MISC = 0x437;
	constexpr std::uint32_t IA32_MC14_CTL = 0x438;
	constexpr std::uint32_t MSR_MC14_CTL = 0x438;
	constexpr std::uint32_t IA32_MC14_STATUS = 0x439;
	constexpr std::uint32_t MSR_MC14_STATUS = 0x439;
	constexpr std::uint32_t IA32_MC14_ADDR1 = 0x43a;
	constexpr std::uint32_t MSR_MC14_ADDR = 0x43a;
	constexpr std::uint32_t IA32_MC14_MISC = 0x43b;
	constexpr std::uint32_t MSR_MC14_MISC = 0x43b;
	constexpr std::uint32_t IA32_MC15_CTL = 0x43c;
	constexpr std::uint32_t MSR_MC15_CTL = 0x43c;
	constexpr std::uint32_t IA32_MC15_STATUS = 0x43d;
	constexpr std::uint32_t MSR_MC15_STATUS = 0x43d;
	constexpr std::uint32_t IA32_MC15_ADDR1 = 0x43e;
	constexpr std::uint32_t MSR_MC15_ADDR = 0x43e;
	constexpr std::uint32_t IA32_MC15_MISC = 0x43f;
	constexpr std::uint32_t MSR_MC15_MISC = 0x43f;
	constexpr std::uint32_t IA32_MC16_CTL = 0x440;
	constexpr std::uint32_t MSR_MC16_CTL = 0x440;
	constexpr std::uint32_t IA32_MC16_STATUS = 0x441;
	constexpr std::uint32_t MSR_MC16_STATUS = 0x441;
	constexpr std::uint32_t IA32_MC16_ADDR1 = 0x442;
	constexpr std::uint32_t MSR_MC16_ADDR = 0x442;
	constexpr std::uint32_t IA32_MC16_MISC = 0x443;
	constexpr std::uint32_t MSR_MC16_MISC = 0x443;
	constexpr std::uint32_t IA32_MC17_CTL = 0x444;
	constexpr std::uint32_t MSR_MC17_CTL = 0x444;
	constexpr std::uint32_t IA32_MC17_STATUS = 0x445;
	constexpr std::uint32_t MSR_MC17_STATUS = 0x445;
	constexpr std::uint32_t IA32_MC17_ADDR1 = 0x446;
	constexpr std::uint32_t MSR_MC17_ADDR = 0x446;
	constexpr std::uint32_t IA32_MC17_MISC = 0x447;
	constexpr std::uint32_t MSR_MC17_MISC = 0x447;
	constexpr std::uint32_t IA32_MC18_CTL = 0x448;
	constexpr std::uint32_t MSR_MC18_CTL = 0x448;
	constexpr std::uint32_t IA32_MC18_STATUS = 0x449;
	constexpr std::uint32_t MSR_MC18_STATUS = 0x449;
	constexpr std::uint32_t IA32_MC18_ADDR1 = 0x44a;
	constexpr std::uint32_t MSR_MC18_ADDR = 0x44a;
	constexpr std::uint32_t IA32_MC18_MISC = 0x44b;
	constexpr std::uint32_t MSR_MC18_MISC = 0x44b;
	constexpr std::uint32_t IA32_MC19_CTL = 0x44c;
	constexpr std::uint32_t MSR_MC19_CTL = 0x44c;
	constexpr std::uint32_t IA32_MC19_STATUS = 0x44d;
	constexpr std::uint32_t MSR_MC19_STATUS = 0x44d;
	constexpr std::uint32_t IA32_MC19_ADDR1 = 0x44e;
	constexpr std::uint32_t MSR_MC19_ADDR = 0x44e;
	constexpr std::uint32_t IA32_MC19_MISC = 0x44f;
	constexpr std::uint32_t MSR_MC19_MISC = 0x44f;
	constexpr std::uint32_t IA32_MC20_CTL = 0x450;
	constexpr std::uint32_t MSR_MC20_CTL = 0x450;
	constexpr std::uint32_t IA32_MC20_STATUS = 0x451;
	constexpr std::uint32_t MSR_MC20_STATUS = 0x451;
	constexpr std::uint32_t IA32_MC20_ADDR1 = 0x452;
	constexpr std::uint32_t MSR_MC20_ADDR = 0x452;
	constexpr std::uint32_t IA32_MC20_MISC = 0x453;
	constexpr std::uint32_t MSR_MC20_MISC = 0x453;
	constexpr std::uint32_t IA32_MC21_CTL = 0x454;
	constexpr std::uint32_t MSR_MC21_CTL = 0x454;
	constexpr std::uint32_t IA32_MC21_STATUS = 0x455;
	constexpr std::uint32_t MSR_MC21_STATUS = 0x455;
	constexpr std::uint32_t IA32_MC21_ADDR1 = 0x456;
	constexpr std::uint32_t MSR_MC21_ADDR = 0x456;
	constexpr std::uint32_t IA32_MC21_MISC = 0x457;
	constexpr std::uint32_t MSR_MC21_MISC = 0x457;
	constexpr std::uint32_t MSR_MC22_CTL = 0x458;
	constexpr std::uint32_t MSR_MC22_STATUS = 0x459;
	constexpr std::uint32_t MSR_MC22_ADDR = 0x45a;
	constexpr std::uint32_t MSR_MC22_MISC = 0x45b;
	constexpr std::uint32_t MSR_MC23_CTL = 0x45c;
	constexpr std::uint32_t MSR_MC23_STATUS = 0x45d;
	constexpr std::uint32_t MSR_MC23_ADDR = 0x45e;
	constexpr std::uint32_t MSR_MC23_MISC = 0x45f;
	constexpr std::uint32_t MSR_MC24_CTL = 0x460;
	constexpr std::uint32_t MSR_MC24_STATUS = 0x461;
	constexpr std::uint32_t MSR_MC24_ADDR = 0x462;
	constexpr std::uint32_t MSR_MC24_MISC = 0x463;
	constexpr std::uint32_t MSR_MC25_CTL = 0x464;
	constexpr std::uint32_t MSR_MC25_STATUS = 0x465;
	constexpr std::uint32_t MSR_MC25_ADDR = 0x466;
	constexpr std::uint32_t MSR_MC25_MISC = 0x467;
	constexpr std::uint32_t MSR_MC26_CTL = 0x468;
	constexpr std::uint32_t MSR_MC26_STATUS = 0x469;
	constexpr std::uint32_t MSR_MC26_ADDR = 0x46a;
	constexpr std::uint32_t MSR_MC26_MISC = 0x46b;
	constexpr std::uint32_t IA32_VMX_BASIC = 0x480;
	constexpr std::uint32_t IA32_VMX_PINBASED_CTLS = 0x481;
	constexpr std::uint32_t IA32_VMX_PROCBASED_CTLS = 0x482;
	constexpr std::uint32_t IA32_VMX_EXIT_CTLS = 0x483;
	constexpr std::uint32_t IA32_VMX_ENTRY_CTLS = 0x484;
	constexpr std::uint32_t IA32_VMX_MISC = 0x485;
	constexpr std::uint32_t IA32_VMX_CR0_FIXED0 = 0x486;
	constexpr std::uint32_t IA32_VMX_CRO_FIXED0 = 0x486;
	constexpr std::uint32_t IA32_VMX_CR0_FIXED1 = 0x487;
	constexpr std::uint32_t IA32_VMX_CRO_FIXED1 = 0x487;
	constexpr std::uint32_t IA32_VMX_CR4_FIXED0 = 0x488;
	constexpr std::uint32_t IA32_VMX_CR4_FIXED1 = 0x489;
	constexpr std::uint32_t IA32_VMX_VMCS_ENUM = 0x48a;
	constexpr std::uint32_t IA32_VMX_PROCBASED_CTLS2 = 0x48b;
	constexpr std::uint32_t IA32_VMX_EPT_VPID_ENUM = 0x48c;
	constexpr std::uint32_t IA32_VMX_EPT_VPID_CAP = 0x48c;
	constexpr std::uint32_t IA32_VMX_TRUE_PINBASED_CTLS = 0x48d;
	constexpr std::uint32_t IA32_VMX_TRUE_PROCBASED_CTLS = 0x48e;
	constexpr std::uint32_t IA32_VMX_TRUE_EXIT_CTLS = 0x48f;
	constexpr std::uint32_t IA32_VMX_TRUE_ENTRY_CTLS = 0x490;
	constexpr std::uint32_t IA32_VMX_FMFUNC = 0x491;
	constexpr std::uint32_t IA32_VMX_VMFUNC = 0x491;
	constexpr std::uint32_t IA32_A_PMC0 = 0x4c1;
	constexpr std::uint32_t IA32_A_PMC1 = 0x4c2;
	constexpr std::uint32_t IA32_A_PMC2 = 0x4c3;
	constexpr std::uint32_t IA32_A_PMC3 = 0x4c4;
	constexpr std::uint32_t IA32_A_PMC4 = 0x4c5;
	constexpr std::uint32_t IA32_A_PMC5 = 0x4c6;
	constexpr std::uint32_t IA32_A_PMC6 = 0x4c7;
	constexpr std::uint32_t IA32_A_PMC7 = 0x4c8;
	constexpr std::uint32_t MSR_SMM_FEATURE_CONTROL = 0x4e0;
	constexpr std::uint32_t MSR_SMM_DELAYED = 0x4e2;
	constexpr std::uint32_t MSR_SMM_BLOCKED = 0x4e3;
	constexpr std::uint32_t MSR_IA32_RTIT_OUTPUT_BASE = 0x560;
	constexpr std::uint32_t MSR_IA32_RTIT_OUTPUT_MASK_PTRS = 0x561;
	constexpr std::uint32_t MSR_IA32_RTIT_CTL = 0x570;
	constexpr std::uint32_t MSR_IA32_RTIT_STATUS = 0x571;
	constexpr std::uint32_t MSR_IA32_CR3_MATCH = 0x572;
	constexpr std::uint32_t MSR_IA32_ADDR0_START = 0x580;
	constexpr std::uint32_t MSR_IA32_ADDR0_END = 0x581;
	constexpr std::uint32_t MSR_IA32_ADDR1_START = 0x582;
	constexpr std::uint32_t MSR_IA32_ADDR1_END = 0x583;
	constexpr std::uint32_t MSR_IA32_ADDR2_START = 0x584;
	constexpr std::uint32_t MSR_IA32_ADDR2_END = 0x585;
	constexpr std::uint32_t MSR_IA32_ADDR3_START = 0x586;
	constexpr std::uint32_t MSR_IA32_ADDR3_END = 0x587;
	constexpr std::uint32_t IA32_DS_AREA = 0x600;
	constexpr std::uint32_t MSR_RAPL_POWER_UNIT = 0x606;
	constexpr std::uint32_t MSR_PKGC3_IRTL = 0x60a;
	constexpr std::uint32_t MSR_PKGC6_IRTL = 0x60b;
	constexpr std::uint32_t MSR_PKGC7_IRTL = 0x60c;
	constexpr std::uint32_t MSR_PKG_POWER_LIMIT = 0x610;
	constexpr std::uint32_t MSR_PKG_ENERGY_STATUS = 0x611;
	constexpr std::uint32_t MSR_PKG_PERF_STATUS = 0x613;
	constexpr std::uint32_t MSR_PKG_POWER_INFO = 0x614;
	constexpr std::uint32_t MSR_DRAM_POWER_LIMIT = 0x618;
	constexpr std::uint32_t MSR_DRAM_ENERGY_STATUS = 0x619;
	constexpr std::uint32_t MSR_DRAM_PERF_STATUS = 0x61b;
	constexpr std::uint32_t MSR_DRAM_POWER_INFO = 0x61c;
	constexpr std::uint32_t MSR_PKG_C9_RESIDENCY = 0x631;
	constexpr std::uint32_t MSR_PKG_C10_RESIDENCY = 0x632;
	constexpr std::uint32_t MSR_PP0_POWER_LIMIT = 0x638;
	constexpr std::uint32_t MSR_PP0_ENERGY_STATUS = 0x639;
	constexpr std::uint32_t MSR_PP0_POLICY = 0x63a;
	constexpr std::uint32_t MSR_PP0_PERF_STATUS = 0x63b;
	constexpr std::uint32_t MSR_PP1_POWER_LIMIT = 0x640;
	constexpr std::uint32_t MSR_PP1_ENERGY_STATUS = 0x641;
	constexpr std::uint32_t MSR_PP1_POLICY = 0x642;
	constexpr std::uint32_t MSR_CONFIG_TDP_NOMINAL = 0x648;
	constexpr std::uint32_t MSR_CONFIG_TDP_LEVEL1 = 0x649;
	constexpr std::uint32_t MSR_CONFIG_TDP_LEVEL2 = 0x64a;
	constexpr std::uint32_t MSR_CONFIG_TDP_CONTROL = 0x64b;
	constexpr std::uint32_t MSR_TURBO_ACTIVATION_RATIO = 0x64c;
	constexpr std::uint32_t MSR_CORE_C1_RESIDENCY = 0x660;
	constexpr std::uint32_t MSR_LASTBRANCH_8_FROM_IP = 0x688;
	constexpr std::uint32_t MSR_LASTBRANCH_9_FROM_IP = 0x689;
	constexpr std::uint32_t MSR_LASTBRANCH_10_FROM_IP = 0x68a;
	constexpr std::uint32_t MSR_LASTBRANCH_11_FROM_IP = 0x68b;
	constexpr std::uint32_t MSR_LASTBRANCH_12_FROM_IP = 0x68c;
	constexpr std::uint32_t MSR_LASTBRANCH_13_FROM_IP = 0x68d;
	constexpr std::uint32_t MSR_LASTBRANCH_14_FROM_IP = 0x68e;
	constexpr std::uint32_t MSR_LASTBRANCH_15_FROM_IP = 0x68f;
	constexpr std::uint32_t MSR_LASTBRANCH_8_TO_IP = 0x6c8;
	constexpr std::uint32_t MSR_LASTBRANCH_9_TO_IP = 0x6c9;
	constexpr std::uint32_t MSR_LASTBRANCH_10_TO_IP = 0x6ca;
	constexpr std::uint32_t MSR_LASTBRANCH_11_TO_IP = 0x6cb;
	constexpr std::uint32_t MSR_LASTBRANCH_12_TO_IP = 0x6cc;
	constexpr std::uint32_t MSR_LASTBRANCH_13_TO_IP = 0x6cd;
	constexpr std::uint32_t MSR_LASTBRANCH_14_TO_IP = 0x6ce;
	constexpr std::uint32_t MSR_LASTBRANCH_15_TO_IP = 0x6cf;
	constexpr std::uint32_t IA32_TSC_DEADLINE = 0x6e0;
	constexpr std::uint32_t MSR_UNC_CBO_0_PERFEVTSEL0 = 0x700;
	constexpr std::uint32_t MSR_UNC_CBO_0_PERFEVTSEL1 = 0x701;
	constexpr std::uint32_t MSR_UNC_CBO_0_PER_CTR0 = 0x706;
	constexpr std::uint32_t MSR_UNC_CBO_0_PER_CTR1 = 0x707;
	constexpr std::uint32_t MSR_UNC_CBO_1_PERFEVTSEL0 = 0x710;
	constexpr std::uint32_t MSR_UNC_CBO_1_PERFEVTSEL1 = 0x711;
	constexpr std::uint32_t MSR_UNC_CBO_1_PER_CTR0 = 0x716;
	constexpr std::uint32_t MSR_UNC_CBO_1_PER_CTR1 = 0x717;
	constexpr std::uint32_t MSR_UNC_CBO_2_PERFEVTSEL0 = 0x720;
	constexpr std::uint32_t MSR_UNC_CBO_2_PERFEVTSEL1 = 0x721;
	constexpr std::uint32_t MSR_UNC_CBO_2_PER_CTR0 = 0x726;
	constexpr std::uint32_t MSR_UNC_CBO_2_PER_CTR1 = 0x727;
	constexpr std::uint32_t MSR_UNC_CBO_3_PERFEVTSEL0 = 0x730;
	constexpr std::uint32_t MSR_UNC_CBO_3_PERFEVTSEL1 = 0x731;
	constexpr std::uint32_t MSR_UNC_CBO_3_PER_CTR0 = 0x736;
	constexpr std::uint32_t MSR_UNC_CBO_3_PER_CTR1 = 0x737;
	constexpr std::uint32_t IA32_X2APIC_APICID = 0x802;
	constexpr std::uint32_t IA32_X2APIC_VERSION = 0x803;
	constexpr std::uint32_t IA32_X2APIC_TPR = 0x808;
	constexpr std::uint32_t IA32_X2APIC_PPR = 0x80a;
	constexpr std::uint32_t IA32_X2APIC_EOI = 0x80b;
	constexpr std::uint32_t IA32_X2APIC_LDR = 0x80d;
	constexpr std::uint32_t IA32_X2APIC_SIVR = 0x80f;
	constexpr std::uint32_t IA32_X2APIC_ISR0 = 0x810;
	constexpr std::uint32_t IA32_X2APIC_ISR1 = 0x811;
	constexpr std::uint32_t IA32_X2APIC_ISR2 = 0x812;
	constexpr std::uint32_t IA32_X2APIC_ISR3 = 0x813;
	constexpr std::uint32_t IA32_X2APIC_ISR4 = 0x814;
	constexpr std::uint32_t IA32_X2APIC_ISR5 = 0x815;
	constexpr std::uint32_t IA32_X2APIC_ISR6 = 0x816;
	constexpr std::uint32_t IA32_X2APIC_ISR7 = 0x817;
	constexpr std::uint32_t IA32_X2APIC_TMR0 = 0x818;
	constexpr std::uint32_t IA32_X2APIC_TMR1 = 0x819;
	constexpr std::uint32_t IA32_X2APIC_TMR2 = 0x81a;
	constexpr std::uint32_t IA32_X2APIC_TMR3 = 0x81b;
	constexpr std::uint32_t IA32_X2APIC_TMR4 = 0x81c;
	constexpr std::uint32_t IA32_X2APIC_TMR5 = 0x81d;
	constexpr std::uint32_t IA32_X2APIC_TMR6 = 0x81e;
	constexpr std::uint32_t IA32_X2APIC_TMR7 = 0x81f;
	constexpr std::uint32_t IA32_X2APIC_IRR0 = 0x820;
	constexpr std::uint32_t IA32_X2APIC_IRR1 = 0x821;
	constexpr std::uint32_t IA32_X2APIC_IRR2 = 0x822;
	constexpr std::uint32_t IA32_X2APIC_IRR3 = 0x823;
	constexpr std::uint32_t IA32_X2APIC_IRR4 = 0x824;
	constexpr std::uint32_t IA32_X2APIC_IRR5 = 0x825;
	constexpr std::uint32_t IA32_X2APIC_IRR6 = 0x826;
	constexpr std::uint32_t IA32_X2APIC_IRR7 = 0x827;
	constexpr std::uint32_t IA32_X2APIC_ESR = 0x828;
	constexpr std::uint32_t IA32_X2APIC_LVT_CMCI = 0x82f;
	constexpr std::uint32_t IA32_X2APIC_ICR = 0x830;
	constexpr std::uint32_t IA32_X2APIC_LVT_TIMER = 0x832;
	constexpr std::uint32_t IA32_X2APIC_LVT_THERMAL = 0x833;
	constexpr std::uint32_t IA32_X2APIC_LVT_PMI = 0x834;
	constexpr std::uint32_t IA32_X2APIC_LVT_LINT0 = 0x835;
	constexpr std::uint32_t IA32_X2APIC_LVT_LINT1 = 0x836;
	constexpr std::uint32_t IA32_X2APIC_LVT_ERROR = 0x837;
	constexpr std::uint32_t IA32_X2APIC_INIT_COUNT = 0x838;
	constexpr std::uint32_t IA32_X2APIC_CUR_COUNT = 0x839;
	constexpr std::uint32_t IA32_X2APIC_DIV_CONF = 0x83e;
	constexpr std::uint32_t IA32_X2APIC_SELF_IPI = 0x83f;
	constexpr std::uint32_t MSR_U_PMON_GLOBAL_CTRL = 0xc00;
	constexpr std::uint32_t MSR_U_PMON_GLOBAL_STATUS = 0xc01;
	constexpr std::uint32_t MSR_U_PMON_GLOBAL_OVF_CTRL = 0xc02;
	constexpr std::uint32_t MSR_U_PMON_EVNT_SEL = 0xc10;
	constexpr std::uint32_t MSR_U_PMON_CTR = 0xc11;
	constexpr std::uint32_t MSR_B0_PMON_BOX_CTRL = 0xc20;
	constexpr std::uint32_t MSR_B0_PMON_BOX_STATUS = 0xc21;
	constexpr std::uint32_t MSR_B0_PMON_BOX_OVF_CTRL = 0xc22;
	constexpr std::uint32_t MSR_B0_PMON_EVNT_SEL0 = 0xc30;
	constexpr std::uint32_t MSR_B0_PMON_CTR0 = 0xc31;
	constexpr std::uint32_t MSR_B0_PMON_EVNT_SEL1 = 0xc32;
	constexpr std::uint32_t MSR_B0_PMON_CTR1 = 0xc33;
	constexpr std::uint32_t MSR_B0_PMON_EVNT_SEL2 = 0xc34;
	constexpr std::uint32_t MSR_B0_PMON_CTR2 = 0xc35;
	constexpr std::uint32_t MSR_B0_PMON_EVNT_SEL3 = 0xc36;
	constexpr std::uint32_t MSR_B0_PMON_CTR3 = 0xc37;
	constexpr std::uint32_t MSR_S0_PMON_BOX_CTRL = 0xc40;
	constexpr std::uint32_t MSR_S0_PMON_BOX_STATUS = 0xc41;
	constexpr std::uint32_t MSR_S0_PMON_BOX_OVF_CTRL = 0xc42;
	constexpr std::uint32_t MSR_S0_PMON_EVNT_SEL0 = 0xc50;
	constexpr std::uint32_t MSR_S0_PMON_CTR0 = 0xc51;
	constexpr std::uint32_t MSR_S0_PMON_EVNT_SEL1 = 0xc52;
	constexpr std::uint32_t MSR_S0_PMON_CTR1 = 0xc53;
	constexpr std::uint32_t MSR_S0_PMON_EVNT_SEL2 = 0xc54;
	constexpr std::uint32_t MSR_S0_PMON_CTR2 = 0xc55;
	constexpr std::uint32_t MSR_S0_PMON_EVNT_SEL3 = 0xc56;
	constexpr std::uint32_t MSR_S0_PMON_CTR3 = 0xc57;
	constexpr std::uint32_t MSR_B1_PMON_BOX_CTRL = 0xc60;
	constexpr std::uint32_t MSR_B1_PMON_BOX_STATUS = 0xc61;
	constexpr std::uint32_t MSR_B1_PMON_BOX_OVF_CTRL = 0xc62;
	constexpr std::uint32_t MSR_B1_PMON_EVNT_SEL0 = 0xc70;
	constexpr std::uint32_t MSR_B1_PMON_CTR0 = 0xc71;
	constexpr std::uint32_t MSR_B1_PMON_EVNT_SEL1 = 0xc72;
	constexpr std::uint32_t MSR_B1_PMON_CTR1 = 0xc73;
	constexpr std::uint32_t MSR_B1_PMON_EVNT_SEL2 = 0xc74;
	constexpr std::uint32_t MSR_B1_PMON_CTR2 = 0xc75;
	constexpr std::uint32_t MSR_B1_PMON_EVNT_SEL3 = 0xc76;
	constexpr std::uint32_t MSR_B1_PMON_CTR3 = 0xc77;
	constexpr std::uint32_t MSR_W_PMON_BOX_CTRL = 0xc80;
	constexpr std::uint32_t MSR_W_PMON_BOX_STATUS = 0xc81;
	constexpr std::uint32_t MSR_W_PMON_BOX_OVF_CTRL = 0xc82;
	constexpr std::uint32_t IA32_QM_EVTSEL = 0xc8d;
	constexpr std::uint32_t IA32_QM_CTR = 0xc8e;
	constexpr std::uint32_t IA32_PQR_ASSOC = 0xc8f;
	constexpr std::uint32_t MSR_W_PMON_EVNT_SEL0 = 0xc90;
	constexpr std::uint32_t MSR_W_PMON_CTR0 = 0xc91;
	constexpr std::uint32_t MSR_W_PMON_EVNT_SEL1 = 0xc92;
	constexpr std::uint32_t MSR_W_PMON_CTR1 = 0xc93;
	constexpr std::uint32_t MSR_W_PMON_EVNT_SEL2 = 0xc94;
	constexpr std::uint32_t MSR_W_PMON_CTR2 = 0xc95;
	constexpr std::uint32_t MSR_W_PMON_EVNT_SEL3 = 0xc96;
	constexpr std::uint32_t MSR_W_PMON_CTR3 = 0xc97;
	constexpr std::uint32_t MSR_M0_PMON_BOX_CTRL = 0xca0;
	constexpr std::uint32_t MSR_M0_PMON_BOX_STATUS = 0xca1;
	constexpr std::uint32_t MSR_M0_PMON_BOX_OVF_CTRL = 0xca2;
	constexpr std::uint32_t MSR_M0_PMON_TIMESTAMP = 0xca4;
	constexpr std::uint32_t MSR_M0_PMON_DSP = 0xca5;
	constexpr std::uint32_t MSR_M0_PMON_ISS = 0xca6;
	constexpr std::uint32_t MSR_M0_PMON_MAP = 0xca7;
	constexpr std::uint32_t MSR_M0_PMON_MSC_THR = 0xca8;
	constexpr std::uint32_t MSR_M0_PMON_PGT = 0xca9;
	constexpr std::uint32_t MSR_M0_PMON_PLD = 0xcaa;
	constexpr std::uint32_t MSR_M0_PMON_ZDP = 0xcab;
	constexpr std::uint32_t MSR_M0_PMON_EVNT_SEL0 = 0xcb0;
	constexpr std::uint32_t MSR_M0_PMON_CTR0 = 0xcb1;
	constexpr std::uint32_t MSR_M0_PMON_EVNT_SEL1 = 0xcb2;
	constexpr std::uint32_t MSR_M0_PMON_CTR1 = 0xcb3;
	constexpr std::uint32_t MSR_M0_PMON_EVNT_SEL2 = 0xcb4;
	constexpr std::uint32_t MSR_M0_PMON_CTR2 = 0xcb5;
	constexpr std::uint32_t MSR_M0_PMON_EVNT_SEL3 = 0xcb6;
	constexpr std::uint32_t MSR_M0_PMON_CTR3 = 0xcb7;
	constexpr std::uint32_t MSR_M0_PMON_EVNT_SEL4 = 0xcb8;
	constexpr std::uint32_t MSR_M0_PMON_CTR4 = 0xcb9;
	constexpr std::uint32_t MSR_M0_PMON_EVNT_SEL5 = 0xcba;
	constexpr std::uint32_t MSR_M0_PMON_CTR5 = 0xcbb;
	constexpr std::uint32_t MSR_S1_PMON_BOX_CTRL = 0xcc0;
	constexpr std::uint32_t MSR_S1_PMON_BOX_STATUS = 0xcc1;
	constexpr std::uint32_t MSR_S1_PMON_BOX_OVF_CTRL = 0xcc2;
	constexpr std::uint32_t MSR_S1_PMON_EVNT_SEL0 = 0xcd0;
	constexpr std::uint32_t MSR_S1_PMON_CTR0 = 0xcd1;
	constexpr std::uint32_t MSR_S1_PMON_EVNT_SEL1 = 0xcd2;
	constexpr std::uint32_t MSR_S1_PMON_CTR1 = 0xcd3;
	constexpr std::uint32_t MSR_S1_PMON_EVNT_SEL2 = 0xcd4;
	constexpr std::uint32_t MSR_S1_PMON_CTR2 = 0xcd5;
	constexpr std::uint32_t MSR_S1_PMON_EVNT_SEL3 = 0xcd6;
	constexpr std::uint32_t MSR_S1_PMON_CTR3 = 0xcd7;
	constexpr std::uint32_t MSR_M1_PMON_BOX_CTRL = 0xce0;
	constexpr std::uint32_t MSR_M1_PMON_BOX_STATUS = 0xce1;
	constexpr std::uint32_t MSR_M1_PMON_BOX_OVF_CTRL = 0xce2;
	constexpr std::uint32_t MSR_M1_PMON_TIMESTAMP = 0xce4;
	constexpr std::uint32_t MSR_M1_PMON_DSP = 0xce5;
	constexpr std::uint32_t MSR_M1_PMON_ISS = 0xce6;
	constexpr std::uint32_t MSR_M1_PMON_MAP = 0xce7;
	constexpr std::uint32_t MSR_M1_PMON_MSC_THR = 0xce8;
	constexpr std::uint32_t MSR_M1_PMON_PGT = 0xce9;
	constexpr std::uint32_t MSR_M1_PMON_PLD = 0xcea;
	constexpr std::uint32_t MSR_M1_PMON_ZDP = 0xceb;
	constexpr std::uint32_t MSR_M1_PMON_EVNT_SEL0 = 0xcf0;
	constexpr std::uint32_t MSR_M1_PMON_CTR0 = 0xcf1;
	constexpr std::uint32_t MSR_M1_PMON_EVNT_SEL1 = 0xcf2;
	constexpr std::uint32_t MSR_M1_PMON_CTR1 = 0xcf3;
	constexpr std::uint32_t MSR_M1_PMON_EVNT_SEL2 = 0xcf4;
	constexpr std::uint32_t MSR_M1_PMON_CTR2 = 0xcf5;
	constexpr std::uint32_t MSR_M1_PMON_EVNT_SEL3 = 0xcf6;
	constexpr std::uint32_t MSR_M1_PMON_CTR3 = 0xcf7;
	constexpr std::uint32_t MSR_M1_PMON_EVNT_SEL4 = 0xcf8;
	constexpr std::uint32_t MSR_M1_PMON_CTR4 = 0xcf9;
	constexpr std::uint32_t MSR_M1_PMON_EVNT_SEL5 = 0xcfa;
	constexpr std::uint32_t MSR_M1_PMON_CTR5 = 0xcfb;
	constexpr std::uint32_t MSR_C0_PMON_BOX_CTRL = 0xd00;
	constexpr std::uint32_t MSR_C0_PMON_BOX_STATUS = 0xd01;
	constexpr std::uint32_t MSR_C0_PMON_BOX_OVF_CTRL = 0xd02;
	constexpr std::uint32_t MSR_C0_PMON_EVNT_SEL0 = 0xd10;
	constexpr std::uint32_t MSR_C0_PMON_CTR0 = 0xd11;
	constexpr std::uint32_t MSR_C0_PMON_EVNT_SEL1 = 0xd12;
	constexpr std::uint32_t MSR_C0_PMON_CTR1 = 0xd13;
	constexpr std::uint32_t MSR_C0_PMON_EVNT_SEL2 = 0xd14;
	constexpr std::uint32_t MSR_C0_PMON_CTR2 = 0xd15;
	constexpr std::uint32_t MSR_C0_PMON_EVNT_SEL3 = 0xd16;
	constexpr std::uint32_t MSR_C0_PMON_CTR3 = 0xd17;
	constexpr std::uint32_t MSR_C0_PMON_EVNT_SEL4 = 0xd18;
	constexpr std::uint32_t MSR_C0_PMON_CTR4 = 0xd19;
	constexpr std::uint32_t MSR_C0_PMON_EVNT_SEL5 = 0xd1a;
	constexpr std::uint32_t MSR_C0_PMON_CTR5 = 0xd1b;
	constexpr std::uint32_t MSR_C4_PMON_BOX_CTRL = 0xd20;
	constexpr std::uint32_t MSR_C4_PMON_BOX_STATUS = 0xd21;
	constexpr std::uint32_t MSR_C4_PMON_BOX_OVF_CTRL = 0xd22;
	constexpr std::uint32_t MSR_C4_PMON_EVNT_SEL0 = 0xd30;
	constexpr std::uint32_t MSR_C4_PMON_CTR0 = 0xd31;
	constexpr std::uint32_t MSR_C4_PMON_EVNT_SEL1 = 0xd32;
	constexpr std::uint32_t MSR_C4_PMON_CTR1 = 0xd33;
	constexpr std::uint32_t MSR_C4_PMON_EVNT_SEL2 = 0xd34;
	constexpr std::uint32_t MSR_C4_PMON_CTR2 = 0xd35;
	constexpr std::uint32_t MSR_C4_PMON_EVNT_SEL3 = 0xd36;
	constexpr std::uint32_t MSR_C4_PMON_CTR3 = 0xd37;
	constexpr std::uint32_t MSR_C4_PMON_EVNT_SEL4 = 0xd38;
	constexpr std::uint32_t MSR_C4_PMON_CTR4 = 0xd39;
	constexpr std::uint32_t MSR_C4_PMON_EVNT_SEL5 = 0xd3a;
	constexpr std::uint32_t MSR_C4_PMON_CTR5 = 0xd3b;
	constexpr std::uint32_t MSR_C2_PMON_BOX_CTRL = 0xd40;
	constexpr std::uint32_t MSR_C2_PMON_BOX_STATUS = 0xd41;
	constexpr std::uint32_t MSR_C2_PMON_BOX_OVF_CTRL = 0xd42;
	constexpr std::uint32_t MSR_C2_PMON_EVNT_SEL0 = 0xd50;
	constexpr std::uint32_t MSR_C2_PMON_CTR0 = 0xd51;
	constexpr std::uint32_t MSR_C2_PMON_EVNT_SEL1 = 0xd52;
	constexpr std::uint32_t MSR_C2_PMON_CTR1 = 0xd53;
	constexpr std::uint32_t MSR_C2_PMON_EVNT_SEL2 = 0xd54;
	constexpr std::uint32_t MSR_C2_PMON_CTR2 = 0xd55;
	constexpr std::uint32_t MSR_C2_PMON_EVNT_SEL3 = 0xd56;
	constexpr std::uint32_t MSR_C2_PMON_CTR3 = 0xd57;
	constexpr std::uint32_t MSR_C2_PMON_EVNT_SEL4 = 0xd58;
	constexpr std::uint32_t MSR_C2_PMON_CTR4 = 0xd59;
	constexpr std::uint32_t MSR_C2_PMON_EVNT_SEL5 = 0xd5a;
	constexpr std::uint32_t MSR_C2_PMON_CTR5 = 0xd5b;
	constexpr std::uint32_t MSR_C6_PMON_BOX_CTRL = 0xd60;
	constexpr std::uint32_t MSR_C6_PMON_BOX_STATUS = 0xd61;
	constexpr std::uint32_t MSR_C6_PMON_BOX_OVF_CTRL = 0xd62;
	constexpr std::uint32_t MSR_C6_PMON_EVNT_SEL0 = 0xd70;
	constexpr std::uint32_t MSR_C6_PMON_CTR0 = 0xd71;
	constexpr std::uint32_t MSR_C6_PMON_EVNT_SEL1 = 0xd72;
	constexpr std::uint32_t MSR_C6_PMON_CTR1 = 0xd73;
	constexpr std::uint32_t MSR_C6_PMON_EVNT_SEL2 = 0xd74;
	constexpr std::uint32_t MSR_C6_PMON_CTR2 = 0xd75;
	constexpr std::uint32_t MSR_C6_PMON_EVNT_SEL3 = 0xd76;
	constexpr std::uint32_t MSR_C6_PMON_CTR3 = 0xd77;
	constexpr std::uint32_t MSR_C6_PMON_EVNT_SEL4 = 0xd78;
	constexpr std::uint32_t MSR_C6_PMON_CTR4 = 0xd79;
	constexpr std::uint32_t MSR_C6_PMON_EVNT_SEL5 = 0xd7a;
	constexpr std::uint32_t MSR_C6_PMON_CTR5 = 0xd7b;
	constexpr std::uint32_t MSR_C1_PMON_BOX_CTRL = 0xd80;
	constexpr std::uint32_t MSR_C1_PMON_BOX_STATUS = 0xd81;
	constexpr std::uint32_t MSR_C1_PMON_BOX_OVF_CTRL = 0xd82;
	constexpr std::uint32_t MSR_C1_PMON_EVNT_SEL0 = 0xd90;
	constexpr std::uint32_t MSR_C1_PMON_CTR0 = 0xd91;
	constexpr std::uint32_t MSR_C1_PMON_EVNT_SEL1 = 0xd92;
	constexpr std::uint32_t MSR_C1_PMON_CTR1 = 0xd93;
	constexpr std::uint32_t MSR_C1_PMON_EVNT_SEL2 = 0xd94;
	constexpr std::uint32_t MSR_C1_PMON_CTR2 = 0xd95;
	constexpr std::uint32_t MSR_C1_PMON_EVNT_SEL3 = 0xd96;
	constexpr std::uint32_t MSR_C1_PMON_CTR3 = 0xd97;
	constexpr std::uint32_t MSR_C1_PMON_EVNT_SEL4 = 0xd98;
	constexpr std::uint32_t MSR_C1_PMON_CTR4 = 0xd99;
	constexpr std::uint32_t MSR_C1_PMON_EVNT_SEL5 = 0xd9a;
	constexpr std::uint32_t MSR_C1_PMON_CTR5 = 0xd9b;
	constexpr std::uint32_t MSR_C5_PMON_BOX_CTRL = 0xda0;
	constexpr std::uint32_t MSR_C5_PMON_BOX_STATUS = 0xda1;
	constexpr std::uint32_t MSR_C5_PMON_BOX_OVF_CTRL = 0xda2;
	constexpr std::uint32_t MSR_C5_PMON_EVNT_SEL0 = 0xdb0;
	constexpr std::uint32_t MSR_C5_PMON_CTR0 = 0xdb1;
	constexpr std::uint32_t MSR_C5_PMON_EVNT_SEL1 = 0xdb2;
	constexpr std::uint32_t MSR_C5_PMON_CTR1 = 0xdb3;
	constexpr std::uint32_t MSR_C5_PMON_EVNT_SEL2 = 0xdb4;
	constexpr std::uint32_t MSR_C5_PMON_CTR2 = 0xdb5;
	constexpr std::uint32_t MSR_C5_PMON_EVNT_SEL3 = 0xdb6;
	constexpr std::uint32_t MSR_C5_PMON_CTR3 = 0xdb7;
	constexpr std::uint32_t MSR_C5_PMON_EVNT_SEL4 = 0xdb8;
	constexpr std::uint32_t MSR_C5_PMON_CTR4 = 0xdb9;
	constexpr std::uint32_t MSR_C5_PMON_EVNT_SEL5 = 0xdba;
	constexpr std::uint32_t MSR_C5_PMON_CTR5 = 0xdbb;
	constexpr std::uint32_t MSR_C3_PMON_BOX_CTRL = 0xdc0;
	constexpr std::uint32_t MSR_C3_PMON_BOX_STATUS = 0xdc1;
	constexpr std::uint32_t MSR_C3_PMON_BOX_OVF_CTRL = 0xdc2;
	constexpr std::uint32_t MSR_C3_PMON_EVNT_SEL0 = 0xdd0;
	constexpr std::uint32_t MSR_C3_PMON_CTR0 = 0xdd1;
	constexpr std::uint32_t MSR_C3_PMON_EVNT_SEL1 = 0xdd2;
	constexpr std::uint32_t MSR_C3_PMON_CTR1 = 0xdd3;
	constexpr std::uint32_t MSR_C3_PMON_EVNT_SEL2 = 0xdd4;
	constexpr std::uint32_t MSR_C3_PMON_CTR2 = 0xdd5;
	constexpr std::uint32_t MSR_C3_PMON_EVNT_SEL3 = 0xdd6;
	constexpr std::uint32_t MSR_C3_PMON_CTR3 = 0xdd7;
	constexpr std::uint32_t MSR_C3_PMON_EVNT_SEL4 = 0xdd8;
	constexpr std::uint32_t MSR_C3_PMON_CTR4 = 0xdd9;
	constexpr std::uint32_t MSR_C3_PMON_EVNT_SEL5 = 0xdda;
	constexpr std::uint32_t MSR_C3_PMON_CTR5 = 0xddb;
	constexpr std::uint32_t MSR_C7_PMON_BOX_CTRL = 0xde0;
	constexpr std::uint32_t MSR_C7_PMON_BOX_STATUS = 0xde1;
	constexpr std::uint32_t MSR_C7_PMON_BOX_OVF_CTRL = 0xde2;
	constexpr std::uint32_t MSR_C7_PMON_EVNT_SEL0 = 0xdf0;
	constexpr std::uint32_t MSR_C7_PMON_CTR0 = 0xdf1;
	constexpr std::uint32_t MSR_C7_PMON_EVNT_SEL1 = 0xdf2;
	constexpr std::uint32_t MSR_C7_PMON_CTR1 = 0xdf3;
	constexpr std::uint32_t MSR_C7_PMON_EVNT_SEL2 = 0xdf4;
	constexpr std::uint32_t MSR_C7_PMON_CTR2 = 0xdf5;
	constexpr std::uint32_t MSR_C7_PMON_EVNT_SEL3 = 0xdf6;
	constexpr std::uint32_t MSR_C7_PMON_CTR3 = 0xdf7;
	constexpr std::uint32_t MSR_C7_PMON_EVNT_SEL4 = 0xdf8;
	constexpr std::uint32_t MSR_C7_PMON_CTR4 = 0xdf9;
	constexpr std::uint32_t MSR_C7_PMON_EVNT_SEL5 = 0xdfa;
	constexpr std::uint32_t MSR_C7_PMON_CTR5 = 0xdfb;
	constexpr std::uint32_t MSR_R0_PMON_BOX_CTRL = 0xe00;
	constexpr std::uint32_t MSR_R0_PMON_BOX_STATUS = 0xe01;
	constexpr std::uint32_t MSR_R0_PMON_BOX_OVF_CTRL = 0xe02;
	constexpr std::uint32_t MSR_R0_PMON_IPERF0_P0 = 0xe04;
	constexpr std::uint32_t MSR_R0_PMON_IPERF0_P1 = 0xe05;
	constexpr std::uint32_t MSR_R0_PMON_IPERF0_P2 = 0xe06;
	constexpr std::uint32_t MSR_R0_PMON_IPERF0_P3 = 0xe07;
	constexpr std::uint32_t MSR_R0_PMON_IPERF0_P4 = 0xe08;
	constexpr std::uint32_t MSR_R0_PMON_IPERF0_P5 = 0xe09;
	constexpr std::uint32_t MSR_R0_PMON_IPERF0_P6 = 0xe0a;
	constexpr std::uint32_t MSR_R0_PMON_IPERF0_P7 = 0xe0b;
	constexpr std::uint32_t MSR_R0_PMON_QLX_P0 = 0xe0c;
	constexpr std::uint32_t MSR_R0_PMON_QLX_P1 = 0xe0d;
	constexpr std::uint32_t MSR_R0_PMON_QLX_P2 = 0xe0e;
	constexpr std::uint32_t MSR_R0_PMON_QLX_P3 = 0xe0f;
	constexpr std::uint32_t MSR_R0_PMON_EVNT_SEL0 = 0xe10;
	constexpr std::uint32_t MSR_R0_PMON_CTR0 = 0xe11;
	constexpr std::uint32_t MSR_R0_PMON_EVNT_SEL1 = 0xe12;
	constexpr std::uint32_t MSR_R0_PMON_CTR1 = 0xe13;
	constexpr std::uint32_t MSR_R0_PMON_EVNT_SEL2 = 0xe14;
	constexpr std::uint32_t MSR_R0_PMON_CTR2 = 0xe15;
	constexpr std::uint32_t MSR_R0_PMON_EVNT_SEL3 = 0xe16;
	constexpr std::uint32_t MSR_R0_PMON_CTR3 = 0xe17;
	constexpr std::uint32_t MSR_R0_PMON_EVNT_SEL4 = 0xe18;
	constexpr std::uint32_t MSR_R0_PMON_CTR4 = 0xe19;
	constexpr std::uint32_t MSR_R0_PMON_EVNT_SEL5 = 0xe1a;
	constexpr std::uint32_t MSR_R0_PMON_CTR5 = 0xe1b;
	constexpr std::uint32_t MSR_R0_PMON_EVNT_SEL6 = 0xe1c;
	constexpr std::uint32_t MSR_R0_PMON_CTR6 = 0xe1d;
	constexpr std::uint32_t MSR_R0_PMON_EVNT_SEL7 = 0xe1e;
	constexpr std::uint32_t MSR_R0_PMON_CTR7 = 0xe1f;
	constexpr std::uint32_t MSR_R1_PMON_BOX_CTRL = 0xe20;
	constexpr std::uint32_t MSR_R1_PMON_BOX_STATUS = 0xe21;
	constexpr std::uint32_t MSR_R1_PMON_BOX_OVF_CTRL = 0xe22;
	constexpr std::uint32_t MSR_R1_PMON_IPERF1_P8 = 0xe24;
	constexpr std::uint32_t MSR_R1_PMON_IPERF1_P9 = 0xe25;
	constexpr std::uint32_t MSR_R1_PMON_IPERF1_P10 = 0xe26;
	constexpr std::uint32_t MSR_R1_PMON_IPERF1_P11 = 0xe27;
	constexpr std::uint32_t MSR_R1_PMON_IPERF1_P12 = 0xe28;
	constexpr std::uint32_t MSR_R1_PMON_IPERF1_P13 = 0xe29;
	constexpr std::uint32_t MSR_R1_PMON_IPERF1_P14 = 0xe2a;
	constexpr std::uint32_t MSR_R1_PMON_IPERF1_P15 = 0xe2b;
	constexpr std::uint32_t MSR_R1_PMON_QLX_P4 = 0xe2c;
	constexpr std::uint32_t MSR_R1_PMON_QLX_P5 = 0xe2d;
	constexpr std::uint32_t MSR_R1_PMON_QLX_P6 = 0xe2e;
	constexpr std::uint32_t MSR_R1_PMON_QLX_P7 = 0xe2f;
	constexpr std::uint32_t MSR_R1_PMON_EVNT_SEL8 = 0xe30;
	constexpr std::uint32_t MSR_R1_PMON_CTR8 = 0xe31;
	constexpr std::uint32_t MSR_R1_PMON_EVNT_SEL9 = 0xe32;
	constexpr std::uint32_t MSR_R1_PMON_CTR9 = 0xe33;
	constexpr std::uint32_t MSR_R1_PMON_EVNT_SEL10 = 0xe34;
	constexpr std::uint32_t MSR_R1_PMON_CTR10 = 0xe35;
	constexpr std::uint32_t MSR_R1_PMON_EVNT_SEL11 = 0xe36;
	constexpr std::uint32_t MSR_R1_PMON_CTR11 = 0xe37;
	constexpr std::uint32_t MSR_R1_PMON_EVNT_SEL12 = 0xe38;
	constexpr std::uint32_t MSR_R1_PMON_CTR12 = 0xe39;
	constexpr std::uint32_t MSR_R1_PMON_EVNT_SEL13 = 0xe3a;
	constexpr std::uint32_t MSR_R1_PMON_CTR13 = 0xe3b;
	constexpr std::uint32_t MSR_R1_PMON_EVNT_SEL14 = 0xe3c;
	constexpr std::uint32_t MSR_R1_PMON_CTR14 = 0xe3d;
	constexpr std::uint32_t MSR_R1_PMON_EVNT_SEL15 = 0xe3e;
	constexpr std::uint32_t MSR_R1_PMON_CTR15 = 0xe3f;
	constexpr std::uint32_t MSR_B0_PMON_MATCH = 0xe45;
	constexpr std::uint32_t MSR_B0_PMON_MASK = 0xe46;
	constexpr std::uint32_t MSR_S0_PMON_MATCH = 0xe49;
	constexpr std::uint32_t MSR_S0_PMON_MASK = 0xe4a;
	constexpr std::uint32_t MSR_B1_PMON_MATCH = 0xe4d;
	constexpr std::uint32_t MSR_B1_PMON_MASK = 0xe4e;
	constexpr std::uint32_t MSR_M0_PMON_MM_CONFIG = 0xe54;
	constexpr std::uint32_t MSR_M0_PMON_ADDR_MATCH = 0xe55;
	constexpr std::uint32_t MSR_M0_PMON_ADDR_MASK = 0xe56;
	constexpr std::uint32_t MSR_S1_PMON_MATCH = 0xe59;
	constexpr std::uint32_t MSR_S1_PMON_MASK = 0xe5a;
	constexpr std::uint32_t MSR_M1_PMON_MM_CONFIG = 0xe5c;
	constexpr std::uint32_t MSR_M1_PMON_ADDR_MATCH = 0xe5d;
	constexpr std::uint32_t MSR_M1_PMON_ADDR_MASK = 0xe5e;
	constexpr std::uint32_t MSR_C8_PMON_BOX_CTRL = 0xf40;
	constexpr std::uint32_t MSR_C8_PMON_BOX_STATUS = 0xf41;
	constexpr std::uint32_t MSR_C8_PMON_BOX_OVF_CTRL = 0xf42;
	constexpr std::uint32_t MSR_C8_PMON_EVNT_SEL0 = 0xf50;
	constexpr std::uint32_t MSR_C8_PMON_CTR0 = 0xf51;
	constexpr std::uint32_t MSR_C8_PMON_EVNT_SEL1 = 0xf52;
	constexpr std::uint32_t MSR_C8_PMON_CTR1 = 0xf53;
	constexpr std::uint32_t MSR_C8_PMON_EVNT_SEL2 = 0xf54;
	constexpr std::uint32_t MSR_C8_PMON_CTR2 = 0xf55;
	constexpr std::uint32_t MSR_C8_PMON_EVNT_SEL3 = 0xf56;
	constexpr std::uint32_t MSR_C8_PMON_CTR3 = 0xf57;
	constexpr std::uint32_t MSR_C8_PMON_EVNT_SEL4 = 0xf58;
	constexpr std::uint32_t MSR_C8_PMON_CTR4 = 0xf59;
	constexpr std::uint32_t MSR_C8_PMON_EVNT_SEL5 = 0xf5a;
	constexpr std::uint32_t MSR_C8_PMON_CTR5 = 0xf5b;
	constexpr std::uint32_t MSR_C9_PMON_BOX_CTRL = 0xfc0;
	constexpr std::uint32_t MSR_C9_PMON_BOX_STATUS = 0xfc1;
	constexpr std::uint32_t MSR_C9_PMON_BOX_OVF_CTRL = 0xfc2;
	constexpr std::uint32_t MSR_C9_PMON_EVNT_SEL0 = 0xfd0;
	constexpr std::uint32_t MSR_C9_PMON_CTR0 = 0xfd1;
	constexpr std::uint32_t MSR_C9_PMON_EVNT_SEL1 = 0xfd2;
	constexpr std::uint32_t MSR_C9_PMON_CTR1 = 0xfd3;
	constexpr std::uint32_t MSR_C9_PMON_EVNT_SEL2 = 0xfd4;
	constexpr std::uint32_t MSR_C9_PMON_CTR2 = 0xfd5;
	constexpr std::uint32_t MSR_C9_PMON_EVNT_SEL3 = 0xfd6;
	constexpr std::uint32_t MSR_C9_PMON_CTR3 = 0xfd7;
	constexpr std::uint32_t MSR_C9_PMON_EVNT_SEL4 = 0xfd8;
	constexpr std::uint32_t MSR_C9_PMON_CTR4 = 0xfd9;
	constexpr std::uint32_t MSR_C9_PMON_EVNT_SEL5 = 0xfda;
	constexpr std::uint32_t MSR_C9_PMON_CTR5 = 0xfdb;
	constexpr std::uint32_t MSR_EMON_L3_CTR_CTL0 = 0x107cc;
	constexpr std::uint32_t MSR_IFSB_BUSQ0 = 0x107cc;
	constexpr std::uint32_t MSR_EMON_L3_CTR_CTL1 = 0x107cd;
	constexpr std::uint32_t MSR_IFSB_BUSQ1 = 0x107cd;
	constexpr std::uint32_t MSR_EMON_L3_CTR_CTL2 = 0x107ce;
	constexpr std::uint32_t MSR_IFSB_SNPQ0 = 0x107ce;
	constexpr std::uint32_t MSR_EMON_L3_CTR_CTL3 = 0x107cf;
	constexpr std::uint32_t MSR_IFSB_SNPQ1 = 0x107cf;
	constexpr std::uint32_t MSR_EFSB_DRDY0 = 0x107d0;
	constexpr std::uint32_t MSR_EMON_L3_CTR_CTL4 = 0x107d0;
	constexpr std::uint32_t MSR_EFSB_DRDY1 = 0x107d1;
	constexpr std::uint32_t MSR_EMON_L3_CTR_CTL5 = 0x107d1;
	constexpr std::uint32_t MSR_EMON_L3_CTR_CTL6 = 0x107d2;
	constexpr std::uint32_t MSR_IFSB_CTL6 = 0x107d2;
	constexpr std::uint32_t MSR_EMON_L3_CTR_CTL7 = 0x107d3;
	constexpr std::uint32_t MSR_IFSB_CNTR7 = 0x107d3;
	constexpr std::uint32_t MSR_EMON_L3_GL_CTL = 0x107d8;
	constexpr std::uint32_t IA32_EFER = 0xc0000080;
	constexpr std::uint32_t IA32_STAR = 0xc0000081;
	constexpr std::uint32_t IA32_LSTAR = 0xc0000082;
	constexpr std::uint32_t IA32_CSTAR = 0xc0000083;
	constexpr std::uint32_t IA32_FMASK = 0xc0000084;
	constexpr std::uint32_t IA32_FS_BASE = 0xc0000100;
	constexpr std::uint32_t IA32_GS_BASE = 0xc0000101;
	constexpr std::uint32_t IA32_KERNEL_GSBASE = 0xc0000102;
	constexpr std::uint32_t IA32_TSC_AUX = 0xc0000103;
}