#pragma once

#include <array>

#include "../pch.h"
#include "utils.hpp"
#include "tui.hpp"

#include <bochscpu.hpp>

extern EXT_API_VERSION g_ExtApiVersion;

extern WINDBG_EXTENSION_APIS ExtensionApis;

//
// Determin whether the user is currently in shadow state where emulator operation is accessable.
//
extern bool InShadowState;

extern TerminalUI g_Tui;

union MMPTE_HARDWARE {
    struct {
        uint64_t Present : 1;
        uint64_t Write : 1;
        uint64_t UserAccessible : 1;
        uint64_t WriteThrough : 1;
        uint64_t CacheDisable : 1;
        uint64_t Accessed : 1;
        uint64_t Dirty : 1;
        uint64_t LargePage : 1;
        uint64_t Available : 4;
        uint64_t PageFrameNumber : 36;
        uint64_t ReservedForHardware : 4;
        uint64_t ReservedForSoftware : 11;
        uint64_t NoExecute : 1;
    } u;
    uint64_t AsUINT64;
    constexpr MMPTE_HARDWARE(const uint64_t Value) : AsUINT64(Value) {}
};

//
// Structure to parse a virtual address.
//

union VIRTUAL_ADDRESS {
    struct {
        uint64_t Offset : 12;
        uint64_t PtIndex : 9;
        uint64_t PdIndex : 9;
        uint64_t PdPtIndex : 9;
        uint64_t Pml4Index : 9;
        uint64_t Reserved : 16;
    } u;
    uint64_t AsUINT64;
    constexpr VIRTUAL_ADDRESS(const uint64_t Value) : AsUINT64(Value) {}
};


struct Zmm_t {
    uint64_t Q[8];

    Zmm_t() { memset(this, 0, sizeof(decltype(*this))); }

    Zmm_t(const DEBUG_VALUE& Val) { memcpy(this, &Val.F128Bytes, 16); }

    bool operator==(const Zmm_t& B) const {
        bool Equal = true;
        for (size_t Idx = 0; Idx < 8; Idx++) {
            Equal = Equal && Q[Idx] == B.Q[Idx];
        }
        return Equal;
    }
};

template <typename T>
bool ExtractBit(const T& data, unsigned int bit_pos) {
    if constexpr (std::is_integral_v<T>) {
        if (bit_pos >= sizeof(T) * 8)
            throw std::out_of_range("bit_pos out of range");
        return (static_cast<std::make_unsigned_t<T>>(data) >> bit_pos) & 1u;
    }
    else {
        static_assert(std::is_same_v<typename T::value_type, uint8_t>, "Container must hold uint8_t");

        if (bit_pos >= data.size() * 8)
            throw std::out_of_range("bit_pos out of range");

        size_t byte_index = bit_pos / 8;
        size_t bit_index = bit_pos % 8;

        return (data[byte_index] >> bit_index) & 1u;
    }
}

template <typename Container>
uint64_t ExtractBits(const Container& data, unsigned int from, unsigned int to) {
    if (from > to) throw std::out_of_range("Invalid bit range");
    if (to >= data.size() * 8) throw std::out_of_range("Bit range exceeds data size");

    unsigned int start_byte = from / 8;
    unsigned int end_byte = to / 8;
    unsigned int num_bytes = end_byte - start_byte + 1;

    if (num_bytes > 8)
        throw std::out_of_range("Bit range too large to fit in uint64_t");

    uint64_t val = 0;
    std::memcpy(&val, &data[start_byte], num_bytes);

    unsigned int bit_offset = from % 8;
    unsigned int width = to - from + 1;

    val >>= bit_offset;
    uint64_t mask = (uint64_t(1) << width) - 1;
    return val & mask;
}

struct Seg_t {
    uint16_t Selector;
    uint64_t Base;
    uint32_t Limit;
    union {
        struct {
            uint16_t SegmentType : 4;
            uint16_t NonSystemSegment : 1;
            uint16_t DescriptorPrivilegeLevel : 2;
            uint16_t Present : 1;
            uint16_t Reserved : 4;
            uint16_t Available : 1;
            uint16_t Long : 1;
            uint16_t Default : 1;
            uint16_t Granularity : 1;
        };

        uint16_t Attr;
    };

    Seg_t() { memset(this, 0, sizeof(decltype(*this))); }

    static Seg_t FromDescriptor(std::uint64_t Selector, const std::array<std::uint8_t, 16>& Value);

    bool operator==(const Seg_t& B) const {
        bool Equal = Attr == B.Attr;
        Equal = Equal && Base == B.Base;
        Equal = Equal && Limit == B.Limit;
        Equal = Equal && Present == B.Present;
        Equal = Equal && Selector == B.Selector;
        return Equal;
    }
};

struct GlobalSeg_t {
    uint64_t Base;
    uint16_t Limit;

    GlobalSeg_t() { memset(this, 0, sizeof(decltype(*this))); }

    GlobalSeg_t(std::uint64_t B, std::uint16_t Lim)
        : Base(B), Limit(Lim) { }

    bool operator==(const GlobalSeg_t& B) const {
        bool Equal = Base == B.Base;
        Equal = Equal && Limit == B.Limit;
        return Equal;
    }
};

union Cr0_t {
    Cr0_t() { Flags = 0; }

    Cr0_t(const uint64_t Value) { Flags = Value; }

    bool operator==(const Cr0_t& B) const { return Flags == B.Flags; }

    void Print() const {
        std::print("CR0: {:#x}\n", Flags);
        std::print("CR0.ProtectionEnable: {}\n", ProtectionEnable);
        std::print("CR0.MonitorCoprocessor: {}\n", MonitorCoprocessor);
        std::print("CR0.EmulateFpu: {}\n", EmulateFpu);
        std::print("CR0.TaskSwitched: {}\n", TaskSwitched);
        std::print("CR0.ExtensionType: {}\n", ExtensionType);
        std::print("CR0.NumericError: {}\n", NumericError);
        std::print("CR0.WriteProtect: {}\n", WriteProtect);
        std::print("CR0.AlignmentMask: {}\n", AlignmentMask);
        std::print("CR0.NotWriteThrough: {}\n", NotWriteThrough);
        std::print("CR0.CacheDisable: {}\n", CacheDisable);
        std::print("CR0.PagingEnable: {}\n", PagingEnable);
    }

    struct {
        uint64_t ProtectionEnable : 1;
#define CR0_PROTECTION_ENABLE_BIT 0
#define CR0_PROTECTION_ENABLE_FLAG 0x01
#define CR0_PROTECTION_ENABLE(_) (((_) >> 0) & 0x01)

       
        uint64_t MonitorCoprocessor : 1;
#define CR0_MONITOR_COPROCESSOR_BIT 1
#define CR0_MONITOR_COPROCESSOR_FLAG 0x02
#define CR0_MONITOR_COPROCESSOR(_) (((_) >> 1) & 0x01)

      
        uint64_t EmulateFpu : 1;
#define CR0_EMULATE_FPU_BIT 2
#define CR0_EMULATE_FPU_FLAG 0x04
#define CR0_EMULATE_FPU(_) (((_) >> 2) & 0x01)

        
        uint64_t TaskSwitched : 1;
#define CR0_TASK_SWITCHED_BIT 3
#define CR0_TASK_SWITCHED_FLAG 0x08
#define CR0_TASK_SWITCHED(_) (((_) >> 3) & 0x01)

       
        uint64_t ExtensionType : 1;
#define CR0_EXTENSION_TYPE_BIT 4
#define CR0_EXTENSION_TYPE_FLAG 0x10
#define CR0_EXTENSION_TYPE(_) (((_) >> 4) & 0x01)

       
        uint64_t NumericError : 1;
#define CR0_NUMERIC_ERROR_BIT 5
#define CR0_NUMERIC_ERROR_FLAG 0x20
#define CR0_NUMERIC_ERROR(_) (((_) >> 5) & 0x01)
        uint64_t Reserved1 : 10;

       
        uint64_t WriteProtect : 1;
#define CR0_WRITE_PROTECT_BIT 16
#define CR0_WRITE_PROTECT_FLAG 0x10000
#define CR0_WRITE_PROTECT(_) (((_) >> 16) & 0x01)
        uint64_t Reserved2 : 1;

        
        uint64_t AlignmentMask : 1;
#define CR0_ALIGNMENT_MASK_BIT 18
#define CR0_ALIGNMENT_MASK_FLAG 0x40000
#define CR0_ALIGNMENT_MASK(_) (((_) >> 18) & 0x01)
        uint64_t Reserved3 : 10;

       
        uint64_t NotWriteThrough : 1;
#define CR0_NOT_WRITE_THROUGH_BIT 29
#define CR0_NOT_WRITE_THROUGH_FLAG 0x20000000
#define CR0_NOT_WRITE_THROUGH(_) (((_) >> 29) & 0x01)

        
        uint64_t CacheDisable : 1;
#define CR0_CACHE_DISABLE_BIT 30
#define CR0_CACHE_DISABLE_FLAG 0x40000000
#define CR0_CACHE_DISABLE(_) (((_) >> 30) & 0x01)

       
        uint64_t PagingEnable : 1;
#define CR0_PAGING_ENABLE_BIT 31
#define CR0_PAGING_ENABLE_FLAG 0x80000000
#define CR0_PAGING_ENABLE(_) (((_) >> 31) & 0x01)
        uint64_t Reserved4 : 32;
    };

    uint64_t Flags;
};

union Cr4_t {
    Cr4_t() { Flags = 0; }

    Cr4_t(const uint64_t Value) { Flags = Value; }

    bool operator==(const Cr4_t& B) const { return Flags == B.Flags; }

    void Print() const {
        std::print("CR4: {:#x}\n", Flags);
        std::print("CR4.VirtualModeExtensions: {}\n", VirtualModeExtensions);
        std::print("CR4.ProtectedModeVirtualInterrupts: {}\n",
            ProtectedModeVirtualInterrupts);
        std::print("CR4.TimestampDisable: {}\n", TimestampDisable);
        std::print("CR4.DebuggingExtensions: {}\n", DebuggingExtensions);
        std::print("CR4.PageSizeExtensions: {}\n", PageSizeExtensions);
        std::print("CR4.PhysicalAddressExtension: {}\n", PhysicalAddressExtension);
        std::print("CR4.MachineCheckEnable: {}\n", MachineCheckEnable);
        std::print("CR4.PageGlobalEnable: {}\n", PageGlobalEnable);
        std::print("CR4.PerformanceMonitoringCounterEnable: {}\n",
            PerformanceMonitoringCounterEnable);
        std::print("CR4.OsFxsaveFxrstorSupport: {}\n", OsFxsaveFxrstorSupport);
        std::print("CR4.OsXmmExceptionSupport: {}\n", OsXmmExceptionSupport);
        std::print("CR4.UsermodeInstructionPrevention: {}\n",
            UsermodeInstructionPrevention);
        std::print("CR4.LA57: {}\n", LA57);
        std::print("CR4.VmxEnable: {}\n", VmxEnable);
        std::print("CR4.SmxEnable: {}\n", SmxEnable);
        std::print("CR4.FsgsbaseEnable: {}\n", FsgsbaseEnable);
        std::print("CR4.PcidEnable: {}\n", PcidEnable);
        std::print("CR4.OsXsave: {}\n", OsXsave);
        std::print("CR4.SmepEnable: {}\n", SmepEnable);
        std::print("CR4.SmapEnable: {}\n", SmapEnable);
        std::print("CR4.ProtectionKeyEnable: {}\n", ProtectionKeyEnable);
    }

    struct {
       
        uint64_t VirtualModeExtensions : 1;
#define CR4_VIRTUAL_MODE_EXTENSIONS_BIT 0
#define CR4_VIRTUAL_MODE_EXTENSIONS_FLAG 0x01
#define CR4_VIRTUAL_MODE_EXTENSIONS(_) (((_) >> 0) & 0x01)

        
        uint64_t ProtectedModeVirtualInterrupts : 1;
#define CR4_PROTECTED_MODE_VIRTUAL_INTERRUPTS_BIT 1
#define CR4_PROTECTED_MODE_VIRTUAL_INTERRUPTS_FLAG 0x02
#define CR4_PROTECTED_MODE_VIRTUAL_INTERRUPTS(_) (((_) >> 1) & 0x01)

       
        uint64_t TimestampDisable : 1;
#define CR4_TIMESTAMP_DISABLE_BIT 2
#define CR4_TIMESTAMP_DISABLE_FLAG 0x04
#define CR4_TIMESTAMP_DISABLE(_) (((_) >> 2) & 0x01)

        
        uint64_t DebuggingExtensions : 1;
#define CR4_DEBUGGING_EXTENSIONS_BIT 3
#define CR4_DEBUGGING_EXTENSIONS_FLAG 0x08
#define CR4_DEBUGGING_EXTENSIONS(_) (((_) >> 3) & 0x01)

        uint64_t PageSizeExtensions : 1;
#define CR4_PAGE_SIZE_EXTENSIONS_BIT 4
#define CR4_PAGE_SIZE_EXTENSIONS_FLAG 0x10
#define CR4_PAGE_SIZE_EXTENSIONS(_) (((_) >> 4) & 0x01)

       
        uint64_t PhysicalAddressExtension : 1;
#define CR4_PHYSICAL_ADDRESS_EXTENSION_BIT 5
#define CR4_PHYSICAL_ADDRESS_EXTENSION_FLAG 0x20
#define CR4_PHYSICAL_ADDRESS_EXTENSION(_) (((_) >> 5) & 0x01)

       
        uint64_t MachineCheckEnable : 1;
#define CR4_MACHINE_CHECK_ENABLE_BIT 6
#define CR4_MACHINE_CHECK_ENABLE_FLAG 0x40
#define CR4_MACHINE_CHECK_ENABLE(_) (((_) >> 6) & 0x01)

       
        uint64_t PageGlobalEnable : 1;
#define CR4_PAGE_GLOBAL_ENABLE_BIT 7
#define CR4_PAGE_GLOBAL_ENABLE_FLAG 0x80
#define CR4_PAGE_GLOBAL_ENABLE(_) (((_) >> 7) & 0x01)

        
        uint64_t PerformanceMonitoringCounterEnable : 1;
#define CR4_PERFORMANCE_MONITORING_COUNTER_ENABLE_BIT 8
#define CR4_PERFORMANCE_MONITORING_COUNTER_ENABLE_FLAG 0x100
#define CR4_PERFORMANCE_MONITORING_COUNTER_ENABLE(_) (((_) >> 8) & 0x01)

       
        uint64_t OsFxsaveFxrstorSupport : 1;
#define CR4_OS_FXSAVE_FXRSTOR_SUPPORT_BIT 9
#define CR4_OS_FXSAVE_FXRSTOR_SUPPORT_FLAG 0x200
#define CR4_OS_FXSAVE_FXRSTOR_SUPPORT(_) (((_) >> 9) & 0x01)

        
        uint64_t OsXmmExceptionSupport : 1;
#define CR4_OS_XMM_EXCEPTION_SUPPORT_BIT 10
#define CR4_OS_XMM_EXCEPTION_SUPPORT_FLAG 0x400
#define CR4_OS_XMM_EXCEPTION_SUPPORT(_) (((_) >> 10) & 0x01)

        
        uint64_t UsermodeInstructionPrevention : 1;
#define CR4_USERMODE_INSTRUCTION_PREVENTION_BIT 11
#define CR4_USERMODE_INSTRUCTION_PREVENTION_FLAG 0x800
#define CR4_USERMODE_INSTRUCTION_PREVENTION(_) (((_) >> 11) & 0x01)

        uint64_t LA57 : 1;
#define CR4_LA57_BIT 12
#define CR4_LA57_FLAG 0x1000
#define CR4_LA57(_) (((_) >> 12) & 0x01)

        
        uint64_t VmxEnable : 1;
#define CR4_VMX_ENABLE_BIT 13
#define CR4_VMX_ENABLE_FLAG 0x2000
#define CR4_VMX_ENABLE(_) (((_) >> 13) & 0x01)

        
        uint64_t SmxEnable : 1;
#define CR4_SMX_ENABLE_BIT 14
#define CR4_SMX_ENABLE_FLAG 0x4000
#define CR4_SMX_ENABLE(_) (((_) >> 14) & 0x01)
        uint64_t Reserved2 : 1;

        
        uint64_t FsgsbaseEnable : 1;
#define CR4_FSGSBASE_ENABLE_BIT 16
#define CR4_FSGSBASE_ENABLE_FLAG 0x10000
#define CR4_FSGSBASE_ENABLE(_) (((_) >> 16) & 0x01)

      
        uint64_t PcidEnable : 1;
#define CR4_PCID_ENABLE_BIT 17
#define CR4_PCID_ENABLE_FLAG 0x20000
#define CR4_PCID_ENABLE(_) (((_) >> 17) & 0x01)

       
        uint64_t OsXsave : 1;
#define CR4_OS_XSAVE_BIT 18
#define CR4_OS_XSAVE_FLAG 0x40000
#define CR4_OS_XSAVE(_) (((_) >> 18) & 0x01)
        uint64_t Reserved3 : 1;

        
        uint64_t SmepEnable : 1;
#define CR4_SMEP_ENABLE_BIT 20
#define CR4_SMEP_ENABLE_FLAG 0x100000
#define CR4_SMEP_ENABLE(_) (((_) >> 20) & 0x01)

       
        uint64_t SmapEnable : 1;
#define CR4_SMAP_ENABLE_BIT 21
#define CR4_SMAP_ENABLE_FLAG 0x200000
#define CR4_SMAP_ENABLE(_) (((_) >> 21) & 0x01)

       
        uint64_t ProtectionKeyEnable : 1;
#define CR4_PROTECTION_KEY_ENABLE_BIT 22
#define CR4_PROTECTION_KEY_ENABLE_FLAG 0x400000
#define CR4_PROTECTION_KEY_ENABLE(_) (((_) >> 22) & 0x01)
        uint64_t Reserved4 : 41;
    };

    uint64_t Flags;
};

union Efer_t {
    Efer_t() { Flags = 0; }

    Efer_t(const uint64_t Value) { Flags = Value; }

    bool operator==(const Efer_t& B) const { return Flags == B.Flags; }

    void Print() const {
        std::print("EFER: {:#x}\n", Flags);
        std::print("EFER.SyscallEnable: {}\n", SyscallEnable);
        std::print("EFER.Ia32EModeEnable: {}\n", Ia32EModeEnable);
        std::print("EFER.Ia32EModeActive: {}\n", Ia32EModeActive);
        std::print("EFER.ExecuteDisableBitEnable: {}\n", ExecuteDisableBitEnable);
    }

    struct {
       
        uint64_t SyscallEnable : 1;
#define IA32_EFER_SYSCALL_ENABLE_BIT 0
#define IA32_EFER_SYSCALL_ENABLE_FLAG 0x01
#define IA32_EFER_SYSCALL_ENABLE(_) (((_) >> 0) & 0x01)
        uint64_t Reserved1 : 7;

        uint64_t Ia32EModeEnable : 1;
#define IA32_EFER_IA32E_MODE_ENABLE_BIT 8
#define IA32_EFER_IA32E_MODE_ENABLE_FLAG 0x100
#define IA32_EFER_IA32E_MODE_ENABLE(_) (((_) >> 8) & 0x01)
        uint64_t Reserved2 : 1;

        
        uint64_t Ia32EModeActive : 1;
#define IA32_EFER_IA32E_MODE_ACTIVE_BIT 10
#define IA32_EFER_IA32E_MODE_ACTIVE_FLAG 0x400
#define IA32_EFER_IA32E_MODE_ACTIVE(_) (((_) >> 10) & 0x01)

        
        uint64_t ExecuteDisableBitEnable : 1;
#define IA32_EFER_EXECUTE_DISABLE_BIT_ENABLE_BIT 11
#define IA32_EFER_EXECUTE_DISABLE_BIT_ENABLE_FLAG 0x800
#define IA32_EFER_EXECUTE_DISABLE_BIT_ENABLE(_) (((_) >> 11) & 0x01)
        uint64_t Reserved3 : 52;
    };

    uint64_t Flags;
};

struct Fptw_t {
    uint16_t Value = 0;

    Fptw_t() = default;
    Fptw_t(const uint16_t Value) : Value(Value) {}

    static Fptw_t FromAbridged(const uint8_t Abridged) {
        uint16_t Fptw = 0;
        for (size_t BitIdx = 0; BitIdx < 8; BitIdx++) {
            const uint16_t Bits = (Abridged >> BitIdx) & 0b1;
            if (Bits == 1) {
                Fptw |= 0b00 << (BitIdx * 2);
            }
            else {
                Fptw |= 0b11 << (BitIdx * 2);
            }
        }

        return Fptw_t(Fptw);
    }

    uint8_t Abridged() const {
        uint8_t Abridged = 0;
        for (size_t Idx = 0; Idx < 8; Idx++) {
            const uint16_t Bits = (Value >> (Idx * 2)) & 0b11;
            if (Bits == 0b11) {
                Abridged |= 0b0 << Idx;
            }
            else {
                Abridged |= 0b1 << Idx;
            }
        }
        return Abridged;
    }

    bool operator==(const Fptw_t& Other) const { return Value == Other.Value; }
};



// 2816
// 2752
struct CpuState_t {
    uint64_t Rax;
    uint64_t Rcx;
    uint64_t Rdx;
    uint64_t Rbx;
    uint64_t Rsp;
    uint64_t Rbp;
    uint64_t Rsi;
    uint64_t Rdi;
    uint64_t R8;
    uint64_t R9;
    uint64_t R10;
    uint64_t R11;
    uint64_t R12;
    uint64_t R13;
    uint64_t R14;
    uint64_t R15;
    uint64_t Rip;
    uint64_t Rflags;
    Seg_t Es;
    Seg_t Cs;
    Seg_t Ss;
    Seg_t Ds;
    Seg_t Fs;
    Seg_t Gs;
    Seg_t Ldtr;
    Seg_t Tr;
    GlobalSeg_t Gdtr;
    GlobalSeg_t Idtr;
    Cr0_t Cr0;
    uint64_t Cr2;
    uint64_t Cr3;
    Cr4_t Cr4;
    uint64_t Cr8;
    uint64_t Dr0;
    uint64_t Dr1;
    uint64_t Dr2;
    uint64_t Dr3;
    uint32_t Dr6;
    uint32_t Dr7;
    uint32_t Xcr0;
    Zmm_t Zmm[32];
    uint16_t Fpcw;
    uint16_t Fpsw;
    Fptw_t Fptw;
    // uint16_t Fpop;
    Float80 Fpst[8];
    uint32_t Mxcsr;
    // uint32_t MxcsrMask;
    uint64_t Tsc;
    Efer_t Efer;
    uint64_t KernelGsBase;
    uint64_t ApicBase;
    uint64_t Pat;
    uint64_t SysenterCs;
    uint64_t SysenterEip;
    uint64_t SysenterEsp;
    uint64_t Star;
    uint64_t Lstar;
    uint64_t Cstar;
    uint64_t Sfmask;
    uint64_t TscAux;
    // uint64_t CetControlU;
    // uint64_t CetControlS;
    // uint64_t Pl0Ssp;
    // uint64_t Pl1Ssp;
    // uint64_t Pl2Ssp;
    // uint64_t Pl3Ssp;
    // uint64_t InterruptSspTable;
    // uint64_t Ssp;

    CpuState_t() { memset(this, 0, sizeof(decltype(*this))); }
};

//
// _REGVAL structure reversed from dbgeng.dll
//


enum RegValType {
    REGVAL_TYPE_I32 = 0,
    REGVAL_TYPE_I16 = 2, 
    REGVAL_TYPE_I64 = 6,
    REGVAL_TYPE_FLOAT80 = 0xa,
    REGVAL_TYPE_VF128 = 0xe,
    REGVAL_TYPE_VF256,
    REGVAL_TYPE_VF512,
};

union Float128 {
    float f[4];
    std::uint8_t Bytes[16];

    Float128(const Zmm& Z) { memcpy(this, &Z, sizeof(decltype(*this))); }
};

union Float256 {
    float f[8];
    std::uint8_t Bytes[32];

    Float256(const Zmm& Z) { memcpy(this, &Z, sizeof(decltype(*this))); }
};

union Float512 {
    float f[16];
    std::uint8_t Bytes[64];
};

struct REGVAL {
    RegValType  Type;
    union {
        uint16_t I16;
        float    F32;
        uint32_t I32;
        uint64_t I64;
        double   F64;
        Float80  F80;
        Float128 VF128;
        Float256 VF256;
        Float512 VF512;
    } u;

    std::string ToString() const;
};

static std::unordered_map<std::uint32_t, std::string> BugCheckCodeNames = {
    {0x00000001,	"APC_INDEX_MISMATCH"},
{0x00000002,	"DEVICE_QUEUE_NOT_BUSY"},
{0x00000003,	"INVALID_AFFINITY_SET"},
{0x00000004,	"INVALID_DATA_ACCESS_TRAP"},
{0x00000005,	"INVALID_PROCESS_ATTACH_ATTEMPT"},
{0x00000006,	"INVALID_PROCESS_DETACH_ATTEMPT"},
{0x00000007,	"INVALID_SOFTWARE_INTERRUPT"},
{0x00000008,	"IRQL_NOT_DISPATCH_LEVEL"},
{0x00000009,	"IRQL_NOT_GREATER_OR_EQUAL"},
{0x0000000A,	"IRQL_NOT_LESS_OR_EQUAL"},
{0x0000000B,	"NO_EXCEPTION_HANDLING_SUPPORT"},
{0x0000000C,	"MAXIMUM_WAIT_OBJECTS_EXCEEDED"},
{0x0000000D,	"MUTEX_LEVEL_NUMBER_VIOLATION"},
{0x0000000E,	"NO_USER_MODE_CONTEXT"},
{0x0000000F,	"SPIN_LOCK_ALREADY_OWNED"},
{0x00000010,	"SPIN_LOCK_NOT_OWNED"},
{0x00000011,	"THREAD_NOT_MUTEX_OWNER"},
{0x00000012,	"TRAP_CAUSE_UNKNOWN"},
{0x00000013,	"EMPTY_THREAD_REAPER_LIST"},
{0x00000014,	"CREATE_DELETE_LOCK_NOT_LOCKED"},
{0x00000015,	"LAST_CHANCE_CALLED_FROM_KMODE"},
{0x00000016,	"CID_HANDLE_CREATION"},
{0x00000017,	"CID_HANDLE_DELETION"},
{0x00000018,	"REFERENCE_BY_POINTER"},
{0x00000019,	"BAD_POOL_HEADER"},
{0x0000001A,	"MEMORY_MANAGEMENT"},
{0x0000001B,	"PFN_SHARE_COUNT"},
{0x0000001C,	"PFN_REFERENCE_COUNT"},
{0x0000001D,	"NO_SPIN_LOCK_AVAILABLE"},
{0x0000001E,	"KMODE_EXCEPTION_NOT_HANDLED"},
{0x0000001F,	"SHARED_RESOURCE_CONV_ERROR"},
{0x00000020,	"KERNEL_APC_PENDING_DURING_EXIT"},
{0x00000021,	"QUOTA_UNDERFLOW"},
{0x00000022,	"FILE_SYSTEM"},
{0x00000023,	"FAT_FILE_SYSTEM"},
{0x00000024,	"NTFS_FILE_SYSTEM"},
{0x00000025,	"NPFS_FILE_SYSTEM"},
{0x00000026,	"CDFS_FILE_SYSTEM"},
{0x00000027,	"RDR_FILE_SYSTEM"},
{0x00000028,	"CORRUPT_ACCESS_TOKEN"},
{0x00000029,	"SECURITY_SYSTEM"},
{0x0000002A,	"INCONSISTENT_IRP"},
{0x0000002B,	"PANIC_STACK_SWITCH"},
{0x0000002C,	"PORT_DRIVER_INTERNAL"},
{0x0000002D,	"SCSI_DISK_DRIVER_INTERNAL"},
{0x0000002E,	"DATA_BUS_ERROR"},
{0x0000002F,	"INSTRUCTION_BUS_ERROR"},
{0x00000030,	"SET_OF_INVALID_CONTEXT"},
{0x00000031,	"PHASE0_INITIALIZATION_FAILED"},
{0x00000032,	"PHASE1_INITIALIZATION_FAILED"},
{0x00000033,	"UNEXPECTED_INITIALIZATION_CALL"},
{0x00000034,	"CACHE_MANAGER"},
{0x00000035,	"NO_MORE_IRP_STACK_LOCATIONS"},
{0x00000036,	"DEVICE_REFERENCE_COUNT_NOT_ZERO"},
{0x00000037,	"FLOPPY_INTERNAL_ERROR"},
{0x00000038,	"SERIAL_DRIVER_INTERNAL"},
{0x00000039,	"SYSTEM_EXIT_OWNED_MUTEX"},
{0x0000003A,	"SYSTEM_UNWIND_PREVIOUS_USER"},
{0x0000003B,	"SYSTEM_SERVICE_EXCEPTION"},
{0x0000003C,	"INTERRUPT_UNWIND_ATTEMPTED"},
{0x0000003D,	"INTERRUPT_EXCEPTION_NOT_HANDLED"},
{0x0000003E,	"MULTIPROCESSOR_CONFIGURATION_NOT_SUPPORTED"},
{0x0000003F,	"NO_MORE_SYSTEM_PTES"},
{0x00000040,	"TARGET_MDL_TOO_SMALL"},
{0x00000041,	"MUST_SUCCEED_POOL_EMPTY"},
{0x00000042,	"ATDISK_DRIVER_INTERNAL"},
{0x00000043,	"NO_SUCH_PARTITION"},
{0x00000044,	"MULTIPLE_IRP_COMPLETE_REQUESTS"},
{0x00000045,	"INSUFFICIENT_SYSTEM_MAP_REGS"},
{0x00000046,	"DEREF_UNKNOWN_LOGON_SESSION"},
{0x00000047,	"REF_UNKNOWN_LOGON_SESSION"},
{0x00000048,	"CANCEL_STATE_IN_COMPLETED_IRP"},
{0x00000049,	"PAGE_FAULT_WITH_INTERRUPTS_OFF"},
{0x0000004A,	"IRQL_GT_ZERO_AT_SYSTEM_SERVICE"},
{0x0000004B,	"STREAMS_INTERNAL_ERROR"},
{0x0000004C,	"FATAL_UNHANDLED_HARD_ERROR"},
{0x0000004D,	"NO_PAGES_AVAILABLE"},
{0x0000004E,	"PFN_LIST_CORRUPT"},
{0x0000004F,	"NDIS_INTERNAL_ERROR"},
{0x00000050,	"PAGE_FAULT_IN_NONPAGED_AREA"},
{0x00000051,	"REGISTRY_ERROR"},
{0x00000052,	"MAILSLOT_FILE_SYSTEM"},
{0x00000053,	"NO_BOOT_DEVICE"},
{0x00000054,	"LM_SERVER_INTERNAL_ERROR"},
{0x00000055,	"DATA_COHERENCY_EXCEPTION"},
{0x00000056,	"INSTRUCTION_COHERENCY_EXCEPTION"},
{0x00000057,	"XNS_INTERNAL_ERROR"},
{0x00000058,	"FTDISK_INTERNAL_ERROR"},
{0x00000059,	"PINBALL_FILE_SYSTEM"},
{0x0000005A,	"CRITICAL_SERVICE_FAILED"},
{0x0000005B,	"SET_ENV_VAR_FAILED"},
{0x0000005C,	"HAL_INITIALIZATION_FAILED"},
{0x0000005D,	"UNSUPPORTED_PROCESSOR"},
{0x0000005E,	"OBJECT_INITIALIZATION_FAILED"},
{0x0000005F,	"SECURITY_INITIALIZATION_FAILED"},
{0x00000060,	"PROCESS_INITIALIZATION_FAILED"},
{0x00000061,	"HAL1_INITIALIZATION_FAILED"},
{0x00000062,	"OBJECT1_INITIALIZATION_FAILED"},
{0x00000063,	"SECURITY1_INITIALIZATION_FAILED"},
{0x00000064,	"SYMBOLIC_INITIALIZATION_FAILED"},
{0x00000065,	"MEMORY1_INITIALIZATION_FAILED"},
{0x00000066,	"CACHE_INITIALIZATION_FAILED"},
{0x00000067,	"CONFIG_INITIALIZATION_FAILED"},
{0x00000068,	"FILE_INITIALIZATION_FAILED"},
{0x00000069,	"IO1_INITIALIZATION_FAILED"},
{0x0000006A,	"LPC_INITIALIZATION_FAILED"},
{0x0000006B,	"PROCESS1_INITIALIZATION_FAILED"},
{0x0000006C,	"REFMON_INITIALIZATION_FAILED"},
{0x0000006D,	"SESSION1_INITIALIZATION_FAILED"},
{0x0000006E,	"SESSION2_INITIALIZATION_FAILED"},
{0x0000006F,	"SESSION3_INITIALIZATION_FAILED"},
{0x00000070,	"SESSION4_INITIALIZATION_FAILED"},
{0x00000071,	"SESSION5_INITIALIZATION_FAILED"},
{0x00000072,	"ASSIGN_DRIVE_LETTERS_FAILED"},
{0x00000073,	"CONFIG_LIST_FAILED"},
{0x00000074,	"BAD_SYSTEM_CONFIG_INFO"},
{0x00000075,	"CANNOT_WRITE_CONFIGURATION"},
{0x00000076,	"PROCESS_HAS_LOCKED_PAGES"},
{0x00000077,	"KERNEL_STACK_INPAGE_ERROR"},
{0x00000078,	"PHASE0_EXCEPTION"},
{0x00000079,	"MISMATCHED_HAL"},
{0x0000007A,	"KERNEL_DATA_INPAGE_ERROR"},
{0x0000007B,	"INACCESSIBLE_BOOT_DEVICE"},
{0x0000007C,	"BUGCODE_NDIS_DRIVER"},
{0x0000007D,	"INSTALL_MORE_MEMORY"},
{0x0000007E,	"SYSTEM_THREAD_EXCEPTION_NOT_HANDLED"},
{0x0000007F,	"UNEXPECTED_KERNEL_MODE_TRAP"},
{0x00000080,	"NMI_HARDWARE_FAILURE"},
{0x00000081,	"SPIN_LOCK_INIT_FAILURE"},
{0x00000082,	"DFS_FILE_SYSTEM"},
{0x00000085,	"SETUP_FAILURE"},
{0x0000008B,	"MBR_CHECKSUM_MISMATCH"},
{0x0000008E,	"KERNEL_MODE_EXCEPTION_NOT_HANDLED"},
{0x0000008F,	"PP0_INITIALIZATION_FAILED"},
{0x00000090,	"PP1_INITIALIZATION_FAILED"},
{0x00000092,	"UP_DRIVER_ON_MP_SYSTEM"},
{0x00000093,	"INVALID_KERNEL_HANDLE"},
{0x00000094,	"KERNEL_STACK_LOCKED_AT_EXIT"},
{0x00000096,	"INVALID_WORK_QUEUE_ITEM"},
{0x00000097,	"BOUND_IMAGE_UNSUPPORTED"},
{0x00000098,	"END_OF_NT_EVALUATION_PERIOD"},
{0x00000099,	"INVALID_REGION_OR_SEGMENT"},
{0x0000009A,	"SYSTEM_LICENSE_VIOLATION"},
{0x0000009B,	"UDFS_FILE_SYSTEM"},
{0x0000009C,	"MACHINE_CHECK_EXCEPTION"},
{0x0000009E,	"USER_MODE_HEALTH_MONITOR"},
{0x0000009F,	"DRIVER_POWER_STATE_FAILURE"},
{0x000000A0,	"INTERNAL_POWER_ERROR"},
{0x000000A1,	"PCI_BUS_DRIVER_INTERNAL"},
{0x000000A2,	"MEMORY_IMAGE_CORRUPT"},
{0x000000A3,	"ACPI_DRIVER_INTERNAL"},
{0x000000A4,	"CNSS_FILE_SYSTEM_FILTER"},
{0x000000A5,	"ACPI_BIOS_ERROR"},
{0x000000A7,	"BAD_EXHANDLE"},
{0x000000AC,	"HAL_MEMORY_ALLOCATION"},
{0x000000AD,	"VIDEO_DRIVER_DEBUG_REPORT_REQUEST"},
{0x000000B1,	"BGI_DETECTED_VIOLATION"},
{0x000000B4,	"VIDEO_DRIVER_INIT_FAILURE"},
{0x000000B8,	"ATTEMPTED_SWITCH_FROM_DPC"},
{0x000000B9,	"CHIPSET_DETECTED_ERROR"},
{0x000000BA,	"SESSION_HAS_VALID_VIEWS_ON_EXIT"},
{0x000000BB,	"NETWORK_BOOT_INITIALIZATION_FAILED"},
{0x000000BC,	"NETWORK_BOOT_DUPLICATE_ADDRESS"},
{0x000000BD,	"INVALID_HIBERNATED_STATE"},
{0x000000BE,	"ATTEMPTED_WRITE_TO_READONLY_MEMORY"},
{0x000000BF,	"MUTEX_ALREADY_OWNED"},
{0x000000C1,	"SPECIAL_POOL_DETECTED_MEMORY_CORRUPTION"},
{0x000000C2,	"BAD_POOL_CALLER"},
{0x000000C4,	"DRIVER_VERIFIER_DETECTED_VIOLATION"},
{0x000000C5,	"DRIVER_CORRUPTED_EXPOOL"},
{0x000000C6,	"DRIVER_CAUGHT_MODIFYING_FREED_POOL"},
{0x000000C7,	"TIMER_OR_DPC_INVALID"},
{0x000000C8,	"IRQL_UNEXPECTED_VALUE"},
{0x000000C9,	"DRIVER_VERIFIER_IOMANAGER_VIOLATION"},
{0x000000CA,	"PNP_DETECTED_FATAL_ERROR"},
{0x000000CB,	"DRIVER_LEFT_LOCKED_PAGES_IN_PROCESS"},
{0x000000CC,	"PAGE_FAULT_IN_FREED_SPECIAL_POOL"},
{0x000000CD,	"PAGE_FAULT_BEYOND_END_OF_ALLOCATION"},
{0x000000CE,	"DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS"},
{0x000000CF,	"TERMINAL_SERVER_DRIVER_MADE_INCORRECT_MEMORY_REFERENCE"},
{0x000000D0,	"DRIVER_CORRUPTED_MMPOOL"},
{0x000000D1,	"DRIVER_IRQL_NOT_LESS_OR_EQUAL"},
{0x000000D2,	"BUGCODE_ID_DRIVER"},
{0x000000D3,	"DRIVER_PORTION_MUST_BE_NONPAGED"},
{0x000000D4,	"SYSTEM_SCAN_AT_RAISED_IRQL_CAUGHT_IMPROPER_DRIVER_UNLOAD"},
{0x000000D5,	"DRIVER_PAGE_FAULT_IN_FREED_SPECIAL_POOL"},
{0x000000D6,	"DRIVER_PAGE_FAULT_BEYOND_END_OF_ALLOCATION"},
{0x000000D7,	"DRIVER_UNMAPPING_INVALID_VIEW"},
{0x000000D8,	"DRIVER_USED_EXCESSIVE_PTES"},
{0x000000D9,	"LOCKED_PAGES_TRACKER_CORRUPTION"},
{0x000000DA,	"SYSTEM_PTE_MISUSE"},
{0x000000DB,	"DRIVER_CORRUPTED_SYSPTES"},
{0x000000DC,	"DRIVER_INVALID_STACK_ACCESS"},
{0x000000DE,	"POOL_CORRUPTION_IN_FILE_AREA"},
{0x000000DF,	"IMPERSONATING_WORKER_THREAD"},
{0x000000E0,	"ACPI_BIOS_FATAL_ERROR"},
{0x000000E1,	"WORKER_THREAD_RETURNED_AT_BAD_IRQL"},
{0x000000E2,	"MANUALLY_INITIATED_CRASH"},
{0x000000E3,	"RESOURCE_NOT_OWNED"},
{0x000000E4,	"WORKER_INVALID"},
{0x000000E6,	"DRIVER_VERIFIER_DMA_VIOLATION"},
{0x000000E7,	"INVALID_FLOATING_POINT_STATE"},
{0x000000E8,	"INVALID_CANCEL_OF_FILE_OPEN"},
{0x000000E9,	"ACTIVE_EX_WORKER_THREAD_TERMINATION"},
{0x000000EA,	"THREAD_STUCK_IN_DEVICE_DRIVER"},
{0x000000EB,	"DIRTY_MAPPED_PAGES_CONGESTION"},
{0x000000EC,	"SESSION_HAS_VALID_SPECIAL_POOL_ON_EXIT"},
{0x000000ED,	"UNMOUNTABLE_BOOT_VOLUME"},
{0x000000EF,	"CRITICAL_PROCESS_DIED"},
{0x000000F0,	"STORAGE_MINIPORT_ERROR"},
{0x000000F1,	"SCSI_VERIFIER_DETECTED_VIOLATION"},
{0x000000F2,	"HARDWARE_INTERRUPT_STORM"},
{0x000000F3,	"DISORDERLY_SHUTDOWN"},
{0x000000F4,	"CRITICAL_OBJECT_TERMINATION"},
{0x000000F5,	"FLTMGR_FILE_SYSTEM"},
{0x000000F6,	"PCI_VERIFIER_DETECTED_VIOLATION"},
{0x000000F7,	"DRIVER_OVERRAN_STACK_BUFFER"},
{0x000000F8,	"RAMDISK_BOOT_INITIALIZATION_FAILED"},
{0x000000F9,	"DRIVER_RETURNED_STATUS_REPARSE_FOR_VOLUME_OPEN"},
{0x000000FA,	"HTTP_DRIVER_CORRUPTED"},
{0x000000FC,	"ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY"},
{0x000000FD,	"DIRTY_NOWRITE_PAGES_CONGESTION"},
{0x000000FE,	"BUGCODE_USB_DRIVER"},
{0x000000FF,	"RESERVE_QUEUE_OVERFLOW"},
{0x00000100,	"LOADER_BLOCK_MISMATCH"},
{0x00000101,	"CLOCK_WATCHDOG_TIMEOUT"},
{0x00000102,	"DPC_WATCHDOG_TIMEOUT"},
{0x00000103,	"MUP_FILE_SYSTEM"},
{0x00000104,	"AGP_INVALID_ACCESS"},
{0x00000105,	"AGP_GART_CORRUPTION"},
{0x00000106,	"AGP_ILLEGALLY_REPROGRAMMED"},
{0x00000108,	"THIRD_PARTY_FILE_SYSTEM_FAILURE"},
{0x00000109,	"CRITICAL_STRUCTURE_CORRUPTION"},
{0x0000010A,	"APP_TAGGING_INITIALIZATION_FAILED"},
{0x0000010C,	"FSRTL_EXTRA_CREATE_PARAMETER_VIOLATION"},
{0x0000010D,	"WDF_VIOLATION"},
{0x0000010E,	"VIDEO_MEMORY_MANAGEMENT_INTERNAL"},
{0x0000010F,	"RESOURCE_MANAGER_EXCEPTION_NOT_HANDLED"},
{0x00000111,	"RECURSIVE_NMI"},
{0x00000112,	"MSRPC_STATE_VIOLATION"},
{0x00000113,	"VIDEO_DXGKRNL_FATAL_ERROR"},
{0x00000114,	"VIDEO_SHADOW_DRIVER_FATAL_ERROR"},
{0x00000115,	"AGP_INTERNAL"},
{0x00000116,	"VIDEO_TDR_FAILURE"},
{0x00000117,	"VIDEO_TDR_TIMEOUT_DETECTED"},
{0x00000119,	"VIDEO_SCHEDULER_INTERNAL_ERROR"},
{0x0000011A,	"EM_INITIALIZATION_FAILURE"},
{0x0000011B,	"DRIVER_RETURNED_HOLDING_CANCEL_LOCK"},
{0x0000011C,	"ATTEMPTED_WRITE_TO_CM_PROTECTED_STORAGE"},
{0x0000011D,	"EVENT_TRACING_FATAL_ERROR"},
{0x0000011E,	"TOO_MANY_RECURSIVE_FAULTS"},
{0x0000011F,	"INVALID_DRIVER_HANDLE"},
{0x00000120,	"BITLOCKER_FATAL_ERROR"},
{0x00000121,	"DRIVER_VIOLATION"},
{0x00000122,	"WHEA_INTERNAL_ERROR"},
{0x00000123,	"CRYPTO_SELF_TEST_FAILURE"},
{0x00000124,	"WHEA_UNCORRECTABLE_ERROR"},
{0x00000125,	"NMR_INVALID_STATE"},
{0x00000126,	"NETIO_INVALID_POOL_CALLER"},
{0x00000127,	"PAGE_NOT_ZERO"},
{0x00000128,	"WORKER_THREAD_RETURNED_WITH_BAD_IO_PRIORITY"},
{0x00000129,	"WORKER_THREAD_RETURNED_WITH_BAD_PAGING_IO_PRIORITY"},
{0x0000012A,	"MUI_NO_VALID_SYSTEM_LANGUAGE"},
{0x0000012B,	"FAULTY_HARDWARE_CORRUPTED_PAGE"},
{0x0000012C,	"EXFAT_FILE_SYSTEM"},
{0x0000012D,	"VOLSNAP_OVERLAPPED_TABLE_ACCESS"},
{0x0000012E,	"INVALID_MDL_RANGE"},
{0x0000012F,	"VHD_BOOT_INITIALIZATION_FAILED"},
{0x00000130,	"DYNAMIC_ADD_PROCESSOR_MISMATCH"},
{0x00000131,	"INVALID_EXTENDED_PROCESSOR_STATE"},
{0x00000132,	"RESOURCE_OWNER_POINTER_INVALID"},
{0x00000133,	"DPC_WATCHDOG_VIOLATION"},
{0x00000134,	"DRIVE_EXTENDER"},
{0x00000135,	"REGISTRY_FILTER_DRIVER_EXCEPTION"},
{0x00000136,	"VHD_BOOT_HOST_VOLUME_NOT_ENOUGH_SPACE"},
{0x00000137,	"WIN32K_HANDLE_MANAGER"},
{0x00000138,	"GPIO_CONTROLLER_DRIVER_ERROR"},
{0x00000139,	"KERNEL_SECURITY_CHECK_FAILURE"},
{0x0000013A,	"KERNEL_MODE_HEAP_CORRUPTION"},
{0x0000013B,	"PASSIVE_INTERRUPT_ERROR"},
{0x0000013C,	"INVALID_IO_BOOST_STATE"},
{0x0000013D,	"CRITICAL_INITIALIZATION_FAILURE"},
{0x00000140,	"STORAGE_DEVICE_ABNORMALITY_DETECTED"},
{0x00000143,	"PROCESSOR_DRIVER_INTERNAL"},
{0x00000144,	"BUGCODE_USB3_DRIVER"},
{0x00000145,	"SECURE_BOOT_VIOLATION"},
{0x00000147,	"ABNORMAL_RESET_DETECTED"},
{0x00000149,	"REFS_FILE_SYSTEM"},
{0x0000014A,	"KERNEL_WMI_INTERNAL"},
{0x0000014B,	"SOC_SUBSYSTEM_FAILURE"},
{0x0000014C,	"FATAL_ABNORMAL_RESET_ERROR"},
{0x0000014D,	"EXCEPTION_SCOPE_INVALID"},
{0x0000014E,	"SOC_CRITICAL_DEVICE_REMOVED"},
{0x0000014F,	"PDC_WATCHDOG_TIMEOUT"},
{0x00000150,	"TCPIP_AOAC_NIC_ACTIVE_REFERENCE_LEAK"},
{0x00000151,	"UNSUPPORTED_INSTRUCTION_MODE"},
{0x00000152,	"INVALID_PUSH_LOCK_FLAGS"},
{0x00000153,	"KERNEL_LOCK_ENTRY_LEAKED_ON_THREAD_TERMINATION"},
{0x00000154,	"UNEXPECTED_STORE_EXCEPTION"},
{0x00000155,	"OS_DATA_TAMPERING"},
{0x00000157,	"KERNEL_THREAD_PRIORITY_FLOOR_VIOLATION"},
{0x00000158,	"ILLEGAL_IOMMU_PAGE_FAULT"},
{0x00000159,	"HAL_ILLEGAL_IOMMU_PAGE_FAULT"},
{0x0000015A,	"SDBUS_INTERNAL_ERROR"},
{0x0000015B,	"WORKER_THREAD_RETURNED_WITH_SYSTEM_PAGE_PRIORITY_ACTIVE"},
{0x00000160,	"WIN32K_ATOMIC_CHECK_FAILURE"},
{0x00000162,	"KERNEL_AUTO_BOOST_INVALID_LOCK_RELEASE"},
{0x00000163,	"WORKER_THREAD_TEST_CONDITION"},
{0x00000164,	"WIN32K_CRITICAL_FAILURE"},
{0x0000016C,	"INVALID_RUNDOWN_PROTECTION_FLAGS"},
{0x0000016D,	"INVALID_SLOT_ALLOCATOR_FLAGS"},
{0x0000016E,	"ERESOURCE_INVALID_RELEASE"},
{0x00000170,	"CLUSTER_CSV_CLUSSVC_DISCONNECT_WATCHDOG"},
{0x00000171,	"CRYPTO_LIBRARY_INTERNAL_ERROR"},
{0x00000173,	"COREMSGCALL_INTERNAL_ERROR"},
{0x00000174,	"COREMSG_INTERNAL_ERROR"},
{0x00000178,	"ELAM_DRIVER_DETECTED_FATAL_ERROR"},
{0x0000017B,	"PROFILER_CONFIGURATION_ILLEGAL"},
{0x0000017E,	"MICROCODE_REVISION_MISMATCH"},
{0x00000187,	"VIDEO_DWMINIT_TIMEOUT_FALLBACK_BDD"},
{0x00000189,	"BAD_OBJECT_HEADER"},
{0x0000018B,	"SECURE_KERNEL_ERROR"},
{0x0000018C,	"HYPERGUARD_VIOLATION"},
{0x0000018D,	"SECURE_FAULT_UNHANDLED"},
{0x0000018E,	"KERNEL_PARTITION_REFERENCE_VIOLATION"},
{0x00000191,	"PF_DETECTED_CORRUPTION"},
{0x00000192,	"KERNEL_AUTO_BOOST_LOCK_ACQUISITION_WITH_RAISED_IRQL"},
{0x00000196,	"LOADER_ROLLBACK_DETECTED"},
{0x00000197,	"WIN32K_SECURITY_FAILURE"},
{0x00000199,	"KERNEL_STORAGE_SLOT_IN_USE"},
{0x0000019A,	"WORKER_THREAD_RETURNED_WHILE_ATTACHED_TO_SILO"},
{0x0000019B,	"TTM_FATAL_ERROR"},
{0x0000019C,	"WIN32K_POWER_WATCHDOG_TIMEOUT"},
{0x000001A0,	"TTM_WATCHDOG_TIMEOUT"},
{0x000001A2,	"WIN32K_CALLOUT_WATCHDOG_BUGCHECK"},
{0x000001AA,	"EXCEPTION_ON_INVALID_STACK"},
{0x000001AB,	"UNWIND_ON_INVALID_STACK"},
{0x000001C6,	"FAST_ERESOURCE_PRECONDITION_VIOLATION"},
{0x000001C7,	"STORE_DATA_STRUCTURE_CORRUPTION"},
{0x000001C8,	"MANUALLY_INITIATED_POWER_BUTTON_HOLD"},
{0x000001CA,	"SYNTHETIC_WATCHDOG_TIMEOUT"},
{0x000001CB,	"INVALID_SILO_DETACH"},
{0x000001CD,	"INVALID_CALLBACK_STACK_ADDRESS"},
{0x000001CE,	"INVALID_KERNEL_STACK_ADDRESS"},
{0x000001CF,	"HARDWARE_WATCHDOG_TIMEOUT"},
{0x000001D0,	"CPI_FIRMWARE_WATCHDOG_TIMEOUT"},
{0x000001D2,	"WORKER_THREAD_INVALID_STATE"},
{0x000001D3,	"WFP_INVALID_OPERATION"},
{0x000001D5,	"DRIVER_PNP_WATCHDOG"},
{0x000001D6,	"WORKER_THREAD_RETURNED_WITH_NON_DEFAULT_WORKLOAD_CLASS"},
{0x000001D7,	"EFS_FATAL_ERROR"},
{0x000001D8,	"UCMUCSI_FAILURE"},
{0x000001D9,	"HAL_IOMMU_INTERNAL_ERROR"},
{0x000001DA,	"HAL_BLOCKED_PROCESSOR_INTERNAL_ERROR"},
{0x000001DB,	"IPI_WATCHDOG_TIMEOUT"},
{0x000001DC,	"DMA_COMMON_BUFFER_VECTOR_ERROR"},
{0x000001DD,	"BUGCODE_MBBADAPTER_DRIVER"},
{0x000001DE,	"BUGCODE_WIFIADAPTER_DRIVER"},
{0x000001DF,	"PROCESSOR_START_TIMEOUT"},
{0x000001E4,	"VIDEO_DXGKRNL_SYSMM_FATAL_ERROR"},
{0x000001E9,	"ILLEGAL_ATS_INITIALIZATION"},
{0x000001EA,	"SECURE_PCI_CONFIG_SPACE_ACCESS_VIOLATION"},
{0x000001EB,	"DAM_WATCHDOG_TIMEOUT"},
{0x000001ED,	"HANDLE_ERROR_ON_CRITICAL_THREAD"},
{0x000001F1,	"KASAN_ENLIGHTENMENT_VIOLATION"},
{0x000001F2,	"KASAN_ILLEGAL_ACCESS"},
{0x00000356,	"XBOX_ERACTRL_CS_TIMEOUT"},
{0x00000BFE,	"BC_BLUETOOTH_VERIFIER_FAULT"},
{0x00000BFF,	"BC_BTHMINI_VERIFIER_FAULT"},
{0x00020001,	"HYPERVISOR_ERROR"},
{0x1000007E,	"SYSTEM_THREAD_EXCEPTION_NOT_HANDLED_M"},
{0x1000007F,	"UNEXPECTED_KERNEL_MODE_TRAP_M"},
{0x1000008E,	"KERNEL_MODE_EXCEPTION_NOT_HANDLED_M"},
{0x100000EA,	"THREAD_STUCK_IN_DEVICE_DRIVER_M"},
{0x4000008A,	"THREAD_TERMINATE_HELD_MUTEX"},
{0xC0000218,	"STATUS_CANNOT_LOAD_REGISTRY_FILE"},
{0xC000021A,	"WINLOGON_FATAL_ERROR"},
{0xC0000221,	"STATUS_IMAGE_CHECKSUM_MISMATCH"},
{0xDEADDEAD,	"MANUALLY_INITIATED_CRASH1"}
};