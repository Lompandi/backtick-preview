
#include <windows.h>

#include <set>
#include <detours.h>
#include <fmt/format.h>

#include "hooks.hpp"
#include "globals.hpp"
#include "emulator.hpp"
#include "cmdparsing.hpp"
#include <iostream>
#include <cassert>

Hooks g_Hooks;

constexpr std::uint64_t Amd64MachineInfoVtableOffset   = 0x633D60;
constexpr std::uint64_t ConnLiveKernelTargetInfoOffset = 0x64E528;
constexpr std::uint64_t DbsSplayTreeCacheFlushOffset = 0x487D18;

// LiveKernelTargetInfoCached::ReadVirtual
uintptr_t ReadVirtualAddress = 0;
using ReadVirtualOffset_t = HRESULT(__fastcall*)(void*, void*, uint64_t, void*, uint32_t, uint32_t*);
static ReadVirtualOffset_t OriginalReadVirtual = nullptr;

uintptr_t GetRegValAddress = 0;
using GetRegisterVal_t = HRESULT(__fastcall*)(void*, ULONG, REGVAL*);
static GetRegisterVal_t OriginalGetRegisterVal = nullptr;

std::uint64_t WriteVirtualAddress = 0;
using WriteVirtual_t = HRESULT(__fastcall*)(void*, void*, uint64_t, void*, uint32_t, uint32_t*);
static WriteVirtual_t OriginalWriteVirtual = nullptr;

struct _ADDR {
    std::uint64_t Type;
    std::uint64_t Value1;
    std::uint64_t Value2;
    std::uint64_t Unk1;
};

std::uint64_t GetPcAddress = 0;
using GetPc_t = HRESULT(__fastcall*)(std::uint64_t, _ADDR*);
static GetPc_t OriginalGetPcVal = nullptr;

std::uint64_t ExecuteCommandAddress = 0;
using ExecuteCommand_t = HRESULT(__fastcall*)(struct DebugClient*, const unsigned __int16*, signed int, int);
static ExecuteCommand_t OriginalExecuteCommand = nullptr;

void* DbsSplayTreeCacheFlushAddress = nullptr;

uint64_t DbgEngBase = 0;
constexpr bool HooksDebugging = false;

std::set<std::uint64_t> g_DbsSplayTreeCacheInstanceAddresses;


template <typename... Args_t>
void HooksDbg(const char* Format, const Args_t &...args) {
    if constexpr (HooksDebugging) {
        fmt::print("hooks: ");
        fmt::print(fmt::runtime(Format), args...);
        fmt::print("\n");
    }
}

static HRESULT SetRegisterValHook(uint64_t pThis, ULONG Index, REGVAL* pRegVal) {
    HooksDbg("[*] Setting register {:#x} to {}", Index, pRegVal->ToString());

    if (!g_Emulator.SetReg((Registers_t)Index, pRegVal)) {
        return E_INVALIDARG;
    }

    return S_OK;
}

static HRESULT GetRegisterValHook(void* pThis, ULONG Index, REGVAL* pRegVal) {
    HooksDbg("[*] Reading register {:#x}", Index);

    if (g_Emulator.GetReg((Registers_t)Index, pRegVal)) {
        return S_OK;
    }

    return OriginalGetRegisterVal(
        pThis, Index, pRegVal
    );
}

static HRESULT ReadVirtualHook(void* pThis, void* Process, uint64_t ReadAddress, void* Buffer, uint32_t Size, uint32_t* BytesRead) {
    HooksDbg("[*] {:#x} Reading {} bytes from {:#x}", (uintptr_t)pThis, Size, ReadAddress);

    //
    // Check whether it is mapped, if not, foward the execution flow to original function
    //

    if (!g_Emulator.IsGvaMapped(ReadAddress)) {
        return OriginalReadVirtual(pThis, Process, ReadAddress, Buffer, Size, BytesRead);
    }

    if (!g_Emulator.VirtRead(ReadAddress, (uint8_t*)Buffer, Size)) {
        return S_FALSE;
    }

    *BytesRead = Size;
    return S_OK;
}

static HRESULT WriteVirtualHook(void* pThis, void* Process, uint64_t WriteAddress, void* Buffer, uint32_t Size, uint32_t* BytesWritten) {
    HooksDbg("[*] Writing {} bytes to {:#x}", Size, WriteAddress);

    if (!g_Emulator.VirtWrite(WriteAddress, (const uint8_t*)Buffer, Size)) {
        return S_FALSE;
    }

    *BytesWritten = Size;
    return S_OK;
}

static HRESULT SetExecStepTraceHook(std::uint64_t pThis, 
    std::uint64_t pAddr, std::uint64_t StepTracePassCheck, 
    std::uint64_t a1, const std::uint16_t* a2, std::uint64_t pThreadInfo, 
    int a3, std::uint64_t InternalCmdState) {


    return S_OK;
}

static HRESULT GetPcHook(std::uint64_t pThis, _ADDR* pAddr) { 
    pAddr->Type = 0x0000000000100028;
    pAddr->Value1 = g_Emulator.Rip();
    pAddr->Value2 = g_Emulator.Rip();
    return S_OK;
}

static HRESULT SetPcHook(std::uint64_t pThis, _ADDR* pAddr) {
    g_Emulator.Rip(pAddr->Value1);
    return S_OK;
}

static HRESULT LiveKernelTargetInfoCached__ReadVirtualHook(void* pThis,
    void* ProcessInfo, std::uint64_t Address, void* Buffer, ULONG Size, ULONG* OutSize) {

    if (ProcessInfo != nullptr) {

        std::uint64_t DbsSplayTreeCacheAddress
            = (uint64_t)((char*)ProcessInfo + 0x4f8);

        if (!g_DbsSplayTreeCacheInstanceAddresses.contains(DbsSplayTreeCacheAddress)) {
            g_DbsSplayTreeCacheInstanceAddresses.insert(DbsSplayTreeCacheAddress);
        }
    }

    using OriginalFunc = HRESULT(__fastcall*)(void*, void*, std::uint64_t, void*, ULONG, ULONG*);
    return g_Hooks.CallOriginalTyped<OriginalFunc>(&LiveKernelTargetInfoCached__ReadVirtualHook,
        pThis, ProcessInfo, Address, Buffer, Size, OutSize);
}

static HRESULT LiveKernelTargetInfoCached__WriteVirtualHook(void* pThis,
    void* ProcessInfo, std::uint64_t Address, void* Buffer, ULONG Size, ULONG* OutSize) {

    if (ProcessInfo != nullptr) {

        std::uint64_t DbsSplayTreeCacheAddress
            = (uint64_t)((char*)ProcessInfo + 0x4f8);

        if (!g_DbsSplayTreeCacheInstanceAddresses.contains(DbsSplayTreeCacheAddress)) {
            g_DbsSplayTreeCacheInstanceAddresses.insert(DbsSplayTreeCacheAddress);
        }
    }

    using OriginalFunc = HRESULT(__fastcall*)(void*, void*, std::uint64_t, void*, ULONG, ULONG*);
    return g_Hooks.CallOriginalTyped<OriginalFunc>(&LiveKernelTargetInfoCached__WriteVirtualHook,
        pThis, ProcessInfo, Address, Buffer, Size, OutSize);
}

static HRESULT ExecuteCommandHook(struct DebugClient* Client,
    const unsigned __int16* Command, signed int a2, int a1) {

    std::u16string WCommandString;
    WCommandString.assign(reinterpret_cast<const char16_t*>(Command));

    if (ExecuteHook(WCommandString)) {
        g_Tui.RenderFrame();
        return S_OK;
    }

    g_OutputCb.ClearOutPutBuffer();

    HRESULT Status = OriginalExecuteCommand(Client, Command, a2, a1);
    g_Tui.RenderFrame();
    return Status;
}

void Hooks::FlushDbsSplayTreeCache() {
    //
    // Haven't get the memory display instance yet
    //
    if (g_DbsSplayTreeCacheInstanceAddresses.empty()) {
        return;
    }

    for (const auto& Instance : g_DbsSplayTreeCacheInstanceAddresses) {
        using Func_t = void(__fastcall*)(void*);
        return reinterpret_cast<Func_t>(DbsSplayTreeCacheFlushAddress)((void*)Instance);
    }
}

void Hooks::RegisterVtableHook(void** Vtable, size_t Index, void* HookFunc) {
    RegisteredHooks_.push_back(std::tie(Vtable, Index, HookFunc));
}

bool Hooks::Enable() {
    for (const auto& [Vtable, Index, HookFunc] : RegisteredHooks_) {
        HookVtable(Vtable, Index, HookFunc);
    }

    DbgEngBase = (std::uint64_t)GetModuleHandleA("dbgeng.dll");

    OriginalGetPcVal = reinterpret_cast<GetPc_t>(AddDetour(
        (void*)(GetPcAddress), (void*)GetPcHook
    ));

    OriginalGetRegisterVal = reinterpret_cast<GetRegisterVal_t>(AddDetour(
        (void*)(GetRegValAddress), (void*)GetRegisterValHook
    ));

    OriginalExecuteCommand = reinterpret_cast<ExecuteCommand_t>(AddDetour(
        (void*)(ExecuteCommandAddress), (void*)ExecuteCommandHook
    ));

    OriginalReadVirtual = reinterpret_cast<ReadVirtualOffset_t>(AddDetour(
        (void*)(ReadVirtualAddress), (void*)ReadVirtualHook
    ));

    OriginalWriteVirtual = reinterpret_cast<WriteVirtual_t>(AddDetour(
        (void*)(WriteVirtualAddress), (void*)WriteVirtualHook
    ));

    return true;
}

bool Hooks::RestorePatchedBytes() {
    for (const auto& [address, restoreBytes] : PatchedBytes_) {
        DWORD oldProtect;
        size_t length = restoreBytes.size();

        if (VirtualProtect(address, length, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            memcpy(address, restoreBytes.data(), length);
            VirtualProtect(address, length, oldProtect, &oldProtect);
            FlushInstructionCache(GetCurrentProcess(), address, length);
        }
    }

    PatchedBytes_.clear();
    return true;
}


bool Hooks::Restore() {
    //
    // Remove all VTable hooks
    //
    for (auto& [targetAddress, originalFunc] : Originals_) {
        DWORD oldProtect;
        VirtualProtect(targetAddress, sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtect);
        *targetAddress = originalFunc;
        VirtualProtect(targetAddress, sizeof(void*), oldProtect, &oldProtect);
    }

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)OriginalExecuteCommand, ExecuteCommandHook);
    DetourDetach(&(PVOID&)OriginalGetRegisterVal, GetRegisterValHook);
    DetourDetach(&(PVOID&)OriginalGetPcVal,       GetPcHook);
    DetourDetach(&(PVOID&)OriginalReadVirtual,    ReadVirtualHook);
    DetourDetach(&(PVOID&)OriginalWriteVirtual,   WriteVirtualHook);
    DetourTransactionCommit();

    DetouredFunctions_.clear();

    return true;
}

/*
48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 33 DB 4D 8B D1 49 8B F0 4C 8B D9 48 85 D2 0F 84 ?? ?? ?? ??                       
*/

/*
48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B 01 49 8B D8 8B EA
*/

/*
40 53 48 83 EC ?? 4D 8B D1 4D 8B D8 48 8B D9 48 85 D2 74 ?? 83 BA 4C ?? ?? ?? ??
*/

/*
48 83 EC ?? 48 89 54 24 ?? BA ?? ?? ?? ?? 44 8B CA 44 8D 42 ??
*/

/*
48 8B C4 55 56 57 41 54 41 55 41 56 41 57 48 8D A8 ?? ?? ?? ?? 48 81 EC ?? ?? ?? ?? 48 C7 44 24 ?? ?? ?? ?? FF 48 89 58 ??
48 8B 05 40 6F 79 00                    mov     rax, cs:__security_cookie
48 33 C4                                xor     rax, rsp
48 89 85 B0 03 00 00
*/

/*
XREF
41 B8 86 00 00 00 48 8B D3 49 8B CD E8 ?? ?? ?? ??
*/

bool Hooks::Init() {
	std::uintptr_t DbgEngBase = (std::uint64_t)GetModuleHandleA("dbgeng.dll");

    // LiveKernelTargetInfoCached::ReadVirtual
    ReadVirtualAddress = ScanForSignature("dbgeng.dll", "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 33 DB 4D 8B D1 49 8B F0 4C 8B D9 48 85 D2 0F 84 ?? ?? ?? ??");

    GetRegValAddress = ScanForSignature("dbgeng.dll", "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B 01 49 8B D8 8B EA");

    WriteVirtualAddress = ScanForSignature("dbgeng.dll", "40 53 48 83 EC ?? 4D 8B D1 4D 8B D8 48 8B D9 48 85 D2 74 ?? 83 BA 4C");

    GetPcAddress = ScanForSignature("dbgeng.dll", "48 83 EC ?? 48 89 54 24 ?? BA ?? ?? ?? ?? 44 8B CA 44 8D 42 ??");

    std::uint64_t ExecuteCommandXref = ScanForSignature("dbgeng.dll", "41 B8 86 00 00 00 48 8B D3 49 8B CD E8 ?? ?? ?? ??");
    std::int32_t Offset = *(std::int32_t*)((uint8_t*)ExecuteCommandXref + 0xd);
    ExecuteCommandAddress = ExecuteCommandXref + 12 + Offset + 5;

    DbsSplayTreeCacheFlushAddress = (void*)(DbgEngBase + DbsSplayTreeCacheFlushOffset);

    // SetReg Hook
    RegisterVtableHook((void**)(DbgEngBase + Amd64MachineInfoVtableOffset),   0x44, &SetRegisterValHook);

    // SetPC Hook
    RegisterVtableHook((void**)(DbgEngBase + Amd64MachineInfoVtableOffset),   0x47, &SetPcHook);


    RegisterVtableHook((void**)(DbgEngBase + ConnLiveKernelTargetInfoOffset), 0x1E, &LiveKernelTargetInfoCached__ReadVirtualHook);

	return true;
}

void* Hooks::AddDetour(void* targetFunc, void* detourFunc) {
    void* original = targetFunc;

    if (DetourTransactionBegin() != NO_ERROR ||
        DetourUpdateThread(GetCurrentThread()) != NO_ERROR ||
        DetourAttach(&original, detourFunc) != NO_ERROR ||
        DetourTransactionCommit() != NO_ERROR) {
        std::println("Detour attach failed for {}", targetFunc);
        return nullptr;
    }

    DetouredFunctions_[targetFunc] = original;
    HookedToOriginal_[detourFunc] = targetFunc;
    return original;
}

void Hooks::HookVtable(void** vtable, size_t index, void* hookFunc) {
    void** targetAddress = &vtable[index];

    if (!IsBadReadPtr(targetAddress, sizeof(void*))) {
        if (Originals_.count(targetAddress) == 0) {
            Originals_[targetAddress] = *targetAddress;
            HookedToOriginal_[hookFunc] = *targetAddress;
        }

        DWORD oldProtect;
        VirtualProtect(targetAddress, sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtect);
        *targetAddress = hookFunc;
        VirtualProtect(targetAddress, sizeof(void*), oldProtect, &oldProtect);
    }
    else {
        HooksDbg("[!] Vtable index {} is not readable at address {:p}", index, (void*)targetAddress);
    }
}
