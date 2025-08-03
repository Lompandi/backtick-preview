
#include <fmt/format.h>

#include "pch.h"

#include "src/emulator.hpp"
#include "src/debugger.hpp"
#include "src/globals.hpp"
#include "src/paging.hpp"
#include "src/utils.hpp"
#include "src/hooks.hpp"
#include "src/tui.hpp"
#include <iostream>

constexpr bool PluginVerbose = false;

template <typename... Args_t>
void PluginDbg(const char* Format, const Args_t &...args) {
    if constexpr (PluginVerbose) {
        fmt::print(fmt::runtime(Format), args...);
        fmt::print("\n");
    }
}

void WINAPI WinDbgExtensionDllInit(
    PWINDBG_EXTENSION_APIS ExtensionApis,
    USHORT MajorVersion, 
    USHORT MinorVersion) {

    if (!g_Debugger.Init()) {
        std::println("Failed to initialize debugger instance.\n");
        return;
    }

    if (!g_Hooks.Init()) {
        std::println("Failed to initialize hooks.\n");
        return;
    }
}

LPEXT_API_VERSION WDBGAPI ExtensionApiVersion(void) {
    return &g_ExtApiVersion;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH: {
    }
    }
    return TRUE;
}

void EnableVirtualTerminalProcessing() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
}

DECLARE_API(shadow) {

    if (InShadowState) {
        return;
    }

    CpuState_t CurrentState; 
    g_Debugger.LoadCpuStateTo(CurrentState);

    g_Emulator.Initialize(CurrentState);

    if (!g_Hooks.Enable()) {
        std::println("[-] Failed to initialize shadow mode.");
        return;
    }

    std::println("Debugger commands are now partially under plugin's control.");

    std::print("\x1b[?1049");
    std::fflush(stdout);

    g_Debugger.StartCaptureOutputToBuffer();

    g_Tui.RenderFrame();
    InShadowState = true;
}

DECLARE_API(unshadow) {
    if (!InShadowState) {
        return;
    }

    //
    // Flush memory display cache to
    // resync the debugger with the actual ram
    //
    g_Hooks.FlushDbsSplayTreeCache();

    if (!g_Hooks.Restore()) {
        std::println("[-] Failed to restore from shadow state.");
        return;
    }

    std::println("Returning to original debugger state");
    
    //
    // Reset emulator's state
    //
    g_Emulator.Reset();

    InShadowState = false;

    std::print("\x1b[?1049l");
    std::fflush(stdout);
}