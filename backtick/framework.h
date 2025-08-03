#pragma once

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>

#define KDEXT_64BIT
#include <wdbgexts.h>
#include <dbgeng.h>

#if defined(WIN32)
#pragma commit(lib, "Dbgeng.lib")
#endif

#include <print>
#include <format>
