#pragma once

#include <string>
#include <vector>

bool ExecuteHook(const std::u16string& Command);

struct GCommandParams {
    bool useHardwareBreakpoint = false;
    bool hasStartAddress = false;
    std::uint64_t startAddress = 0;
    std::vector<std::uint64_t> breakAddresses;
    std::u16string breakCommands;
};

GCommandParams ParseGCommand(const std::u16string& command);

std::uint64_t ParseAddress(const std::string& addrStr);