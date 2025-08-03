#include "cmdparsing.hpp"

#include "emulator.hpp"
#include "debugapi.h"
#include "globals.hpp"

constexpr bool ExperimentalFeaturesEnabled = true;

std::string LossyUTF16ToASCII(const std::u16string& utf16) {
    std::string ascii;
    ascii.reserve(utf16.size());

    for (char16_t ch : utf16) {
        if (ch <= 0x7F) {
            ascii.push_back(static_cast<char>(ch));
        }
        else {
            ascii.push_back('?');
        }
    }

    return ascii;
}

bool ExecuteHook(const std::u16string& Command) {
    std::u16string cmdStr = Command;

    if (cmdStr.empty()) {
        return true;
    }

    switch (cmdStr[0]) {
    case 'g': {
        // g[a] [= StartAddress] [BreakAddress ... [; BreakCommands]]
        if (Command == u"g" || Command.starts_with(u"g ") || Command == u"ga" ||
            Command.starts_with(u"ga ")) {
            auto params = ParseGCommand(Command);

            if (params.hasStartAddress) {
                g_Emulator.Rip(params.startAddress);
                std::println("[*] Starting execution from: {:#x}", params.startAddress);
            }

            if (params.breakAddresses.empty()) {
                g_Emulator.Run();
            }
        }
        else if (Command == u"gu") {
            g_Emulator.GoUp();
        }
        else if (Command.starts_with(u"g-") && ExperimentalFeaturesEnabled) {
            g_Emulator.ReverseGo();
        }
        else {
            std::println("Does not support this run mode currently");
            return true;
        }
        break;
    }
    case 't': {
        if (Command.starts_with(u"t-")) {
            uint64_t Count = 1;

            if (Command.size() > 2) {
                Count = g_Debugger.Evaluate(
                    LossyUTF16ToASCII(Command.substr(2)),
                    DEBUG_VALUE_INT64).I64;
            }

            for (auto i = 0; i < Count; i++) {
                if (g_Emulator.ReachRevertEnd()) {
                    break;
                }
                g_Emulator.ReverseStepInto();
                g_Emulator.PrintSimpleStepStatus();
            }
        }
        else if (Command.starts_with(u"t")) {
            g_Emulator.StepInto();
            g_Emulator.PrintSimpleStepStatus();
        }
        break;
    }
    case 'p': {
        if (Command.starts_with(u"p-")) {
            g_Emulator.ReverseStepOver();
            g_Emulator.PrintSimpleStepStatus();
        }
        else if (Command.starts_with(u"p")) {
            g_Emulator.StepOver();
            g_Emulator.PrintSimpleStepStatus();
        }
        break;
    }
    case 'b': {
        if (Command.starts_with(u"bp")) {
            std::string narrow_command = LossyUTF16ToASCII(Command.substr(3));
            if (narrow_command.empty()) {
                break;
            }
            std::uint64_t address = g_Debugger.Evaluate(narrow_command, DEBUG_VALUE_INT64).I64;
            if (!address) {
                std::println("Bp expression '{}' could not be resolved", narrow_command);
                std::println("*** Bp expression '{}' contains symbols not qualified with module name.", narrow_command);
                return true;
            }
            g_Emulator.InsertCodeBreakpoint(address);
        }
        else if (Command.starts_with(u"bl")) {
            g_Emulator.ListBreakpoint();
        }
        else if (Command.starts_with(u"bc")) {
            std::string narrow_command = LossyUTF16ToASCII(Command.substr(3));
            if (narrow_command.empty()) {
                break;
            }
            else {
                std::stringstream ss_command(narrow_command);
                std::string id;
                while (ss_command >> id) {
                    g_Emulator.RemoveCodeBreakpoint(std::stoul(id));
                }
            }
        }
        break;
    }
    case 'k': {
        g_Emulator.PrintStackTrace();
        break;
    }
    default: {
        // Fall back to original debugger engine
        return false;
    }
    }

    return true;
}

GCommandParams  ParseGCommand(const std::u16string& command) {
    GCommandParams params;

    std::u16string remaining;
    if (command.starts_with(u"ga ") || command == u"ga") {
        params.useHardwareBreakpoint = true;
        remaining = command.length() > 3 ? command.substr(3) : u"";
    }
    else if (command.starts_with(u"g ") || command == u"g") {
        remaining = command.length() > 2 ? command.substr(2) : u"";
    }
    if (remaining.empty()) {
        return params;
    }

    if (auto pos = remaining.find_first_not_of(u" \t"); pos != std::string::npos) {
        remaining = remaining.substr(pos);
    }

    if (auto semicolonPos = remaining.find(';'); semicolonPos != std::string::npos) {
        params.breakCommands = remaining.substr(semicolonPos + 1);
        remaining = remaining.substr(0, semicolonPos);
    }

    // start address (=address)
    if (remaining.starts_with(u"=")) {
        params.hasStartAddress = true;
        auto spacePos = remaining.find(' ', 1);
        if (spacePos != std::string::npos) {
            params.startAddress = ParseAddress(LossyUTF16ToASCII(remaining.substr(1, spacePos - 1)));
            remaining = remaining.substr(spacePos + 1);
        }
        else {
            params.startAddress = ParseAddress(LossyUTF16ToASCII(remaining.substr(1)));
            return params;
        }
    }

    // break addresses
    if (!remaining.empty()) {
        std::string addrStr;
        for (char c : remaining) {
            if (c == ' ' || c == '\t') {
                if (!addrStr.empty()) {
                    params.breakAddresses.push_back(ParseAddress(addrStr));
                    addrStr.clear();
                }
            }
            else {
                addrStr += c;
            }
        }
        if (!addrStr.empty()) {
            params.breakAddresses.push_back(ParseAddress(addrStr));
        }
    }

    return params;
}


std::uint64_t ParseAddress(const std::string& addrStr) {
    std::string trimmed = addrStr;
    if (auto pos = trimmed.find_first_not_of(" \t"); pos != std::string::npos) {
        trimmed = trimmed.substr(pos);
    }
    if (trimmed.starts_with("0x") || trimmed.starts_with("0X")) {
        return std::stoull(trimmed.substr(2), nullptr, 16);
    }

    return std::stoull(trimmed, nullptr, 16);
}