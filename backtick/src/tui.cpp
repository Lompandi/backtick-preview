
#include <regex>
#include <print>
#include <fmt/color.h>
#include <fmt/xchar.h>
#include <fmt/format.h>

#include "tui.hpp"
#include "emulator.hpp"
#include <iostream>

std::wstring StripAnsiCodes(const std::wstring& input) {
    static const std::wregex ansi_regex(L"\x1b\\[[0-9;]*[A-Za-z]");
    return std::regex_replace(input, ansi_regex, L"");
}

std::size_t VisibleLength(const std::wstring& input) {
    return StripAnsiCodes(input).length();
}

void TerminalUI::DrawUnicodeBoxToBuffer(
    std::size_t start_x,
    std::size_t start_y,
    const std::vector<std::wstring>& lines,
    std::size_t box_width,
    bool center_text,
    const std::wstring& title
) {
    if (box_width < 4) box_width = 4;

    const wchar_t top_left = L'\u256D';
    const wchar_t top_right = L'\u256E';
    const wchar_t bottom_left = L'\u2570';
    const wchar_t bottom_right = L'\u256F';
    const wchar_t horizontal = L'\u2500';
    const wchar_t vertical = L'\u2502';

    std::size_t content_width = box_width - 2;
    std::size_t y = start_y;

    // Top border
    /*WriteToBuffer(start_x, y, top_left);
    for (std::size_t i = 0; i < content_width; ++i)
        WriteToBuffer(start_x + 1 + i, y, horizontal);
    WriteToBuffer(start_x + 1 + content_width, y, top_right);
    ++y;*/
    if (!title.empty()) {
        std::wstring clean_title = StripAnsiCodes(title);
        std::size_t title_len = clean_title.length() + 2; // account for padding around title

        // Clamp title to fit
        if (title_len > content_width) {
            clean_title = clean_title.substr(0, content_width - 2);
            title_len = clean_title.length() + 2;
        }

        std::size_t left_len = (content_width - title_len) / 2;
        std::size_t right_len = content_width - title_len - left_len;

        std::size_t cursor_x = start_x;

        // Left side
        WriteToBuffer(cursor_x++, start_y, top_left);
        for (std::size_t i = 0; i < left_len; ++i)
            WriteToBuffer(cursor_x++, start_y, horizontal);

        // Right corner first, then title, then left corner (flipped visually)
        WriteToBuffer(cursor_x++, start_y, top_right); // visually left of title

        for (wchar_t ch : clean_title)
            WriteToBuffer(cursor_x++, start_y, ch);

        WriteToBuffer(cursor_x++, start_y, top_left); // visually right of title

        for (std::size_t i = 0; i < right_len; ++i)
            WriteToBuffer(cursor_x++, start_y, horizontal);

        WriteToBuffer(cursor_x, start_y, top_right);
    }
    else {
        // Standard top border
        WriteToBuffer(start_x, start_y, top_left);
        for (std::size_t i = 0; i < content_width; ++i)
            WriteToBuffer(start_x + 1 + i, start_y, horizontal);
        WriteToBuffer(start_x + 1 + content_width, start_y, top_right);
    }
    ++y; // move to content line

    // Content lines
    for (const auto& line : lines) {
        std::wstring stripped = StripAnsiCodes(line);
        std::wstring content = stripped;

        if (content.length() > content_width)
            content = content.substr(0, content_width);

        std::size_t padding = content_width - content.length();
        std::size_t pad_left = center_text ? padding / 2 : 0;
        std::size_t pad_right = padding - pad_left;

        std::size_t cursor_x = start_x;

        WriteToBuffer(cursor_x++, y, vertical);
        for (std::size_t i = 0; i < pad_left; ++i)
            WriteToBuffer(cursor_x++, y, L' ');
        for (wchar_t ch : content)
            WriteToBuffer(cursor_x++, y, ch);
        for (std::size_t i = 0; i < pad_right; ++i)
            WriteToBuffer(cursor_x++, y, L' ');
        WriteToBuffer(cursor_x, y, vertical);
        ++y;
    }

    // Bottom border
    WriteToBuffer(start_x, y, bottom_left);
    for (std::size_t i = 0; i < content_width; ++i)
        WriteToBuffer(start_x + 1 + i, y, horizontal);
    WriteToBuffer(start_x + 1 + content_width, y, bottom_right);
}

void TerminalUI::DrawUnicodeBox(const std::vector<std::wstring>& lines, std::size_t box_width, bool center_text) {
    if (box_width < 4) box_width = 4;

    const wchar_t* top_left = L"\u256D";
    const wchar_t* top_right = L"\u256E";
    const wchar_t* bottom_left = L"\u2570";
    const wchar_t* bottom_right = L"\u256F";
    const wchar_t* horizontal = L"\u2500";
    const wchar_t* vertical = L"\u2502";

    std::size_t content_width = box_width - 2;

    std::wprintf(L"%ls", top_left);
    for (std::size_t i = 0; i < content_width; ++i) std::wprintf(L"%ls", horizontal);
    std::wprintf(L"%ls\n", top_right);

    for (const auto& line : lines) {
        std::wstring content = line;

        if (VisibleLength(content) > content_width) {
            content = content.substr(0, content_width);
        }

        std::size_t padding = content_width - VisibleLength(content);
        std::size_t pad_left = center_text ? padding / 2 : 0;
        std::size_t pad_right = padding - pad_left;

        std::wprintf(L"%ls%*ls%ls%*ls%ls\n",
            vertical,
            static_cast<int>(pad_left), L"",
            content.c_str(),
            static_cast<int>(pad_right), L"",
            vertical
        );
    }

    std::wprintf(L"%ls", bottom_left);
    for (std::size_t i = 0; i < content_width; ++i) std::wprintf(L"%ls", horizontal);
    std::wprintf(L"%ls\n", bottom_right);
}

std::vector<std::wstring> TerminalUI::ToWStringVector(const std::vector<std::string>& StrVec) {
    std::vector<std::wstring> result;
    result.reserve(StrVec.size());

    for (const auto& str : StrVec) {
        int wideLen = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
        if (wideLen > 0) {
            std::wstring wstr(wideLen - 1, 0); // exclude null terminator
            MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstr[0], wideLen);
            result.push_back(std::move(wstr));
        }
        else {
            result.push_back(L"[Invalid UTF-8]");
        }
    }

    return result;
}

std::vector<std::wstring> ToWStringVectorStripped(const std::vector<std::string>& strVec) {
    std::vector<std::wstring> result;
    result.reserve(strVec.size());

    for (const auto& str : strVec) {
        std::string cleaned;
        for (unsigned char ch : str) {
            if (ch >= 32 || ch == '\t' || ch == '\n') {
                cleaned += ch;
            }
        }

        int wideLen = MultiByteToWideChar(CP_UTF8, 0, cleaned.c_str(), -1, nullptr, 0);
        if (wideLen > 0) {
            std::wstring wstr(wideLen - 1, 0);
            MultiByteToWideChar(CP_UTF8, 0, cleaned.c_str(), -1, &wstr[0], wideLen);
            result.push_back(std::move(wstr));
        }
        else {
            result.push_back(L"[Invalid UTF-8]");
        }
    }

    return result;
}

std::vector<std::wstring> TerminalUI::ToWStringVector(const std::deque<std::string>& strVec) {
    std::vector<std::wstring> result;
    result.reserve(strVec.size());

    for (const auto& str : strVec) {
        std::string cleaned = str;
        for (int i = 0; i < str.size(); i++) {
            if (cleaned[i] == '\n') {
                cleaned[i] = ' ';
            }
        }

        int wideLen = MultiByteToWideChar(CP_UTF8, 0, cleaned.c_str(), -1, nullptr, 0);
        if (wideLen > 0) {
            std::wstring wstr(wideLen - 1, 0);
            MultiByteToWideChar(CP_UTF8, 0, cleaned.c_str(), -1, &wstr[0], wideLen);
            result.push_back(std::move(wstr));
        }
        else {
            result.push_back(L"[Invalid UTF-8]");
        }
    }

    return result;
}

std::wstring Reg64Diff(const std::wstring& name, std::uint64_t prev, std::uint64_t post) {
    std::wstring state = fmt::format(L"{:016x}", post);
    if (prev != post) {
        state = L"\x1b[31m" + state + L"\x1b[0m";  // Red
    }

    return fmt::format(L"{}={}", name, state);
}

void TerminalUI::FlushRenderBufferToConsole() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    //
    // Prepare emulator cpu state.
    // Set console output to UTF-8 (affects narrow I/O)
    //
    std::print("\x1b[2J\x1b[H");

    for (const auto& row : RenderBuffer_) {
        std::wstring line;
        for (auto ch : row) {
            line += static_cast<wchar_t>(ch);
        }
        
        DWORD written;

        WriteConsoleW(hConsole, line.c_str(), static_cast<DWORD>(line.length()), &written, nullptr);
        WriteConsoleW(hConsole, L"\n", 1, &written, nullptr);
    }

    std::fflush(stdout);
}

std::wstring ToWString(const std::string& str) {
    if (str.empty()) return std::wstring();

    int wide_len = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
    if (wide_len == 0) return std::wstring();

    std::wstring wstr(wide_len - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstr[0], wide_len);

    return wstr;
}

void TerminalUI::RenderFrame() {
    for (auto& row : RenderBuffer_)
        row.fill(L' ');

	const auto& InstructionBuffer = g_Debugger.Disassemble(g_Emulator.Rip(), 10);
    const auto& RegState = g_Debugger.GetDefaultRegisterState();

#define REG64_DIFF(Name, _Reg_) \
    Reg64Diff(L#Name, RegState._Reg_, PrevRegState_._Reg_)

    std::vector<std::wstring> RegContextState;
    RegContextState.push_back(fmt::format(fmt::runtime(L"{} {} {}"),
        REG64_DIFF(rax, Rax), REG64_DIFF(rbx, Rbx), REG64_DIFF(rcx, Rcx)));
    RegContextState.push_back(fmt::format(fmt::runtime(L"{} {} {}"),
        REG64_DIFF(rdx, Rdx), REG64_DIFF(rsi, Rsi), REG64_DIFF(rdi, Rdi)));
    RegContextState.push_back(fmt::format(fmt::runtime(L"{} {} {}"),
        REG64_DIFF(rip, Rip), REG64_DIFF(rsp, Rsp), REG64_DIFF(rbp, Rbp)));
    RegContextState.push_back(fmt::format(fmt::runtime(L" {}  {} {}"),
        REG64_DIFF(r8, R8), REG64_DIFF(r9, R9), REG64_DIFF(r10, R10)));
    RegContextState.push_back(fmt::format(fmt::runtime(L"{} {} {}"),
        REG64_DIFF(r11, R11), REG64_DIFF(r12, R12), REG64_DIFF(r13, R13)));
    RegContextState.push_back(fmt::format(fmt::runtime(L"{} {}"),
        REG64_DIFF(r14, R14), REG64_DIFF(r15, R15)));
    RegContextState.push_back(fmt::format(fmt::runtime(L"cs={:04x}  ss={:04x}  ds={:04x}  es={:04x}  fs={:04x}  gs={:04x}             efl={:08x}"),
        RegState.Cs, RegState.Ss, RegState.Ds, RegState.Es, RegState.Fs, RegState.Gs, RegState.Rflags));
    
    const auto& Lines = g_Emulator.GetBreakpoints();
    std::vector<std::wstring> BreakpointInfo; 
    BreakpointInfo.reserve(Lines.size());

    int Count = 0;
    for (const auto& [Id, Address] : Lines) {
        if (Count > 18) {
            break;
        }

        auto NameIfAvail = ToWString(g_Debugger.GetName(Address, true));

        BreakpointInfo.push_back(fmt::format(L"{}  {:016x}{}",
            Id, Address, 
            NameIfAvail.empty() ? L"" : fmt::format(L" ({})", NameIfAvail)));

        Count += 1;
    }
    
    if (Lines.size() <= 19) {
        for (int i = 0; i < 19 - Lines.size(); i++) {
            BreakpointInfo.push_back(L"");
        }
    }

#undef min

    auto CommandOutputs = g_OutputCb.GetOutputBuffer();
    auto CommandOutputPad = std::vector<std::string>(17);
    for (int i = 0; i < std::min(CommandOutputs.size(), 17ull); i++) {
        CommandOutputPad[i] = CommandOutputs[i];
    }

    DrawUnicodeBoxToBuffer(0, 0, RegContextState, 87, false, L"Registers");

    DrawUnicodeBoxToBuffer(0, 9, ToWStringVector(InstructionBuffer), 87, false, 
        g_Emulator.GetExecutionDirection() == ExecutionVector::Foward ? L"Foward \u2193" : L"Backward \u2191");

    DrawUnicodeBoxToBuffer(88, 0, BreakpointInfo, 52, false, L"Breakpoints");

    DrawUnicodeBoxToBuffer(0, 21, ToWStringVector(CommandOutputPad), 140, false, L"Command Outputs");

    FlushRenderBufferToConsole();

    PrevRegState_ = RegState;
}

StdioOutputCallbacks g_OutputCb;
STDMETHODIMP
StdioOutputCallbacks::QueryInterface(
    THIS_
    IN REFIID InterfaceId,
    OUT PVOID* Interface
)
{
    *Interface = NULL;
    if (IsEqualIID(InterfaceId, __uuidof(IUnknown)) ||
        IsEqualIID(InterfaceId, __uuidof(IDebugOutputCallbacks)))
    {
        *Interface = (IDebugOutputCallbacks*)this;
        AddRef();
        return S_OK;
    }
    else
    {
        return E_NOINTERFACE;
    }
}
STDMETHODIMP_(ULONG)
StdioOutputCallbacks::AddRef(
    THIS
)
{
    return 1;
}
STDMETHODIMP_(ULONG)
StdioOutputCallbacks::Release(
    THIS
)
{
    return 0;
}
STDMETHODIMP
StdioOutputCallbacks::Output(
    THIS_
    IN ULONG Mask,
    IN PCSTR Text
)
{
    UNREFERENCED_PARAMETER(Mask);

    std::istringstream stream(std::string{ Text });
    std::string line;

    while (std::getline(stream, line)) {
        if (!line.starts_with("kd>")) {
            m_OutputBuffer.push_back(line);
        }

        if (m_OutputBuffer.size() > 16) {
            m_OutputBuffer.pop_front();
        }
    }

    return S_OK;
}

void StdioOutputCallbacks::InitOutPutBuffer()
{
    m_OutputBuffer.clear();
}