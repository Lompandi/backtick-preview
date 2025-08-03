#pragma once

#include <array>
#include <deque>
#include <vector>

#include "debugger.hpp"

class TerminalUI {
public:
	TerminalUI() { SetConsoleOutputCP(CP_UTF8); }

	void RenderFrame();
	
	void WriteToBuffer(std::size_t x, std::size_t y, wchar_t ch) {
		RenderBuffer_[y][x] = ch;
	}

	void DrawUnicodeBox(const std::vector<std::wstring>& lines, std::size_t box_width = 72, bool center_text = false);

	void DrawUnicodeBoxToBuffer(
		std::size_t start_x,
		std::size_t start_y,
		const std::vector<std::wstring>& lines,
		std::size_t box_width,
		bool center_text,
		const std::wstring& title
	);

	void FlushRenderBufferToConsole();

	std::vector<std::wstring> ToWStringVector(const std::vector<std::string>& StrVec);

    std::vector<std::wstring> ToWStringVector(const std::deque<std::string>& strVec);

private:
	// [y][x]
	std::array<std::array<uint16_t, 140>, 40> RenderBuffer_;
	DefaultRegistersState PrevRegState_;
};

class StdioOutputCallbacks : public IDebugOutputCallbacks
{
private:
    std::deque<std::string> m_OutputBuffer;
public:
    void InitOutPutBuffer();

    const std::deque<std::string>& GetOutputBuffer() {
        return m_OutputBuffer;
    }

    std::deque<std::string> SplitLines(const std::string& input);

    void ClearOutPutBuffer() {
        m_OutputBuffer.clear();
    }

    STDMETHOD(QueryInterface)(
        THIS_
        IN REFIID InterfaceId,
        OUT PVOID* Interface
        );

    STDMETHOD_(ULONG, AddRef)(
        THIS
        );

    STDMETHOD_(ULONG, Release)(
        THIS
        );
    
    STDMETHOD(Output)(
        THIS_
        IN ULONG Mask,
        IN PCSTR Text
        );
};
extern StdioOutputCallbacks g_OutputCb;