
#include "utils.hpp"

#include <psapi.h>

#include <fstream>

#include "globals.hpp"

#define INRANGE(x, a, b) (x >= a && x <= b)
#define GET_BYTE(x) (GET_BITS(x[0]) << 4 | GET_BITS(x[1]))
#define GET_BITS(x) (INRANGE((x & (~0x20)), 'A', 'F') ? ((x & (~0x20)) - 'A' + 0xa) : (INRANGE(x, '0', '9') ? x - '0' : 0))

uintptr_t ScanForSignature(const char* Module, const char* Signature) {
	const char* pattern = Signature;
	uintptr_t firstMatch = 0;
	static const auto rangeStart = (uintptr_t)GetModuleHandleA(Module);
	static MODULEINFO miModInfo;
	static bool init = false;
	if (!init) {
		init = true;
		GetModuleInformation(GetCurrentProcess(), (HMODULE)rangeStart, &miModInfo, sizeof(MODULEINFO));
	}
	static const uintptr_t rangeEnd = rangeStart + miModInfo.SizeOfImage;

	BYTE patByte = GET_BYTE(pattern);
	const char* oldPat = pattern;

	for (uintptr_t pCur = rangeStart; pCur < rangeEnd; pCur++) {
		if (!*pattern)
			return firstMatch;

		while (*(PBYTE)pattern == ' ')
			pattern++;

		if (!*pattern)
			return firstMatch;

		if (oldPat != pattern) {
			oldPat = pattern;
			if (*(PBYTE)pattern != '\?')
				patByte = GET_BYTE(pattern);
		}

		if (*(PBYTE)pattern == '\?' || *(BYTE*)pCur == patByte) {
			if (!firstMatch)
				firstMatch = pCur;

			if (!pattern[2] || !pattern[1])
				return firstMatch;

			pattern += 2;
		}
		else {
			pattern = Signature;
			firstMatch = 0;
		}
	}

	return 0u;
}

void Hexdump(const void* data, size_t size) {
    const unsigned char* byteData = static_cast<const unsigned char*>(data);
    constexpr size_t bytesPerLine = 16;

    for (size_t i = 0; i < size; i += bytesPerLine) {
        std::print("{:08x}: ", i);

        for (size_t j = 0; j < bytesPerLine; ++j) {
            if (i + j < size) {
                std::print("{:02x} ", byteData[i + j]);
            } else {
                std::print("   ");
            }
        }

        std::print(" ");

        for (size_t j = 0; j < bytesPerLine; ++j) {
            if (i + j < size) {
                unsigned char c = byteData[i + j];
                std::print("{}", std::isprint(c) ? static_cast<char>(c) : '.');
            }
        }

        std::print("\n");
    }
}

void StripAllControlChars(std::string& s) {
	s.erase(std::remove_if(s.begin(), s.end(),
		[](unsigned char ch) {
			return (ch < 0x20 && ch != ' ');
		}),
		s.end());
}