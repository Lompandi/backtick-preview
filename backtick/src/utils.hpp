#pragma once

#include <cstdint>
#include <filesystem>

#include "debugger.hpp"

namespace fs = std::filesystem;

constexpr std::uint64_t AlignPage(std::uint64_t Address) { return Address & ~0xfff; }

void Hexdump(const void* data, size_t size);

struct CpuState_t;

uintptr_t ScanForSignature(const char* szModule, const char* szSignature);

template <typename T>
bool ExtractBit(const T& value, std::size_t bitPos) {
    static_assert(std::is_trivially_copyable<T>::value, "T must be trivially copyable");

    constexpr std::size_t totalBits = sizeof(T) * 8;
    if (bitPos >= totalBits) {
        throw std::out_of_range("Bit position out of range");
    }

    unsigned char bytes[sizeof(T)];
    std::memcpy(bytes, &value, sizeof(T));

    std::size_t byteIndex = bitPos / 8;
    std::size_t bitIndex = bitPos % 8;

    return (bytes[byteIndex] >> bitIndex) & 1;
}

template <typename T>
uint64_t ExtractBits(const T& value, size_t startBit, size_t endBit) {
    static_assert(std::is_trivially_copyable<T>::value, "T must be trivially copyable");

    constexpr size_t totalBits = sizeof(T) * 8;
    if (startBit > endBit || endBit >= totalBits) {
        throw std::out_of_range("Invalid bit range");
    }

    unsigned char bytes[sizeof(T)];
    std::memcpy(bytes, &value, sizeof(T));

    uint64_t result = 0;
    size_t bitIndex = 0;

    for (size_t i = startBit; i <= endBit; ++i, ++bitIndex) {
        size_t byteIndex = i / 8;
        size_t bitInByte = i % 8;
        uint64_t bit = (bytes[byteIndex] >> bitInByte) & 1;
        result |= (bit << bitIndex);
    }

    return result;
}

void StripAllControlChars(std::string& s);