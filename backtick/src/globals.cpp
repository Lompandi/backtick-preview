
#include "utils.hpp"
#include "globals.hpp"

EXT_API_VERSION g_ExtApiVersion = { 1,1,EXT_API_VERSION_NUMBER, 0 };
// 
WINDBG_EXTENSION_APIS ExtensionApis = { 0 };

bool InShadowState = false;

TerminalUI g_Tui;

std::string REGVAL::ToString() const {

    switch (Type) {
    case REGVAL_TYPE_I32:
        return std::format("{}", u.I32);
    case REGVAL_TYPE_I64:
        return std::format("{}", u.I64);
    case REGVAL_TYPE_FLOAT80: {

    }
    case REGVAL_TYPE_VF128: {
        std::string Fmt;
        for (int i = 0; i < 4; i++) {
            Fmt += std::format("{} ", u.VF128.f[i]);
        }
        Fmt.pop_back();
        return Fmt;
    }
    case REGVAL_TYPE_VF256: {
        std::string Fmt;
        for (int i = 0; i < 8; i++) {
            Fmt += std::format("{} ", u.VF256.f[i]);
        }
        Fmt.pop_back();
        return Fmt;
    }
    case REGVAL_TYPE_VF512: {
        std::string Fmt;
        for (int i = 0; i < 16; i++) {
            Fmt += std::format("{} ", u.VF512.f[i]);
        }
        Fmt.pop_back();
        return Fmt;
    }
    default:
        return "<invalid>";
    }
}

Seg_t Seg_t::FromDescriptor(std::uint64_t Selector, const std::array<std::uint8_t, 16>& Value) {
    auto Limit      = uint32_t(ExtractBits(Value, 0ull, 15ull) | (ExtractBits(Value, 48ull, 51ull) << 16));
    auto Base       = ExtractBits(Value, 16ull, 39ull) | (ExtractBits(Value, 56ull, 63ull) << 24);
    auto Present    = ExtractBit(Value, 47ull) == 1;
    auto Attr       = uint32_t(ExtractBits(Value, 40ull, 55ull));
    auto Selector16 = uint16_t(Selector);
    auto NonSystem  = ExtractBit(Value, 44ull);
    if (NonSystem == 0) {
        Base |= ExtractBits(Value, 64ull, 95ull) << 32;
    }

    auto Granularity = ExtractBit(Value, 55ull) == 1;
    auto Increment = 1;
    if (Granularity) {
        Increment = 0x1000;
    }
    auto Offset = 0;
    if (Granularity) {
        Offset = 0xfff;
    }

    Limit = Limit * Increment + Offset;

    Seg_t Ret;
    Ret.Selector = Selector16;
    Ret.Base     = Base;
    Ret.Limit    = Limit;
    Ret.Attr     = Attr;

    return Ret;
}