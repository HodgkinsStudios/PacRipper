// PacRipper semantic-oracle analysis test-only independent Z80 oracle source.
// Adapted from an earlier Pac-Man emulator project created and owned by Jacob Hodgkins.
// Validation/corroboration only; never static disassembly proof.
#pragma once

#include <cstdint>

namespace pacemu {

using u8  = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
using s8  = std::int8_t;
using s16 = std::int16_t;
using s32 = std::int32_t;
using s64 = std::int64_t;

struct Rgb {
    u8 r;
    u8 g;
    u8 b;
};

} // namespace pacemu
