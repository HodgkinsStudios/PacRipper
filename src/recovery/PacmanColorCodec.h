#pragma once
// PacRipper Pac-Man palette / color lookup PROM codec
// Created by Jacob Hodgkins

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pacripper {

struct ColorBitOwner {
    std::size_t romBitOffset = 0;
    std::size_t romByteOffset = 0;
    std::uint8_t romBitFromMsb = 0;
    std::uint16_t entryId = 0;
    std::string semanticField;
    std::uint8_t semanticBit = 0;
};

struct PaletteSourceEntry {
    std::uint8_t index = 0;
    // rawBits[n] owns PROM bit n (bit 0 is the 0x01 bit).
    std::array<std::uint8_t,8> rawBits{};
    std::uint8_t red = 0;
    std::uint8_t green = 0;
    std::uint8_t blue = 0;
};

struct ColorLookupSourceEntry {
    std::uint16_t address = 0;
    std::uint8_t colorGroup = 0;
    std::uint8_t pixel = 0;
    std::uint8_t paletteIndex = 0;
    // 82S126 is used as a 4-bit palette lookup. The serialized ROM
    // image is byte-addressed, so the upper nibble is preserved explicitly
    // for exact reconstruction even though the board lookup uses only the low nibble.
    std::uint8_t serializedUpperNibble = 0;
};

class PacmanColorCodec {
public:
    using PaletteEntries = std::array<PaletteSourceEntry,32>;
    using LookupEntries = std::array<ColorLookupSourceEntry,256>;

    static bool decodePalette(const std::vector<std::uint8_t>& prom,
                              PaletteEntries& entries,
                              std::vector<ColorBitOwner>* owners,
                              std::string& error);
    static bool encodePalette(const PaletteEntries& entries,
                              std::vector<std::uint8_t>& prom,
                              std::string& error);

    static bool decodeLookup(const std::vector<std::uint8_t>& prom,
                             LookupEntries& entries,
                             std::vector<ColorBitOwner>* owners,
                             std::string& error);
    static bool encodeLookup(const LookupEntries& entries,
                             std::vector<std::uint8_t>& prom,
                             std::string& error);

    static std::uint32_t argb(const PaletteSourceEntry& entry);
    static unsigned lookupAddress(std::uint8_t color,std::uint8_t pixel);
    static std::uint8_t lookupPaletteIndex(std::uint8_t serializedValue);
};

} // namespace pacripper
