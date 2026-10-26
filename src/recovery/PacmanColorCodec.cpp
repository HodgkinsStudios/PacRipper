// PacRipper Pac-Man palette / color lookup PROM codec
// Created by Jacob Hodgkins
#include "PacmanColorCodec.h"

namespace pacripper {
namespace {

void deriveRgb(PaletteSourceEntry& entry) {
    const auto& b = entry.rawBits;
    const unsigned r = 0x21u*b[0] + 0x47u*b[1] + 0x97u*b[2];
    const unsigned g = 0x21u*b[3] + 0x47u*b[4] + 0x97u*b[5];
    const unsigned bl = 0x51u*b[6] + 0xAEu*b[7];
    entry.red = static_cast<std::uint8_t>(r);
    entry.green = static_cast<std::uint8_t>(g);
    entry.blue = static_cast<std::uint8_t>(bl);
}

std::string paletteField(unsigned bit) {
    if (bit < 3u) return "red_resistor_bit";
    if (bit < 6u) return "green_resistor_bit";
    return "blue_resistor_bit";
}

} // namespace

bool PacmanColorCodec::decodePalette(const std::vector<std::uint8_t>& prom,
                                     PaletteEntries& entries,
                                     std::vector<ColorBitOwner>* owners,
                                     std::string& error) {
    if (prom.size() != entries.size()) {
        error = "palette PROM size mismatch: expected 32 bytes";
        return false;
    }
    if (owners) owners->clear();
    for (std::size_t i = 0; i < entries.size(); ++i) {
        auto& entry = entries[i];
        entry = {};
        entry.index = static_cast<std::uint8_t>(i);
        const std::uint8_t raw = prom[i];
        for (unsigned bit = 0; bit < 8u; ++bit) {
            entry.rawBits[bit] = static_cast<std::uint8_t>((raw >> bit) & 1u);
            if (owners) {
                ColorBitOwner owner;
                owner.romByteOffset = i;
                owner.romBitFromMsb = static_cast<std::uint8_t>(7u-bit);
                owner.romBitOffset = i*8u + owner.romBitFromMsb;
                owner.entryId = static_cast<std::uint16_t>(i);
                owner.semanticField = paletteField(bit);
                owner.semanticBit = static_cast<std::uint8_t>(bit < 3u ? bit : bit < 6u ? bit-3u : bit-6u);
                owners->push_back(owner);
            }
        }
        deriveRgb(entry);
    }
    error.clear();
    return true;
}

bool PacmanColorCodec::encodePalette(const PaletteEntries& entries,
                                     std::vector<std::uint8_t>& prom,
                                     std::string& error) {
    prom.assign(entries.size(),0);
    for (std::size_t i = 0; i < entries.size(); ++i) {
        const auto& entry = entries[i];
        if (entry.index != i) {
            error = "palette source index mismatch";
            return false;
        }
        std::uint8_t raw = 0;
        for (unsigned bit = 0; bit < 8u; ++bit) {
            if (entry.rawBits[bit] > 1u) {
                error = "palette source bit outside binary domain";
                return false;
            }
            raw = static_cast<std::uint8_t>(raw | static_cast<std::uint8_t>(entry.rawBits[bit] << bit));
        }
        PaletteSourceEntry derived = entry;
        deriveRgb(derived);
        if (derived.red != entry.red || derived.green != entry.green || derived.blue != entry.blue) {
            error = "palette derived RGB metadata disagrees with resistor bits";
            return false;
        }
        prom[i] = raw;
    }
    error.clear();
    return true;
}

bool PacmanColorCodec::decodeLookup(const std::vector<std::uint8_t>& prom,
                                    LookupEntries& entries,
                                    std::vector<ColorBitOwner>* owners,
                                    std::string& error) {
    if (prom.size() != entries.size()) {
        error = "color lookup PROM size mismatch: expected 256 bytes";
        return false;
    }
    if (owners) owners->clear();
    for (std::size_t i = 0; i < entries.size(); ++i) {
        auto& entry = entries[i];
        entry = {};
        entry.address = static_cast<std::uint16_t>(i);
        entry.colorGroup = static_cast<std::uint8_t>((i >> 2) & 0x3Fu);
        entry.pixel = static_cast<std::uint8_t>(i & 3u);
        entry.paletteIndex = static_cast<std::uint8_t>(prom[i] & 0x0Fu);
        entry.serializedUpperNibble = static_cast<std::uint8_t>((prom[i] >> 4) & 0x0Fu);
        if (owners) {
            for (unsigned bit = 0; bit < 8u; ++bit) {
                ColorBitOwner owner;
                owner.romByteOffset = i;
                owner.romBitFromMsb = static_cast<std::uint8_t>(7u-bit);
                owner.romBitOffset = i*8u + owner.romBitFromMsb;
                owner.entryId = static_cast<std::uint16_t>(i);
                owner.semanticField = bit < 4u ? "palette_index" : "serialized_upper_nibble_preserved_for_exact_rebuild";
                owner.semanticBit = static_cast<std::uint8_t>(bit < 4u ? bit : bit-4u);
                owners->push_back(owner);
            }
        }
    }
    error.clear();
    return true;
}

bool PacmanColorCodec::encodeLookup(const LookupEntries& entries,
                                    std::vector<std::uint8_t>& prom,
                                    std::string& error) {
    prom.assign(entries.size(),0);
    for (std::size_t i = 0; i < entries.size(); ++i) {
        const auto& entry = entries[i];
        if (entry.address != i || entry.colorGroup != ((i >> 2) & 0x3Fu) || entry.pixel != (i & 3u)) {
            error = "color lookup source address/group/pixel mapping mismatch";
            return false;
        }
        if (entry.paletteIndex > 0x0Fu || entry.serializedUpperNibble > 0x0Fu) {
            error = "color lookup source nibble outside 4-bit domain";
            return false;
        }
        prom[i] = static_cast<std::uint8_t>((entry.serializedUpperNibble << 4) | entry.paletteIndex);
    }
    error.clear();
    return true;
}

std::uint32_t PacmanColorCodec::argb(const PaletteSourceEntry& entry) {
    return 0xFF000000u | (static_cast<std::uint32_t>(entry.red) << 16)
         | (static_cast<std::uint32_t>(entry.green) << 8) | entry.blue;
}

unsigned PacmanColorCodec::lookupAddress(std::uint8_t color,std::uint8_t pixel) {
    return ((static_cast<unsigned>(color) & 0x3Fu) << 2) | (pixel & 3u);
}

std::uint8_t PacmanColorCodec::lookupPaletteIndex(std::uint8_t serializedValue) {
    return static_cast<std::uint8_t>(serializedValue & 0x0Fu);
}

} // namespace pacripper
