// PacRipper Pac-Man graphics ROM exact codec
// Created by Jacob Hodgkins
#include "PacmanGraphicsCodec.h"

#include <sstream>

namespace pacripper {
namespace {

std::uint8_t bitAt(const std::vector<std::uint8_t>& data, std::size_t bitOffset) {
    const std::size_t byteIndex = bitOffset >> 3;
    if (byteIndex >= data.size()) return 0;
    return (data[byteIndex] & static_cast<std::uint8_t>(0x80u >> (bitOffset & 7u))) ? 1u : 0u;
}

void setBit(std::vector<std::uint8_t>& data, std::size_t bitOffset, bool value) {
    const std::size_t byteIndex = bitOffset >> 3;
    const auto mask = static_cast<std::uint8_t>(0x80u >> (bitOffset & 7u));
    if (value) data[byteIndex] = static_cast<std::uint8_t>(data[byteIndex] | mask);
    else data[byteIndex] = static_cast<std::uint8_t>(data[byteIndex] & static_cast<std::uint8_t>(~mask));
}

void addOwner(std::vector<GraphicsBitOwner>* owners, std::size_t bitOffset,
              std::uint16_t objectId, int x, int y, std::uint8_t pixelBit) {
    if (!owners) return;
    GraphicsBitOwner o;
    o.romBitOffset = bitOffset;
    o.romByteOffset = bitOffset >> 3;
    o.romBitFromMsb = static_cast<std::uint8_t>(bitOffset & 7u);
    o.objectId = objectId;
    o.x = static_cast<std::uint8_t>(x);
    o.y = static_cast<std::uint8_t>(y);
    o.pixelBit = pixelBit;
    owners->push_back(o);
}

} // namespace

std::size_t PacmanGraphicsCodec::characterBitOffset(std::uint16_t code, int x, int y,
                                                    std::uint8_t pixelBit) {
    static const int charX[8] = {64,65,66,67,0,1,2,3};
    const std::size_t base = static_cast<std::size_t>(code) * 16u * 8u;
    const std::size_t p0 = base + static_cast<std::size_t>(y) * 8u
                         + static_cast<std::size_t>(charX[x]);
    return pixelBit ? p0 : p0 + 4u;
}

std::size_t PacmanGraphicsCodec::spriteBitOffset(std::uint16_t code, int x, int y,
                                                 std::uint8_t pixelBit) {
    static const int spriteX[16] = {64,65,66,67,128,129,130,131,192,193,194,195,0,1,2,3};
    const std::size_t yoff = y < 8
        ? static_cast<std::size_t>(y) * 8u
        : 32u * 8u + static_cast<std::size_t>(y - 8) * 8u;
    const std::size_t base = static_cast<std::size_t>(code) * 64u * 8u;
    const std::size_t p0 = base + yoff + static_cast<std::size_t>(spriteX[x]);
    return pixelBit ? p0 : p0 + 4u;
}

bool PacmanGraphicsCodec::decodeCharacters(const std::vector<std::uint8_t>& rom,
                                           CharacterPixels& out,
                                           std::vector<GraphicsBitOwner>* owners,
                                           std::string& error) {
    if (rom.size() != 0x1000) {
        std::ostringstream s;
        s << "character ROM must be 4096 bytes, got " << rom.size();
        error = s.str();
        return false;
    }
    for (auto& r : out) r.fill(0);
    if (owners) {
        owners->clear();
        owners->reserve(0x1000u * 8u);
    }
    for (std::uint16_t code = 0; code < 256; ++code) {
        for (int y = 0; y < 8; ++y) {
            for (int x = 0; x < 8; ++x) {
                const auto msb = characterBitOffset(code, x, y, 1);
                const auto lsb = characterBitOffset(code, x, y, 0);
                out[code][static_cast<std::size_t>(y * 8 + x)] =
                    static_cast<std::uint8_t>((bitAt(rom, msb) << 1) | bitAt(rom, lsb));
                addOwner(owners, msb, code, x, y, 1);
                addOwner(owners, lsb, code, x, y, 0);
            }
        }
    }
    error.clear();
    return true;
}

bool PacmanGraphicsCodec::encodeCharacters(const CharacterPixels& pixels,
                                           std::vector<std::uint8_t>& out,
                                           std::string& error) {
    out.assign(0x1000, 0);
    for (std::uint16_t code = 0; code < 256; ++code) {
        for (int y = 0; y < 8; ++y) {
            for (int x = 0; x < 8; ++x) {
                const auto v = pixels[code][static_cast<std::size_t>(y * 8 + x)];
                if (v > 3) {
                    error = "character pixel outside 2-bpp domain";
                    return false;
                }
                setBit(out, characterBitOffset(code, x, y, 1), (v & 2u) != 0);
                setBit(out, characterBitOffset(code, x, y, 0), (v & 1u) != 0);
            }
        }
    }
    error.clear();
    return true;
}

bool PacmanGraphicsCodec::decodeSprites(const std::vector<std::uint8_t>& rom,
                                        SpritePixels& out,
                                        std::vector<GraphicsBitOwner>* owners,
                                        std::string& error) {
    if (rom.size() != 0x1000) {
        std::ostringstream s;
        s << "sprite ROM must be 4096 bytes, got " << rom.size();
        error = s.str();
        return false;
    }
    for (auto& r : out) r.fill(0);
    if (owners) {
        owners->clear();
        owners->reserve(0x1000u * 8u);
    }
    for (std::uint16_t code = 0; code < 64; ++code) {
        for (int y = 0; y < 16; ++y) {
            for (int x = 0; x < 16; ++x) {
                const auto msb = spriteBitOffset(code, x, y, 1);
                const auto lsb = spriteBitOffset(code, x, y, 0);
                out[code][static_cast<std::size_t>(y * 16 + x)] =
                    static_cast<std::uint8_t>((bitAt(rom, msb) << 1) | bitAt(rom, lsb));
                addOwner(owners, msb, code, x, y, 1);
                addOwner(owners, lsb, code, x, y, 0);
            }
        }
    }
    error.clear();
    return true;
}

bool PacmanGraphicsCodec::encodeSprites(const SpritePixels& pixels,
                                        std::vector<std::uint8_t>& out,
                                        std::string& error) {
    out.assign(0x1000, 0);
    for (std::uint16_t code = 0; code < 64; ++code) {
        for (int y = 0; y < 16; ++y) {
            for (int x = 0; x < 16; ++x) {
                const auto v = pixels[code][static_cast<std::size_t>(y * 16 + x)];
                if (v > 3) {
                    error = "sprite pixel outside 2-bpp domain";
                    return false;
                }
                setBit(out, spriteBitOffset(code, x, y, 1), (v & 2u) != 0);
                setBit(out, spriteBitOffset(code, x, y, 0), (v & 1u) != 0);
            }
        }
    }
    error.clear();
    return true;
}

} // namespace pacripper
