#pragma once
// PacRipper Pac-Man graphics ROM exact codec
// Created by Jacob Hodgkins

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pacripper {

struct GraphicsBitOwner {
    std::size_t romBitOffset = 0;
    std::size_t romByteOffset = 0;
    std::uint8_t romBitFromMsb = 0;
    std::uint16_t objectId = 0;
    std::uint8_t x = 0;
    std::uint8_t y = 0;
    std::uint8_t pixelBit = 0; // 1=MSB of 2-bpp pixel, 0=LSB
};

class PacmanGraphicsCodec {
public:
    using CharacterPixels = std::array<std::array<std::uint8_t,64>,256>;
    using SpritePixels = std::array<std::array<std::uint8_t,256>,64>;

    static bool decodeCharacters(const std::vector<std::uint8_t>& rom, CharacterPixels& out,
                                 std::vector<GraphicsBitOwner>* owners, std::string& error);
    static bool encodeCharacters(const CharacterPixels& pixels, std::vector<std::uint8_t>& out,
                                 std::string& error);
    static bool decodeSprites(const std::vector<std::uint8_t>& rom, SpritePixels& out,
                              std::vector<GraphicsBitOwner>* owners, std::string& error);
    static bool encodeSprites(const SpritePixels& pixels, std::vector<std::uint8_t>& out,
                              std::string& error);

    static std::size_t characterBitOffset(std::uint16_t code, int x, int y, std::uint8_t pixelBit);
    static std::size_t spriteBitOffset(std::uint16_t code, int x, int y, std::uint8_t pixelBit);
};

} // namespace pacripper
