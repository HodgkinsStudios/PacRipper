#pragma once
// PacRipper Pac-Man 82s126.1m waveform PROM codec
// Created by Jacob Hodgkins

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pacripper {

struct WaveformBitOwner {
    std::size_t romBitOffset = 0;
    std::size_t romByteOffset = 0;
    std::uint8_t romBitFromMsb = 0;
    std::uint16_t entryId = 0;
    std::uint8_t waveform = 0;
    std::uint8_t position = 0;
    std::string semanticField;
    std::uint8_t semanticBit = 0;
};

struct WaveformSourceEntry {
    std::uint16_t address = 0;
    std::uint8_t waveform = 0;
    std::uint8_t position = 0;
    std::uint8_t sampleNibble = 0;
    std::int8_t signedSample = 0;
    // The physical 82S126 is 4-bit wide. Dumps are serialized as bytes, so
    // retain the upper nibble explicitly for deterministic byte-exact inverse
    // reconstruction without assigning it a hardware meaning.
    std::uint8_t serializedUpperNibble = 0;
};

class PacmanWaveformCodec {
public:
    static constexpr std::size_t PromSize = 256;
    static constexpr std::size_t WaveformCount = 8;
    static constexpr std::size_t PositionsPerWaveform = 32;
    using Entries = std::array<WaveformSourceEntry,PromSize>;

    static bool decode(const std::vector<std::uint8_t>& prom,
                       Entries& entries,
                       std::vector<WaveformBitOwner>* owners,
                       std::string& error);
    static bool encode(const Entries& entries,
                       std::vector<std::uint8_t>& prom,
                       std::string& error);

    static std::size_t address(std::uint8_t waveform,std::uint8_t position);
    static std::int8_t signedSample(std::uint8_t serializedValue);
};

} // namespace pacripper
