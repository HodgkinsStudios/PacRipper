#pragma once
// PacRipper Pac-Man 82s126.3m sound timing/control PROM codec
// Created by Jacob Hodgkins

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pacripper {

struct TimingPromBitOwner {
    std::size_t romBitOffset = 0;
    std::size_t romByteOffset = 0;
    std::uint8_t romBitFromMsb = 0;
    std::uint16_t entryId = 0;
    std::string semanticField;
    std::uint8_t semanticBit = 0;
};

struct TimingPromSourceEntry {
    std::uint16_t address = 0;
    // Midway's troubleshooting manual documents A0..A5 as the 1H..32H
    // timing phase inputs, A6 as WR0, and A7 tied low on the board.
    std::uint8_t timingPhase = 0;
    std::uint8_t wr0 = 0;
    std::uint8_t a7 = 0;
    bool hardwareAddressReachable = false;
    // Low nibble is the 82S126's four-bit timing/control word. Exact per-line
    // dump-bit-to-board-control assignment is not invented where documentation
    // only establishes the word's collective control role.
    std::uint8_t controlNibble = 0;
    std::array<std::uint8_t,4> controlBits{};
    std::uint8_t serializedUpperNibble = 0;
};

class PacmanTimingPromCodec {
public:
    static constexpr std::size_t PromSize = 256;
    using Entries = std::array<TimingPromSourceEntry,PromSize>;

    static bool decode(const std::vector<std::uint8_t>& prom,
                       Entries& entries,
                       std::vector<TimingPromBitOwner>* owners,
                       std::string& error);
    static bool encode(const Entries& entries,
                       std::vector<std::uint8_t>& prom,
                       std::string& error);
};

} // namespace pacripper
