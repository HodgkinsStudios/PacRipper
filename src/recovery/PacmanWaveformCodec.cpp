// PacRipper Pac-Man 82s126.1m waveform PROM codec
// Created by Jacob Hodgkins
#include "PacmanWaveformCodec.h"

namespace pacripper {

bool PacmanWaveformCodec::decode(const std::vector<std::uint8_t>& prom,
                                 Entries& entries,
                                 std::vector<WaveformBitOwner>* owners,
                                 std::string& error) {
    if (prom.size() != PromSize) {
        error = "waveform PROM size mismatch: expected 256 bytes";
        return false;
    }
    if (owners) owners->clear();
    for (std::size_t i = 0; i < entries.size(); ++i) {
        auto& entry = entries[i];
        entry = {};
        entry.address = static_cast<std::uint16_t>(i);
        entry.waveform = static_cast<std::uint8_t>((i >> 5) & 7u);
        entry.position = static_cast<std::uint8_t>(i & 0x1Fu);
        entry.sampleNibble = static_cast<std::uint8_t>(prom[i] & 0x0Fu);
        entry.signedSample = static_cast<std::int8_t>(static_cast<int>(entry.sampleNibble)-8);
        entry.serializedUpperNibble = static_cast<std::uint8_t>((prom[i] >> 4) & 0x0Fu);
        if (owners) {
            for (unsigned bit = 0; bit < 8u; ++bit) {
                WaveformBitOwner owner;
                owner.romByteOffset = i;
                owner.romBitFromMsb = static_cast<std::uint8_t>(7u-bit);
                owner.romBitOffset = i*8u + owner.romBitFromMsb;
                owner.entryId = static_cast<std::uint16_t>(i);
                owner.waveform = entry.waveform;
                owner.position = entry.position;
                owner.semanticField = bit < 4u ? "signed_waveform_sample_nibble" : "serialized_upper_nibble_not_part_of_82s126_4bit_output";
                owner.semanticBit = static_cast<std::uint8_t>(bit < 4u ? bit : bit-4u);
                owners->push_back(owner);
            }
        }
    }
    error.clear();
    return true;
}

bool PacmanWaveformCodec::encode(const Entries& entries,
                                 std::vector<std::uint8_t>& prom,
                                 std::string& error) {
    prom.assign(entries.size(),0);
    for (std::size_t i = 0; i < entries.size(); ++i) {
        const auto& entry = entries[i];
        if (entry.address != i || entry.waveform != ((i >> 5) & 7u) || entry.position != (i & 0x1Fu)) {
            error = "waveform source address/waveform/position mapping mismatch";
            return false;
        }
        if (entry.sampleNibble > 0x0Fu || entry.serializedUpperNibble > 0x0Fu) {
            error = "waveform source nibble outside 4-bit domain";
            return false;
        }
        if (entry.signedSample != static_cast<std::int8_t>(static_cast<int>(entry.sampleNibble)-8)) {
            error = "waveform derived signed sample disagrees with sample nibble";
            return false;
        }
        prom[i] = static_cast<std::uint8_t>((entry.serializedUpperNibble << 4) | entry.sampleNibble);
    }
    error.clear();
    return true;
}

std::size_t PacmanWaveformCodec::address(std::uint8_t waveform,std::uint8_t position) {
    return (static_cast<std::size_t>(waveform & 7u) << 5) | (position & 0x1Fu);
}

std::int8_t PacmanWaveformCodec::signedSample(std::uint8_t serializedValue) {
    return static_cast<std::int8_t>(static_cast<int>(serializedValue & 0x0Fu)-8);
}

} // namespace pacripper
