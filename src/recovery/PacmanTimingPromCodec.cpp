// PacRipper Pac-Man 82s126.3m sound timing/control PROM codec
// Created by Jacob Hodgkins
#include "PacmanTimingPromCodec.h"

namespace pacripper {

bool PacmanTimingPromCodec::decode(const std::vector<std::uint8_t>& prom,
                                   Entries& entries,
                                   std::vector<TimingPromBitOwner>* owners,
                                   std::string& error) {
    if (prom.size() != PromSize) {
        error = "sound timing PROM size mismatch: expected 256 bytes";
        return false;
    }
    if (owners) owners->clear();
    for (std::size_t i = 0; i < entries.size(); ++i) {
        auto& entry = entries[i];
        entry = {};
        entry.address = static_cast<std::uint16_t>(i);
        entry.timingPhase = static_cast<std::uint8_t>(i & 0x3Fu);
        entry.wr0 = static_cast<std::uint8_t>((i >> 6) & 1u);
        entry.a7 = static_cast<std::uint8_t>((i >> 7) & 1u);
        entry.hardwareAddressReachable = entry.a7 == 0u;
        entry.controlNibble = static_cast<std::uint8_t>(prom[i] & 0x0Fu);
        for (unsigned bit = 0; bit < 4u; ++bit) entry.controlBits[bit] = static_cast<std::uint8_t>((entry.controlNibble >> bit) & 1u);
        entry.serializedUpperNibble = static_cast<std::uint8_t>((prom[i] >> 4) & 0x0Fu);
        if (owners) {
            for (unsigned bit = 0; bit < 8u; ++bit) {
                TimingPromBitOwner owner;
                owner.romByteOffset = i;
                owner.romBitFromMsb = static_cast<std::uint8_t>(7u-bit);
                owner.romBitOffset = i*8u + owner.romBitFromMsb;
                owner.entryId = static_cast<std::uint16_t>(i);
                if (bit < 4u) {
                    owner.semanticField = entry.hardwareAddressReachable ? "sound_timing_control_output_bit" : "sound_timing_control_output_bit_at_A7_tied_low_unreachable_address";
                    owner.semanticBit = static_cast<std::uint8_t>(bit);
                } else {
                    owner.semanticField = "serialized_upper_nibble_not_part_of_82s126_4bit_output";
                    owner.semanticBit = static_cast<std::uint8_t>(bit-4u);
                }
                owners->push_back(owner);
            }
        }
    }
    error.clear();
    return true;
}

bool PacmanTimingPromCodec::encode(const Entries& entries,
                                   std::vector<std::uint8_t>& prom,
                                   std::string& error) {
    prom.assign(entries.size(),0);
    for (std::size_t i = 0; i < entries.size(); ++i) {
        const auto& entry = entries[i];
        const auto phase = static_cast<std::uint8_t>(i & 0x3Fu);
        const auto wr0 = static_cast<std::uint8_t>((i >> 6) & 1u);
        const auto a7 = static_cast<std::uint8_t>((i >> 7) & 1u);
        if (entry.address != i || entry.timingPhase != phase || entry.wr0 != wr0 || entry.a7 != a7 || entry.hardwareAddressReachable != (a7==0u)) {
            error = "sound timing source address/input/reachability mapping mismatch";
            return false;
        }
        if (entry.controlNibble > 0x0Fu || entry.serializedUpperNibble > 0x0Fu) {
            error = "sound timing source nibble outside 4-bit domain";
            return false;
        }
        std::uint8_t reconstructed = 0;
        for (unsigned bit = 0; bit < 4u; ++bit) {
            if (entry.controlBits[bit] > 1u) {
                error = "sound timing source control bit outside binary domain";
                return false;
            }
            reconstructed = static_cast<std::uint8_t>(reconstructed | static_cast<std::uint8_t>(entry.controlBits[bit] << bit));
        }
        if (reconstructed != entry.controlNibble) {
            error = "sound timing control bits disagree with control nibble";
            return false;
        }
        prom[i] = static_cast<std::uint8_t>((entry.serializedUpperNibble << 4) | entry.controlNibble);
    }
    error.clear();
    return true;
}

} // namespace pacripper
