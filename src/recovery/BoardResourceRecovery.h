#pragma once
// PacRipper Complete Board ROM/PROM Recovery — graphics, color, and audio recovery
// Created by Jacob Hodgkins

#include "rom/RomSet.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pacripper {

struct BoardGraphicsStats {
    std::size_t activeCanonicalFiles = 0;
    std::size_t activeNonProgramFiles = 0;
    std::size_t excludedArchiveMembers = 0;
    std::size_t characterObjects = 0;
    std::size_t spriteObjects = 0;
    std::size_t characterOwnedBits = 0;
    std::size_t spriteOwnedBits = 0;
    bool characterOwnershipComplete = false;
    bool spriteOwnershipComplete = false;
    bool characterRoundTrip = false;
    bool spriteRoundTrip = false;
    bool exportedSourceRoundTrip = false;
    bool rendererCanonicalReference = false;
    std::uint64_t rendererNormalHash = 0;
    std::uint64_t rendererFlipHash = 0;
    bool allPassed = false;
};

struct BoardGraphicsResult {
    BoardGraphicsStats stats;
    std::string characterSha256;
    std::string spriteSha256;
    std::vector<std::string> diagnostics;
};

struct BoardColorStats {
    std::size_t paletteEntries = 0;
    std::size_t colorLookupEntries = 0;
    std::size_t paletteOwnedBits = 0;
    std::size_t colorLookupOwnedBits = 0;
    std::size_t colorLookupUpperNibbleNonzeroEntries = 0;
    bool paletteOwnershipComplete = false;
    bool colorLookupOwnershipComplete = false;
    bool paletteRoundTrip = false;
    bool colorLookupRoundTrip = false;
    bool exportedSourceRoundTrip = false;
    bool rendererCanonicalReference = false;
    std::uint64_t rendererNormalHash = 0;
    std::uint64_t rendererFlipHash = 0;
    bool allPassed = false;
};

struct BoardColorResult {
    BoardGraphicsResult graphics;
    BoardColorStats stats;
    std::string paletteSha256;
    std::string colorLookupSha256;
    std::vector<std::string> diagnostics;
};


struct BoardAudioStats {
    std::size_t waveformEntries = 0;
    std::size_t waveformOwnedBits = 0;
    std::size_t waveformUpperNibbleNonzeroEntries = 0;
    bool waveformOwnershipComplete = false;
    bool waveformRoundTrip = false;
    bool exportedWaveformSourceRoundTrip = false;
    bool audioCanonicalReference = false;
    std::uint64_t audioTonePcmHash = 0;
    std::uint64_t audioTransitionPcmHash = 0;
    int audioPeakAmplitude = 0;

    std::size_t timingEntries = 0;
    std::size_t timingOwnedBits = 0;
    std::size_t timingReachableEntries = 0;
    std::size_t timingUnreachableA7Entries = 0;
    std::size_t timingUpperNibbleNonzeroEntries = 0;
    std::size_t timingUnreachableNonzeroControlEntries = 0;
    bool timingOwnershipComplete = false;
    bool timingRoundTrip = false;
    bool exportedTimingSourceRoundTrip = false;
    bool timingRoleEvidenceEstablished = false;
    bool allPassed = false;
};

struct BoardAudioResult {
    BoardColorResult color;
    BoardAudioStats stats;
    std::string waveformSha256;
    std::string timingPromSha256;
    std::vector<std::string> diagnostics;
};

class BoardResourceRecovery {
public:
    static bool exportGraphics(const RomSet& set,const std::string& outDir,BoardGraphicsResult& result,std::string& error);
    static bool verifyGraphicsExport(const RomSet& set,const std::string& outDir,BoardGraphicsResult& result,std::string& error);
    static std::vector<std::string> reportLines(const BoardGraphicsResult& result);

    static bool exportColor(const RomSet& set,const std::string& outDir,BoardColorResult& result,std::string& error);
    static bool verifyColorExport(const RomSet& set,const std::string& outDir,BoardColorResult& result,std::string& error);
    static std::vector<std::string> reportLines(const BoardColorResult& result);

    static bool exportAudio(const RomSet& set,const std::string& outDir,BoardAudioResult& result,std::string& error);
    static bool verifyAudioExport(const RomSet& set,const std::string& outDir,BoardAudioResult& result,std::string& error);
    static std::vector<std::string> reportLines(const BoardAudioResult& result);
};

} // namespace pacripper
