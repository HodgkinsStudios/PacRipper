#pragma once
// PacRipper deterministic ROM rebuilder integrated deterministic ROM rebuilder
// Created by Jacob Hodgkins

#include "ExactRomReconstruction.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pacripper {

struct RomRebuildMismatchRecord {
    std::size_t id=0;
    std::uint16_t address=0;
    std::uint8_t originalByte=0;
    std::uint8_t rebuiltByte=0;
    RomReconstructionOwnerKind ownerKind=RomReconstructionOwnerKind::Unowned;
    std::size_t sourceId=static_cast<std::size_t>(-1);
    std::string sourceText;
    std::string provenance;
};

struct RomRebuilderStats {
    std::size_t originalBytes=0;
    std::size_t rebuiltBytes=0;
    std::size_t ledgerRecords=0;
    std::size_t ownedAddresses=0;
    std::size_t missingAddresses=0;
    std::size_t duplicateAddresses=0;
    std::size_t outOfRangeRecords=0;
    std::size_t matchingBytes=0;
    std::size_t mismatchCount=0;
    std::string originalSha256;
    std::string rebuiltSha256;
    std::string repeatedSha256;
    bool canonicalInput=false;
    bool ownershipComplete=false;
    bool sizeMatch=false;
    bool sha256Match=false;
    bool deterministicRepeat=false;
    bool safeToWrite=false;
    bool verified=false;
};

struct RomRebuildResult {
    std::vector<std::uint8_t> rebuiltBytes;
    std::vector<std::uint8_t> repeatedBytes;
    std::vector<RomRebuildMismatchRecord> mismatches;
    RomRebuilderStats stats;
    std::string diagnostic;
};

class RomRebuilder {
public:
    static constexpr std::size_t kCanonicalProgramSize=0x4000;

    static const char* canonicalProgramSha256();
    static std::string sha256(const std::vector<std::uint8_t>& bytes);

    // Reconstruction consumes only ledger ownership/emitted-byte facts. The original
    // program is supplied separately and is used only for canonical-revision safety
    // and post-rebuild verification.
    static RomRebuildResult rebuildAndVerify(
        const std::vector<std::uint8_t>& originalProgram,
        const std::vector<RomReconstructionReconstructionByteRecord>& ledger);

    static bool writeBinary(const std::string& path,const std::vector<std::uint8_t>& bytes,std::string& error);
    static std::vector<std::string> reportLines(const RomRebuildResult& result);
};

} // namespace pacripper
