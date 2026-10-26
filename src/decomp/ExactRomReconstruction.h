#pragma once
// PacRipper exact ROM reconstruction deterministic bit-exact ROM reconstruction proof
// Created by Jacob Hodgkins

#include "SystemRootAnalysis.h"
#include "ReconciliationEngine.h"
#include "CanonicalRomClosure.h"
#include "RomClosure.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pacripper {

enum class RomReconstructionOwnerKind {
    Unowned,
    CanonicalInstruction,
    InlinePayload,
    CanonicalDataObject,
    ClassifiedData,
    ProvenUnused
};

struct RomReconstructionReconstructionByteRecord {
    std::uint16_t address=0;
    std::uint8_t expectedByte=0;
    std::uint8_t emittedByte=0;
    bool owned=false;
    RomReconstructionOwnerKind ownerKind=RomReconstructionOwnerKind::Unowned;
    std::size_t sourceId=static_cast<std::size_t>(-1);
    std::uint16_t sourceStart=0;
    std::uint16_t sourceEnd=0;
    int sourcePc=-1;
    std::size_t sourceOffset=0;
    RomClosurePrimary closurePrimary=RomClosurePrimary::Unresolved;
    std::string sourceText;
    std::string provenance;
};

struct RomReconstructionReconstructionMapRecord {
    std::size_t id=0;
    std::uint16_t start=0;
    std::uint16_t end=0;
    std::size_t length=0;
    RomReconstructionOwnerKind ownerKind=RomReconstructionOwnerKind::Unowned;
    std::size_t sourceId=static_cast<std::size_t>(-1);
    std::string sourceText;
    std::string provenance;
};

struct RomReconstructionBinaryDiffRecord {
    std::size_t id=0;
    std::uint16_t address=0;
    std::uint8_t expectedByte=0;
    std::uint8_t emittedByte=0;
    RomReconstructionOwnerKind ownerKind=RomReconstructionOwnerKind::Unowned;
    std::size_t sourceId=static_cast<std::size_t>(-1);
    std::string provenance;
};

struct RomReconstructionStats {
    std::size_t romBytes=0;
    std::size_t ledgerRecords=0;
    std::size_t ownedAddresses=0;
    std::size_t unownedAddresses=0;
    std::size_t ownershipConflicts=0;
    std::size_t sourceByteMismatches=0;
    std::size_t rebuiltByteMismatches=0;
    std::size_t canonicalInstructionBytes=0;
    std::size_t inlinePayloadBytes=0;
    std::size_t canonicalDataObjectBytes=0;
    std::size_t classifiedDataBytes=0;
    std::size_t provenUnusedBytes=0;
    bool completeOwnership=false;
    bool exactRebuild=false;
};

struct RomReconstructionReconstructionResult {
    std::vector<RomReconstructionReconstructionByteRecord> ledger;
    std::vector<RomReconstructionReconstructionMapRecord> map;
    std::vector<RomReconstructionBinaryDiffRecord> diffs;
    std::vector<std::uint8_t> rebuiltBytes;
    RomReconstructionStats stats;
};

class ExactRomReconstruction {
public:
    static RomReconstructionReconstructionResult build(
        const std::vector<std::uint8_t>& program,
        const std::vector<ReconciliationCanonicalInstructionRecord>& canonicalInstructions,
        const std::vector<SystemRootInlineDataRecord>& inlineData,
        const std::vector<CanonicalClosureCanonicalDataObjectRecord>& canonicalDataObjects,
        const std::vector<CanonicalClosureNegativeClosureRecord>& negativeClosure,
        const std::vector<RomByteClosureRecord>& closureBytes);

    static std::string ownerKindText(RomReconstructionOwnerKind kind);
};

} // namespace pacripper
