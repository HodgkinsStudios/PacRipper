#pragma once
// PacRipper residual-reference analysis residual high-ROM reference / negative-proof model
// Created by Jacob Hodgkins

#include "IndirectAddressAnalysis.h"
#include "RomClosure.h"

#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace pacripper {

enum class SystemRomSemanticKind {
    InterruptVectorWord
};

struct SystemRomSemanticRecord {
    std::size_t id=0;
    SystemRomSemanticKind kind=SystemRomSemanticKind::InterruptVectorWord;
    std::uint16_t start=0;
    std::uint16_t end=0; // exclusive
    std::uint16_t decodedValue=0;
    std::uint16_t target=0;
    std::uint8_t interruptPage=0;
    std::uint8_t vectorByte=0;
    bool exact=false;
    bool staticProof=false;
    bool targetStaticBeforeResidualReference=false;
    std::set<std::uint16_t> proofPCs;
    std::string proofSource;
    std::string note;
};

struct NegativeReferenceRecord {
    std::size_t id=0;
    std::uint16_t start=0;
    std::uint16_t end=0; // exclusive
    std::size_t length=0;

    // Positive/static reference classes. These remain separate so absence in one
    // class can never be silently promoted to global absence.
    std::set<std::uint16_t> directMemoryRefPCs;
    std::set<std::uint16_t> immediateAddressPCs;
    std::set<std::uint16_t> controlTargetPCs;
    std::set<std::size_t> finiteIndirectAccessIds;
    std::set<std::uint16_t> finiteIndirectPCs;
    std::set<std::size_t> systemSemanticIds;

    // A statically reachable indirect read with an unknown alternative can still
    // target the span, so it blocks exhaustive negative proof.
    std::set<std::uint16_t> unknownIndirectReadBlockerPCs;

    // Dynamic observations are corroboration only and never establish static
    // absence or a static root.
    std::set<std::uint16_t> dynamicReadPCs;
    std::size_t dynamicReadEvents=0;

    bool leftBoundaryProven=false;
    bool rightBoundaryProven=false;
    bool leftRomBoundary=false;
    bool rightRomBoundary=false;
    bool directReferenceAbsent=false;
    bool finiteIndirectReferenceAbsent=false;
    bool controlReferenceAbsent=false;
    bool systemSemanticAbsent=false;
    bool exhaustiveModeledStaticAbsence=false;
    bool supportsUnusedClassification=false;
    std::string note;
};

struct UnusedRomRegionRecord {
    std::size_t id=0;
    std::size_t negativeReferenceId=0;
    std::uint16_t start=0;
    std::uint16_t end=0; // exclusive
    bool accepted=false;
    std::string note;
};

struct SemanticOverlapRecord {
    std::size_t id=0;
    std::uint16_t start=0;
    std::uint16_t end=0; // exclusive
    std::set<std::string> interpretations;
    bool compatible=true;
    std::string note;
};

struct ResidualReferenceClosureProvenanceRecord {
    std::uint16_t address=0;
    bool exact=false;
    bool bounded=false;
    bool negativeProof=false;
    std::set<std::size_t> systemSemanticIds;
    std::set<std::size_t> negativeReferenceIds;
    std::set<std::uint16_t> proofPCs;
    std::string note;
};

struct ResidualReferenceSemanticCoverageStats {
    std::size_t romBytes=0;
    std::size_t semanticBytesBeforeResidualReference=0;
    std::size_t residualReferenceNewSemanticBytes=0;
    std::size_t semanticBytesAfterResidualReference=0;
    std::size_t checksumOnlyBytes=0;
    std::size_t unresolvedAfterResidualReference=0;
};

class ResidualReferenceAnalysis {
public:
    static bool addressValueIntersects(const AddressLatticeValue& value,
                                       std::uint16_t start,std::uint16_t end);
    static bool qualifiesUnused(const NegativeReferenceRecord& record);
    static UnusedRomRegionRecord unusedRegion(const NegativeReferenceRecord& record,
                                              std::size_t id);
    static bool applyExactSystemSemantic(const SystemRomSemanticRecord& semantic,
                                         const std::vector<RomByteClosureRecord>& baseline,
                                         std::vector<RomByteClosureRecord>& overlay,
                                         std::vector<ResidualReferenceClosureProvenanceRecord>& provenance);
    static std::string systemSemanticKindText(SystemRomSemanticKind kind);
};

} // namespace pacripper
