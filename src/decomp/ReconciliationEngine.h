#pragma once
// PacRipper semantic reconciliation correction/reconciliation audit
// Created by Jacob Hodgkins

#include "RomClosure.h"

#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace pacripper {

struct ReconciliationCanonicalInstructionRecord {
    std::size_t id=0;
    std::uint16_t pc=0;
    std::size_t length=0;
    std::vector<std::uint8_t> bytes;
    std::string mnemonic;
    std::string operands;
    bool analyzerRoot=false;
    bool systemRootReachable=false;
    bool semanticOracleSemanticallyVerified=false;
    bool semanticOracleSourceBytesMatch=false;
    std::set<std::size_t> systemRootReachabilityIds;
    std::set<std::size_t> semanticOracleOperationIds;
    std::string note;
};

struct ReconciliationResidualRecord {
    std::size_t id=0;
    std::uint16_t start=0;
    std::uint16_t end=0;
    std::size_t length=0;
    std::string reason;
};

struct ReconciliationStats {
    std::size_t canonicalInstructionStarts=0;
    std::size_t canonicalCodeBytes=0;
    std::size_t analyzerInstructionStarts=0;
    std::size_t systemRootInstructionStarts=0;
    std::size_t analyzerSystemOverlapStarts=0;
    std::size_t systemOnlyInstructionStarts=0;
    std::size_t semanticOracleCoveredCanonicalInstructions=0;
    std::size_t canonicalInstructionsNotYetLifted=0;
    std::size_t semanticOracleByteMismatches=0;
    std::size_t systemRootDecodeLengthMismatches=0;
    std::size_t canonicalInstructionBoundaryConflicts=0;
    std::size_t incompletePointerDomainVetoBytes=0;
    std::size_t incompletePointerDomainVetoSpans=0;
    std::size_t canonicalCodePreviouslyMarkedUnused=0;
    std::size_t unresolvedAfterReconciliation=0;
    std::size_t residualSpansAfterReconciliation=0;
    bool canonicalInventorySelfConsistent=false;
    bool semanticOracleSubsetVerified=false;
    bool oldCompleteSemanticClaimSuperseded=false;
};

} // namespace pacripper
