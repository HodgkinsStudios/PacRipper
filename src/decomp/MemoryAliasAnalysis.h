#pragma once
// PacRipper memory-alias analysis memory-state / writer-alias / pointer-lifecycle proofs
// Created by Jacob Hodgkins

#include "RootContextAnalysis.h"
#include "../analysis/Analyzer.h"

#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace pacripper {

enum class MemoryAliasProofKind {
    MemoryLifecycle,
    CalleeMemoryEffect,
    LoopCarriedState,
    CommandStreamPointer,
    SelfTestChecksum
};

struct MemoryAliasWriterAliasRecord {
    std::size_t id=0;
    std::uint16_t start=0;
    std::uint16_t end=0; // exclusive
    std::set<std::uint16_t> directWriterPCs;
    std::set<std::uint16_t> indirectWriterPCs;
    std::set<std::uint16_t> unknownAliasWriterPCs;
    std::set<std::size_t> indirectWriterProofIds;
    std::set<std::uint16_t> proofPCs;
    bool complete=false;
    std::string note;
};

struct MemoryAliasAddressProofRecord {
    std::size_t id=0;
    std::uint16_t pc=0;
    std::string operand;
    MemoryAliasProofKind kind=MemoryAliasProofKind::MemoryLifecycle;
    AddressLatticeValue address;
    RootContextDomainClass domainClass=RootContextDomainClass::Unresolved;
    bool inheritedRootContextBlocker=false;
    bool newlyRootedRootContextBlocker=false;
    bool accepted=false;
    bool exactSingleton=false;
    bool sourceInvariant=false;
    std::set<std::size_t> writerAliasRecordIds;
    std::set<std::uint16_t> proofPCs;
    std::string note;
};

struct MemoryAliasClosureProvenanceRecord {
    std::uint16_t address=0;
    bool exact=false;
    bool bounded=false;
    std::set<std::size_t> addressProofIds;
    std::set<std::size_t> writerAliasRecordIds;
    std::set<std::uint16_t> sourcePCs;
    std::string note;
};

struct MemoryAliasStats {
    std::size_t writerContextRecords=0;
    std::size_t writerProofs=0;
    std::size_t acceptedWriterProofs=0;
    std::size_t unresolvedWriterProofs=0;
    std::size_t writerAliasInventories=0;
    std::size_t completeWriterAliasInventories=0;
    bool writerCallerInventoryComplete=false;
    std::size_t writerContextOverflowEvents=0;
    std::size_t writerGuardTrips=0;
    std::size_t writerUnresolvedIndirectControlPCs=0;
    std::size_t addressProofs=0;
    std::size_t acceptedAddressProofs=0;
    std::size_t inheritedBlockers=0;
    std::size_t refinedInheritedBlockers=0;
    std::size_t remainingInheritedBlockers=0;
    std::size_t newlyRootedBlockers=0;
    std::size_t refinedNewlyRootedBlockers=0;
    std::size_t remainingNewlyRootedBlockers=0;
    std::size_t totalRemainingBlockers=0;
    std::size_t closureProvenanceRecords=0;
    std::size_t newlyExplainedBytes=0;
    std::size_t newlyExactExplainedBytes=0;
    std::size_t newlyBoundedExplainedBytes=0;
    std::size_t unresolvedAfterMemoryAlias=0;
    std::size_t residualSpansAfterMemoryAlias=0;
};

struct MemoryAliasAnalysisResult {
    // Full write-mode output from the verified context-sensitive root analysis fixed-point engine.
    std::vector<RootContextAddressContextRecord> writerContexts;
    std::vector<RootContextAddressProofRecord> writerProofs;
    std::vector<MemoryAliasWriterAliasRecord> writerAliases;
    std::vector<MemoryAliasAddressProofRecord> addressProofs;
    std::set<std::uint16_t> inheritedBlockerPCs;
    std::set<std::uint16_t> newlyRootedBlockerPCs;
    std::set<std::uint16_t> refinedInheritedBlockerPCs;
    std::set<std::uint16_t> refinedNewlyRootedBlockerPCs;
    std::set<std::uint16_t> remainingInheritedBlockerPCs;
    std::set<std::uint16_t> remainingNewlyRootedBlockerPCs;
    bool writerCallerInventoryComplete=false;
    std::size_t writerContextOverflowEvents=0;
    std::size_t writerGuardTrips=0;
    std::size_t writerUnresolvedIndirectControlPCs=0;
};

class MemoryAliasAnalysis {
public:
    static MemoryAliasAnalysisResult analyze(
        const Analyzer& analyzer,
        const std::vector<SystemRootReachabilityRecord>& rootedReachability,
        const std::vector<RootContextAddressContextRecord>& readContexts,
        const std::vector<RootContextAddressContextRecord>& writerContexts,
        const std::vector<RootContextAddressProofRecord>& writerProofs,
        bool callerInventoryComplete,
        std::size_t contextOverflowEvents,
        std::size_t guardTrips,
        std::size_t unresolvedIndirectControlPCs);

    static std::string proofKindText(MemoryAliasProofKind kind);
    static bool completeWriterInventory(const MemoryAliasWriterAliasRecord& record);
    static bool semanticRomClosureEligible(const MemoryAliasAddressProofRecord& proof);
};

} // namespace pacripper
