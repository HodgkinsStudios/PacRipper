#pragma once
// PacRipper context-sensitive root analysis context-sensitive system-root address flow
// Created by Jacob Hodgkins

#include "SystemRootAnalysis.h"
#include "../analysis/Analyzer.h"

#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace pacripper {

enum class RootContextDomainClass {
    FiniteRom,
    FiniteNonRom,
    Mixed,
    Unresolved
};

struct RootContextAddressContextRecord {
    std::size_t id=0;
    std::uint16_t pc=0;
    std::string operand;
    IndirectMemoryDirection direction=IndirectMemoryDirection::Read;
    std::string contextKey;
    std::size_t callDepth=0;
    std::size_t returnBarrierDepth=0;
    std::set<std::uint16_t> callSites;
    std::set<std::uint16_t> returnPCs;
    AddressLatticeValue address;
    bool contextWidened=false;
    bool syntheticRestartSummary=false;
    std::set<std::uint16_t> proofPCs;
    std::string note;
};

struct RootContextAddressProofRecord {
    std::size_t id=0;
    std::uint16_t pc=0;
    std::string operand;
    IndirectMemoryDirection direction=IndirectMemoryDirection::Read;
    AddressLatticeValue aggregateAddress;
    RootContextDomainClass domainClass=RootContextDomainClass::Unresolved;
    std::set<std::size_t> contextRecordIds;
    std::set<std::uint16_t> callSites;
    std::set<std::uint16_t> proofPCs;
    bool callerComplete=false;
    bool contextOverflow=false;
    bool inheritedSystemRootBlocker=false;
    bool newlyRootedSystemRootBlocker=false;
    bool accepted=false;
    bool exactSingleton=false;
    bool finiteRomOnly=false;
    bool finiteNonRomOnly=false;
    bool mixedRomNonRom=false;
    bool sourceInvariant=false;
    std::string note;
};

struct RootContextAnalysisResult {
    std::vector<RootContextAddressContextRecord> contextRecords;
    std::vector<RootContextAddressProofRecord> addressProofs;
    // memory-alias analysis side channel: collected during the same fixed-point traversal so
    // writer alias auditing does not require a second whole-program run.
    std::vector<RootContextAddressContextRecord> writerContextRecords;
    std::vector<RootContextAddressProofRecord> writerAddressProofs;
    std::set<std::uint16_t> inheritedBlockerPCs;
    std::set<std::uint16_t> newlyRootedBlockerPCs;
    std::set<std::uint16_t> refinedInheritedBlockerPCs;
    std::set<std::uint16_t> refinedNewlyRootedBlockerPCs;
    std::set<std::uint16_t> remainingInheritedBlockerPCs;
    std::set<std::uint16_t> remainingNewlyRootedBlockerPCs;
    std::set<std::uint16_t> contextOverflowPCs;
    std::set<std::uint16_t> unresolvedIndirectControlPCs;
    std::size_t rootedContextStates=0;
    std::size_t maxObservedCallDepth=0;
    std::size_t stateMergeUpdates=0;
    std::size_t valueWidenEvents=0;
    std::size_t contextOverflowEvents=0;
    std::size_t guardTrips=0;
    bool callerInventoryComplete=true;
};

struct RootContextNegativeReferenceRecord {
    std::size_t id=0;
    std::size_t systemRootNegativeReferenceId=0;
    std::uint16_t start=0;
    std::uint16_t end=0;
    std::size_t length=0;
    std::set<std::uint16_t> remainingInheritedBlockerPCs;
    std::set<std::uint16_t> remainingNewlyRootedBlockerPCs;
    std::set<std::uint16_t> finitePositiveHitPCs;
    std::set<std::size_t> finitePositiveProofIds;
    bool inheritedPositiveReference=false;
    bool callerInventoryComplete=false;
    bool exhaustiveModeledStaticAbsence=false;
    bool supportsUnusedClassification=false;
    std::size_t dynamicReadEvents=0;
    std::string note;
};

struct RootContextClosureProvenanceRecord {
    std::uint16_t address=0;
    bool exact=false;
    bool bounded=false;
    std::set<std::size_t> addressProofIds;
    std::set<std::size_t> contextRecordIds;
    std::set<std::uint16_t> sourcePCs;
    std::set<std::uint16_t> callSites;
    std::string note;
};

struct RootContextStats {
    std::size_t rootedContextStates=0;
    std::size_t maxObservedCallDepth=0;
    std::size_t stateMergeUpdates=0;
    std::size_t valueWidenEvents=0;
    std::size_t contextOverflowEvents=0;
    std::size_t contextOverflowPCs=0;
    std::size_t unresolvedIndirectControlPCs=0;
    std::size_t guardTrips=0;
    bool callerInventoryComplete=true;
    std::size_t addressContextRecords=0;
    std::size_t addressProofs=0;
    std::size_t acceptedAddressProofs=0;
    std::size_t sourceInvariantProofs=0;
    std::size_t finiteRomProofs=0;
    std::size_t finiteNonRomProofs=0;
    std::size_t mixedProofs=0;
    std::size_t unresolvedProofs=0;
    std::size_t inheritedBlockers=0;
    std::size_t refinedInheritedBlockers=0;
    std::size_t remainingInheritedBlockers=0;
    std::size_t newlyRootedBlockers=0;
    std::size_t refinedNewlyRootedBlockers=0;
    std::size_t remainingNewlyRootedBlockers=0;
    std::size_t totalRemainingBlockers=0;
    std::size_t negativeReferenceRecords=0;
    std::size_t exhaustiveNegativeReferenceRecords=0;
    std::size_t unusedRomRegions=0;
    std::size_t closureProvenanceRecords=0;
    std::size_t newlyExplainedBytes=0;
    std::size_t newlyExactExplainedBytes=0;
    std::size_t newlyBoundedExplainedBytes=0;
    std::size_t unresolvedAfterRootContext=0;
    std::size_t residualSpansAfterRootContext=0;
};

class RootContextAnalysis {
public:
    static RootContextAnalysisResult analyze(
        const Analyzer& analyzer,
        const std::vector<SystemRootReachabilityRecord>& rootedReachability,
        const std::vector<SystemRootInlineDataRecord>& inlineData,
        const std::vector<SystemRootNegativeReferenceRecord>& systemRootNegativeEvidence,
        std::size_t maxValues=64,
        std::size_t maxContextsPerPC=512,
        std::size_t maxCallDepth=16);

    // memory-alias analysis reuses the exact same fixed-point engine to inventory indirect
    // memory writers.  The ordinary analyze() path remains read-only/verified.
    static RootContextAnalysisResult analyzeWrites(
        const Analyzer& analyzer,
        const std::vector<SystemRootReachabilityRecord>& rootedReachability,
        const std::vector<SystemRootInlineDataRecord>& inlineData,
        const std::vector<SystemRootNegativeReferenceRecord>& systemRootNegativeEvidence,
        std::size_t maxValues=64,
        std::size_t maxContextsPerPC=512,
        std::size_t maxCallDepth=16);

    // Public proof-boundary helpers are intentionally small so the smoke suite can
    // regression-test the lattice without constructing the Pac-Man analyzer.
    static AddressLatticeValue mergeCallerDomains(
        const std::vector<AddressLatticeValue>& domains,
        std::size_t maxValues=64);
    static RootContextDomainClass classifyDomain(const AddressLatticeValue& value,std::size_t romSize);
    static bool completeFiniteDomain(const AddressLatticeValue& value,std::set<std::uint16_t>& out,std::size_t cap=65536);
    static bool supportsUnused(const RootContextNegativeReferenceRecord& record,bool leftBoundaryProven,bool rightBoundaryProven);
    static std::string domainClassText(RootContextDomainClass kind);
};

} // namespace pacripper
