#pragma once
// PacRipper maze-topology analysis maze-topology / retry-loop proofs and residual classification
// Created by Jacob Hodgkins

#include "CommandStreamAnalysis.h"
#include "../analysis/Analyzer.h"

#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace pacripper {

enum class MazeTopologyTopologyKind { CanonicalMazeDecoder, CharacterDemoBarrier, UnresolvedLifecycle };
enum class MazeTopologyResidualKind { RetryLoopDependent, DecoderOrTableGap, NoSemanticConsumer, GenuineUnresolved };

struct MazeTopologyTopologyInputRecord {
    std::size_t id=0;
    MazeTopologyTopologyKind kind=MazeTopologyTopologyKind::UnresolvedLifecycle;
    std::string name;
    std::set<std::uint16_t> callerPCs;
    std::set<std::uint16_t> coordinateAddresses;
    std::set<std::uint16_t> directionAddresses;
    std::set<std::uint16_t> proofPCs;
    std::size_t passableNodes=0;
    std::size_t minimumPassableDegree=0;
    std::size_t deadEndNodes=0;
    std::set<std::uint8_t> fixedLowCoordinates;
    std::set<std::uint8_t> blockedNeighborLowCoordinates;
    bool sourceShapeProven=false;
    bool topologyComplete=false;
    bool retryExitApplicable=false;
    std::string note;
};

struct MazeTopologyDirectionCandidateRecord {
    std::size_t id=0;
    std::size_t physicalRecordIndex=0;
    std::uint8_t semanticDirection=0;
    std::uint16_t address=0;
    std::uint8_t deltaLow=0;
    std::uint8_t deltaHigh=0;
    bool duplicateBacking=false;
    bool byteExact=false;
    std::set<std::uint16_t> proofPCs;
    std::string note;
};

struct MazeTopologyRetryLoopProofRecord {
    std::size_t id=0;
    std::uint16_t routine=0x291E;
    std::set<std::uint16_t> callerPCs;
    std::set<std::size_t> topologyInputIds;
    std::set<std::size_t> directionCandidateIds;
    std::set<std::uint16_t> proofPCs;
    std::size_t semanticDirectionCount=4;
    std::size_t maximumSemanticTestsIfTopologyComplete=4;
    std::size_t maximumPhysicalRecordIndexIfComplete=6;
    bool callerCoverageComplete=false;
    bool moduloCycleProven=false;
    bool reverseRejectionProven=false;
    bool ixProgressionProven=false;
    bool passabilityTestProven=false;
    bool tunnelWrapExclusionProven=false;
    bool duplicateBackingProven=false;
    bool canonicalMazeExitProven=false;
    bool allTopologyStatesComplete=false;
    bool accepted=false;
    std::string missingStaticFact;
    std::string note;
};

struct MazeTopologyAddressProofRecord {
    std::size_t id=0;
    std::uint16_t pc=0;
    std::string operand;
    AddressLatticeValue address;
    RootContextDomainClass domainClass=RootContextDomainClass::Unresolved;
    std::set<std::uint16_t> candidateFiniteDomain;
    std::set<std::size_t> retryLoopProofIds;
    std::set<std::size_t> topologyInputIds;
    std::set<std::uint16_t> proofPCs;
    bool inheritedCommandStreamBlocker=false;
    bool candidateDomainConditional=false;
    bool accepted=false;
    std::string note;
};

struct MazeTopologyResidualClassificationRecord {
    std::size_t id=0;
    std::uint16_t start=0;
    std::uint16_t end=0; // exclusive
    MazeTopologyResidualKind kind=MazeTopologyResidualKind::GenuineUnresolved;
    std::set<std::uint16_t> proofPCs;
    bool staticStructuralEvidence=false;
    bool closesBytes=false;
    std::string note;
};

struct MazeTopologyClosureProvenanceRecord {
    std::uint16_t address=0;
    bool exact=false;
    bool bounded=false;
    std::set<std::size_t> addressProofIds;
    std::set<std::size_t> retryLoopProofIds;
    std::set<std::size_t> topologyInputIds;
    std::set<std::uint16_t> sourcePCs;
    std::string note;
};

struct MazeTopologyStats {
    std::size_t topologyInputs=0;
    std::size_t completeTopologyInputs=0;
    std::size_t directionCandidateRecords=0;
    std::size_t duplicateDirectionRecords=0;
    std::size_t retryLoopProofs=0;
    std::size_t acceptedRetryLoopProofs=0;
    std::size_t addressProofs=0;
    std::size_t acceptedAddressProofs=0;
    std::size_t inheritedBlockers=0;
    std::size_t refinedInheritedBlockers=0;
    std::size_t remainingBlockers=0;
    std::size_t residualClassificationRecords=0;
    std::size_t retryLoopDependentResidualBytes=0;
    std::size_t decoderOrTableGapResidualBytes=0;
    std::size_t noSemanticConsumerResidualBytes=0;
    std::size_t genuineUnresolvedResidualBytes=0;
    std::size_t closureProvenanceRecords=0;
    std::size_t newlyExplainedBytes=0;
    std::size_t newlyExactExplainedBytes=0;
    std::size_t newlyBoundedExplainedBytes=0;
    std::size_t unresolvedAfterMazeTopology=0;
    std::size_t residualSpansAfterMazeTopology=0;
};

struct MazeTopologyAnalysisResult {
    std::vector<MazeTopologyTopologyInputRecord> topologyInputs;
    std::vector<MazeTopologyDirectionCandidateRecord> directionCandidates;
    std::vector<MazeTopologyRetryLoopProofRecord> retryLoopProofs;
    std::vector<MazeTopologyAddressProofRecord> addressProofs;
    std::set<std::uint16_t> inheritedBlockerPCs;
    std::set<std::uint16_t> refinedInheritedBlockerPCs;
    std::set<std::uint16_t> remainingBlockerPCs;
};

class MazeTopologyAnalysis {
public:
    static MazeTopologyAnalysisResult analyze(const Analyzer& analyzer);
    static std::string topologyKindText(MazeTopologyTopologyKind kind);
    static std::string residualKindText(MazeTopologyResidualKind kind);
    static bool semanticRomClosureEligible(const MazeTopologyAddressProofRecord& proof);
};

} // namespace pacripper
