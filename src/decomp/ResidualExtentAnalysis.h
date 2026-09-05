#pragma once
// PacRipper residual-extent analysis residual extent / exhaustive unused-region proof model
// Created by Jacob Hodgkins

#include "IntermissionAnalysis.h"
#include "ResidualReferenceAnalysis.h"

#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace pacripper {

enum class ResidualExtentExtentKind {
    SparsePointerDomain,
    DelimitedStreamDomain,
    ExactRecordDomain,
    SentinelStreamDomain,
    CommandStreamGraph,
    SystemTailGuard
};

struct ResidualExtentResidualAuditRecord {
    std::size_t id=0;
    std::uint16_t start=0;
    std::uint16_t end=0; // exclusive
    std::size_t length=0;
    MazeTopologyResidualKind inheritedKind=MazeTopologyResidualKind::GenuineUnresolved;
    std::set<std::uint16_t> directMemoryRefPCs;
    std::set<std::uint16_t> immediateAddressPCs;
    std::set<std::uint16_t> controlTargetPCs;
    std::set<std::uint16_t> finiteIndirectPCs;
    std::set<std::uint16_t> checksumSelfTestPCs;
    std::set<std::size_t> decoderIds;
    std::set<std::size_t> pointerDomainIds;
    std::set<std::size_t> streamIds;
    std::set<std::size_t> fixedRecordIds;
    std::set<std::size_t> boundedBlockIds;
    std::set<std::size_t> systemSemanticIds;
    std::set<std::size_t> overlapIds;
    std::set<std::size_t> pointerLinkIds;
    std::set<std::uint16_t> unresolvedReadPCs;
    bool leftBoundaryProven=false;
    bool rightBoundaryProven=false;
    bool leftRomBoundary=false;
    bool rightRomBoundary=false;
    bool allConsumersBounded=false;
    bool positiveSemanticReference=false;
    bool guard330d330e=false;
    bool guard3ffe3fff=false;
    bool negativeClosureEligible=false;
    std::string note;
};

struct ResidualExtentExtentProofRecord {
    std::size_t id=0;
    ResidualExtentExtentKind kind=ResidualExtentExtentKind::SparsePointerDomain;
    std::string name;
    std::uint16_t start=0;
    std::uint16_t end=0; // exclusive research window
    std::set<std::uint16_t> acceptedAddresses;
    std::set<std::uint16_t> acceptedRoots;
    std::set<std::uint16_t> excludedRoots;
    std::set<std::uint16_t> residualAddresses;
    std::set<std::uint16_t> consumerPCs;
    std::set<std::uint16_t> proofPCs;
    std::set<std::size_t> sourceObjectIds;
    bool sourceDomainComplete=false;
    bool nestedExtentComplete=false;
    bool accepted=false;
    bool closesBytes=false;
    std::string note;
};

struct ResidualExtentNegativeReferenceRecord {
    std::size_t id=0;
    std::size_t residualAuditId=0;
    std::uint16_t start=0;
    std::uint16_t end=0;
    std::size_t length=0;
    std::set<std::uint16_t> directMemoryRefPCs;
    std::set<std::uint16_t> immediateAddressPCs;
    std::set<std::uint16_t> controlTargetPCs;
    std::set<std::uint16_t> finiteIndirectPCs;
    std::set<std::uint16_t> checksumSelfTestPCs;
    std::set<std::size_t> systemSemanticIds;
    std::set<std::uint16_t> unresolvedReadPCs;
    std::set<std::uint16_t> boundedReadPCs;
    std::set<std::uint16_t> dynamicReadPCs;
    std::size_t dynamicReadEvents=0;
    bool callerInventoryComplete=false;
    bool indirectControlInventoryComplete=false;
    bool allReadAlternativesBounded=false;
    bool directReferenceAbsent=false;
    bool finiteIndirectReferenceAbsent=false;
    bool controlReferenceAbsent=false;
    bool systemSemanticAbsent=false;
    bool leftBoundaryProven=false;
    bool rightBoundaryProven=false;
    bool leftRomBoundary=false;
    bool rightRomBoundary=false;
    bool exhaustiveModeledStaticAbsence=false;
    std::set<std::size_t> incompletePointerDomainIds;
    bool incompletePointerDomainPotentialReference=false;
    bool guardExcluded=false;
    bool supportsUnusedClassification=false;
    std::string note;
};

struct ResidualExtentUnusedRegionRecord {
    std::size_t id=0;
    std::size_t negativeProofId=0;
    std::uint16_t start=0;
    std::uint16_t end=0;
    bool accepted=false;
    std::string note;
};

struct ResidualExtentClosureProvenanceRecord {
    std::uint16_t address=0;
    bool provenUnused=false;
    std::set<std::size_t> residualAuditIds;
    std::set<std::size_t> negativeProofIds;
    std::set<std::size_t> extentProofIds;
    std::set<std::uint16_t> proofPCs;
    std::string note;
};

struct ResidualExtentFinalResidualRecord {
    std::size_t id=0;
    std::uint16_t start=0;
    std::uint16_t end=0;
    std::size_t length=0;
    std::string reason;
};

struct ResidualExtentStats {
    std::size_t residualAuditRecords=0;
    std::size_t auditedResidualBytes=0;
    std::size_t extentProofs=0;
    std::size_t acceptedExtentProofs=0;
    std::size_t negativeReferenceProofs=0;
    std::size_t exhaustiveNegativeProofs=0;
    std::size_t unusedRegions=0;
    std::size_t closureProvenanceRecords=0;
    std::size_t newlyUnusedExplainedBytes=0;
    std::size_t newlyExplainedBytes=0;
    std::size_t unresolvedAfterResidualExtent=0;
    std::size_t residualSpansAfterResidualExtent=0;
    std::size_t guard330d330eClosedBytes=0;
    std::size_t guard3ffe3fffUnresolvedBytes=0;
    bool allConsumerInventoryComplete=false;
};

class ResidualExtentAnalysis {
public:
    static bool intersects(std::uint16_t a0,std::uint16_t a1,std::uint16_t b0,std::uint16_t b1);
    static bool addressSetIntersects(const std::set<std::uint16_t>& values,std::uint16_t start,std::uint16_t end);
    static bool completeFiniteDomain(const AddressLatticeValue& value,std::set<std::uint16_t>& out);
    static bool qualifiesUnused(const ResidualExtentNegativeReferenceRecord& record);
    static std::string extentKindText(ResidualExtentExtentKind kind);
};

} // namespace pacripper
