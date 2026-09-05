#pragma once
// PacRipper system-root reachability analysis system-root reachability and indirect-address refinement
// Created by Jacob Hodgkins

#include "IndirectAddressAnalysis.h"
#include "ResidualReferenceAnalysis.h"
#include "RomClosure.h"
#include "../analysis/Analyzer.h"
#include "../disasm/Z80Disassembler.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace pacripper {

enum class SystemRootKind {
    InterruptVectorTarget
};

enum class SystemRootReachabilityEdgeKind {
    Root,
    Fallthrough,
    BranchOrCallTarget,
    RestartTarget,
    DispatchTarget,
    InlineContinuation
};

enum class SystemRootInlineDataKind {
    Rst20DispatchTable,
    Rst28InlineArgs,
    Rst30InlinePayload,
    CallInlineFiveBytes
};

enum class IndirectAddressRefinementKind {
    ExactSet,
    ContiguousRange,
    StridedRange,
    NonRomRange,
    ProvenSemanticUnion,
    InlineConvention
};

struct SystemRootRecord {
    std::size_t id=0;
    SystemRootKind kind=SystemRootKind::InterruptVectorTarget;
    std::uint16_t entry=0;
    std::size_t systemSemanticId=0;
    std::uint16_t vectorAddress=0;
    std::uint8_t vectorByte=0;
    bool staticProof=false;
    bool targetStaticBeforeSystemRoot=false;
    std::set<std::uint16_t> proofPCs;
    std::string note;
};

struct SystemRootReachabilityRecord {
    std::size_t id=0;
    std::size_t rootId=0;
    std::uint16_t pc=0;
    int predecessorPc=-1;
    SystemRootReachabilityEdgeKind edgeKind=SystemRootReachabilityEdgeKind::Root;
    std::size_t length=0;
    bool alreadyIndependentStatic=false;
    bool traceDiscoveredBeforeSystemRoot=false;
    bool newlyIndependentStatic=false;
    std::set<std::uint16_t> byteAddresses;
    std::string note;
};

struct SystemRootInlineDataRecord {
    std::size_t id=0;
    std::size_t rootId=0;
    SystemRootInlineDataKind kind=SystemRootInlineDataKind::Rst28InlineArgs;
    std::uint16_t sourcePC=0;
    std::uint16_t start=0;
    std::uint16_t end=0; // exclusive
    bool exact=true;
    bool staticProof=true;
    std::set<std::uint16_t> dispatchTargets;
    std::string note;
};

struct SystemRootReachabilityResult {
    std::vector<SystemRootRecord> roots;
    std::vector<SystemRootReachabilityRecord> reachability;
    std::vector<SystemRootInlineDataRecord> inlineData;
    std::set<std::uint16_t> reachablePCs;
    std::set<std::uint16_t> newlyIndependentPCs;
    std::set<std::uint16_t> reachableBytes;
    std::set<std::uint16_t> unresolvedIndirectExitPCs;
    std::size_t hardDataConflicts=0;
};

struct IndirectAddressRefinementRecord {
    std::size_t id=0;
    std::size_t accessId=static_cast<std::size_t>(-1);
    std::uint16_t pc=0;
    IndirectAddressRefinementKind kind=IndirectAddressRefinementKind::ExactSet;
    AddressValueKind originalKind=AddressValueKind::Unknown;
    AddressLatticeValue refinedAddress;
    bool originalResidualReferenceBlocker=false;
    bool rootReachable=false;
    bool accepted=false;
    bool removesUnknownAlternative=false;
    bool intersectsRom=false;
    bool nonRomOnly=false;
    bool sourceInstructionSuppressed=false;
    std::set<std::uint16_t> proofPCs;
    std::set<std::size_t> semanticIds;
    std::set<std::size_t> inlineDataIds;
    std::string note;
};

struct SystemRootNegativeReferenceRecord {
    std::size_t id=0;
    std::size_t residualReferenceNegativeReferenceId=0;
    std::uint16_t start=0;
    std::uint16_t end=0;
    std::size_t length=0;
    std::set<std::uint16_t> originalUnknownBlockerPCs;
    std::set<std::uint16_t> refinedOriginalBlockerPCs;
    std::set<std::uint16_t> remainingOriginalBlockerPCs;
    std::set<std::uint16_t> newlyRootedUnknownBlockerPCs;
    std::set<std::uint16_t> finiteRefinedHitPCs;
    bool inheritedPositiveReference=false;
    bool exhaustiveModeledStaticAbsence=false;
    bool supportsUnusedClassification=false;
    std::size_t dynamicReadEvents=0;
    std::string note;
};

struct SystemRootClosureProvenanceRecord {
    std::uint16_t address=0;
    bool exact=false;
    bool bounded=false;
    bool code=false;
    bool inlineData=false;
    bool refinedConsumer=false;
    std::set<std::size_t> rootIds;
    std::set<std::uint16_t> sourcePCs;
    std::set<std::size_t> refinementIds;
    std::set<std::size_t> inlineDataIds;
    std::string note;
};

struct SystemRootStats {
    std::size_t systemRoots=0;
    std::size_t reachableInstructions=0;
    std::size_t newlyIndependentInstructions=0;
    std::size_t reachableCodeBytes=0;
    std::size_t inlineDataRecords=0;
    std::size_t refinements=0;
    std::size_t originalResidualReferenceBlockers=0;
    std::size_t refinedOriginalResidualReferenceBlockers=0;
    std::size_t remainingOriginalResidualReferenceBlockers=0;
    std::size_t newlyRootedUnknownBlockerPCs=0;
    std::size_t totalRemainingUnknownBlockerPCs=0;
    std::size_t exhaustiveNegativeReferenceRecords=0;
    std::size_t unusedRomRegions=0;
    std::size_t closureProvenanceRecords=0;
    std::size_t newlyExplainedBytes=0;
    std::size_t newlyExactExplainedBytes=0;
    std::size_t newlyBoundedExplainedBytes=0;
    std::size_t unresolvedAfterSystemRoot=0;
    std::size_t residualSpansAfterSystemRoot=0;
};

class SystemRootAnalysis {
public:
    static SystemRootReachabilityResult discoverSystemRoots(
        const Analyzer& analyzer,
        const std::vector<RomByteClosureRecord>& frozenResidualReferenceClosure,
        const std::vector<SystemRomSemanticRecord>& systemSemantics);

    static bool addressIntersectsRom(const AddressLatticeValue& value,std::size_t romSize);
    static bool addressIntersectsSpan(const AddressLatticeValue& value,std::uint16_t start,std::uint16_t end);
    static bool supportsUnused(const SystemRootNegativeReferenceRecord& record,bool leftBoundaryProven,bool rightBoundaryProven);
    static std::string rootKindText(SystemRootKind kind);
    static std::string edgeKindText(SystemRootReachabilityEdgeKind kind);
    static std::string inlineKindText(SystemRootInlineDataKind kind);
    static std::string refinementKindText(IndirectAddressRefinementKind kind);
};

} // namespace pacripper
