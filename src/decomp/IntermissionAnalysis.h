#pragma once
// PacRipper intermission analysis intermission lifecycle / retry-loop closure
// Created by Jacob Hodgkins

#include "MazeTopologyAnalysis.h"
#include "HardwareSemantics.h"
#include "../analysis/Analyzer.h"

#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace pacripper {

enum class IntermissionDispatchKind { GlobalGameState, IntermissionSelect, FirstIntermission, SecondIntermission, ThirdIntermission, TimerScheduler };
enum class IntermissionWriterKind { PlayfieldFill, PlayfieldScrub, SideBarrier, IntermissionAnimation, HudOrIrq, StaticExactOther };

struct IntermissionDispatchProofRecord {
    std::size_t id=0;
    IntermissionDispatchKind kind=IntermissionDispatchKind::GlobalGameState;
    std::uint16_t dispatchPC=0;
    std::uint16_t tableStart=0;
    std::size_t entryCount=0;
    std::vector<std::uint16_t> targets;
    std::set<std::uint16_t> proofPCs;
    bool sourceShapeProven=false;
    bool complete=false;
    std::string note;
};

struct IntermissionVideoWriterProofRecord {
    std::size_t id=0;
    IntermissionWriterKind kind=IntermissionWriterKind::StaticExactOther;
    std::string name;
    std::set<std::uint16_t> writerPCs;
    std::set<std::uint16_t> targetAddresses;
    std::set<std::uint8_t> writtenValues;
    bool targetSetExact=false;
    bool lifecycleReachable=false;
    bool touchesCriticalCorridor=false;
    bool canWriteBlockingValue=false;
    bool sourceShapeProven=false;
    std::string note;
};

struct IntermissionLifecycleProofRecord {
    std::size_t id=0;
    std::set<std::uint16_t> proofPCs;
    std::set<std::uint16_t> criticalCorridorAddresses;
    std::set<std::uint16_t> chooserCallers;
    std::set<std::size_t> dispatchProofIds;
    std::set<std::size_t> writerProofIds;
    bool setupQueueShapeProven=false;
    bool playfieldClearBeforeIntermissionProven=false;
    bool ghostInitializerProven=false;
    bool coordinateMappingProven=false;
    bool interiorGateProven=false;
    bool stateDispatchComplete=false;
    bool delayedTransitionsComplete=false;
    bool taskQueueDrainProven=false;
    bool relevantWriterInventoryComplete=false;
    bool criticalCorridorInitializedPassable=false;
    bool criticalCorridorPreservedPassable=false;
    bool intermissionRetryExitProven=false;
    bool canonicalMazeRetryExitInherited=false;
    bool allTopologyStatesComplete=false;
    bool accepted=false;
    std::string missingStaticFact;
    std::string note;
};

struct IntermissionAddressProofRecord {
    std::size_t id=0;
    std::uint16_t pc=0;
    std::string operand;
    AddressLatticeValue address;
    RootContextDomainClass domainClass=RootContextDomainClass::Unresolved;
    std::set<std::uint16_t> finiteDomain;
    std::set<std::size_t> lifecycleProofIds;
    std::set<std::uint16_t> proofPCs;
    bool inheritedMazeTopologyBlocker=false;
    bool accepted=false;
    std::string note;
};

struct IntermissionClosureProvenanceRecord {
    std::uint16_t address=0;
    bool exact=false;
    bool bounded=false;
    std::set<std::size_t> addressProofIds;
    std::set<std::size_t> lifecycleProofIds;
    std::set<std::uint16_t> sourcePCs;
    std::string note;
};

struct IntermissionStats {
    std::size_t dispatchProofs=0;
    std::size_t completeDispatchProofs=0;
    std::size_t writerProofs=0;
    std::size_t lifecycleReachableWriterProofs=0;
    std::size_t criticalCorridorWriterProofs=0;
    std::size_t blockingCriticalWriterProofs=0;
    std::size_t lifecycleProofs=0;
    std::size_t acceptedLifecycleProofs=0;
    std::size_t addressProofs=0;
    std::size_t acceptedAddressProofs=0;
    std::size_t inheritedBlockers=0;
    std::size_t refinedInheritedBlockers=0;
    std::size_t remainingBlockers=0;
    std::size_t closureProvenanceRecords=0;
    std::size_t newlyExplainedBytes=0;
    std::size_t newlyExactExplainedBytes=0;
    std::size_t newlyBoundedExplainedBytes=0;
    std::size_t unresolvedAfterIntermission=0;
    std::size_t residualSpansAfterIntermission=0;
};

struct IntermissionAnalysisResult {
    std::vector<IntermissionDispatchProofRecord> dispatchProofs;
    std::vector<IntermissionVideoWriterProofRecord> writerProofs;
    std::vector<IntermissionLifecycleProofRecord> lifecycleProofs;
    std::vector<IntermissionAddressProofRecord> addressProofs;
    std::set<std::uint16_t> inheritedBlockerPCs;
    std::set<std::uint16_t> refinedInheritedBlockerPCs;
    std::set<std::uint16_t> remainingBlockerPCs;
};

class IntermissionAnalysis {
public:
    static IntermissionAnalysisResult analyze(const Analyzer& analyzer,
                                        const std::vector<HardwareAccessRecord>& hardwareAccesses,
                                        const std::vector<MazeTopologyRetryLoopProofRecord>& mazeTopologyRetryProofs,
                                        const std::vector<MazeTopologyAddressProofRecord>& mazeTopologyAddressProofs);
    static std::string dispatchKindText(IntermissionDispatchKind kind);
    static std::string writerKindText(IntermissionWriterKind kind);
    static bool semanticRomClosureEligible(const IntermissionAddressProofRecord& proof);
};

} // namespace pacripper
