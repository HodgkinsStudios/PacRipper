#pragma once
// PacRipper maze-preparation logic direct native game-logic implementation:
// Created by Jacob Hodgkins

#include "../decomp/SessionInitializationNativeLogic.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pacripper {

enum class MazePreparationLogicFamily {
    SessionLifeDecrementAndMazePrepCall,
    SessionModeAdvanceCompletion,
    AttractStateZeroFieldClearCall,
    StartStateMapHelperCall,
    MazePreparationModeGate,
    InlineRectangleFillHelper,
    MazePreparationLivesTail
};

struct MazePreparationCoverageRecord {
    std::size_t id=0;
    std::string stableId;
    MazePreparationLogicFamily family=MazePreparationLogicFamily::SessionLifeDecrementAndMazePrepCall;
    std::uint16_t entryPC=0;
    std::vector<std::uint16_t> sourcePCs;
    std::size_t units=0;
    bool directNative=false;
    bool sourcePresent=false;
    std::string evidence;
};

struct MazePreparationValidationRecord {
    std::string stableId;
    bool passed=false;
    std::string evidenceKind;
    std::string diagnostic;
};

struct MazePreparationStats {
    std::size_t recoveredLogicUnits=0;
    std::size_t baselineDirectNativeLogicUnits=0;
    std::size_t additionalDirectNativeLogicUnits=0;
    std::size_t directNativeLogicUnits=0;
    std::size_t transitionalLogicUnits=0;
    std::size_t baselineCoverageFamilies=0;
    std::size_t additionalCoverageFamilies=0;
    std::size_t coverageFamilies=0;
    bool noOverlap=false;
    bool noGap=false;
    bool coverageReady=false;
    std::size_t differentialChecks=0;
    std::size_t differentialPassed=0;
    std::size_t differentialFailed=0;
    std::size_t differentialReferenceOperations=0;
    std::size_t canonicalChecks=0;
    std::size_t canonicalPassed=0;
    std::size_t canonicalFailed=0;
    std::size_t lifecycleChecks=0;
    std::size_t lifecyclePassed=0;
    std::size_t lifecycleFailed=0;
    std::uint64_t canonicalReferenceOperations=0;
    std::uint64_t canonicalHybridOperations=0;
    std::uint64_t canonicalTransitionalOperations=0;
    std::uint64_t canonicalReferenceSessionHash=0;
    std::uint64_t canonicalHybridSessionHash=0;
    std::uint64_t lifecycleReferenceOperations=0;
    std::uint64_t lifecycleHybridOperations=0;
    std::uint64_t lifecycleTransitionalOperations=0;
    std::uint64_t lifecycleReferenceSessionHash=0;
    std::uint64_t lifecycleHybridSessionHash=0;
    std::size_t lifecycleNewFamiliesObserved=0;
    std::uint64_t lifecycleNewFamilyInvocations=0;
    std::uint64_t lifecyclePrimaryEntryFirstFrame=0;
    std::uint64_t lifecyclePrimaryCompletionFirstFrame=0;
    std::uint64_t lifecycleAttractBridgeFirstFrame=0;
    std::uint64_t lifecycleStartBridgeFirstFrame=0;
    bool canonicalHybridPass=false;
    bool lifecycleInputScenarioPass=false;
    bool endToEndNative=false;
};

class MazePreparationNativeLogicCoverage {
public:
    static constexpr std::size_t FixedRecoveredLogicUnits=5414;
    static constexpr std::size_t BaselineDirectNativeLogicUnits=340;
    static constexpr std::size_t AdditionalDirectNativeLogicUnits=44;
    static constexpr std::size_t DirectNativeLogicUnits=BaselineDirectNativeLogicUnits+AdditionalDirectNativeLogicUnits;
    static constexpr std::size_t TransitionalLogicUnits=FixedRecoveredLogicUnits-DirectNativeLogicUnits;
    static constexpr std::size_t AdditionalCoverageFamilies=7;

    static std::string familyText(MazePreparationLogicFamily family);
    static const std::vector<MazePreparationCoverageRecord>& coverageManifest();
    static bool familyForEntry(std::uint16_t pc,MazePreparationLogicFamily& family);
    static bool isCoveredSourcePC(std::uint16_t pc);

    static void buildCoverageLedger(const std::vector<GeneratedOperation>& operations,
                                     std::vector<MazePreparationCoverageRecord>& ledger,
                                     MazePreparationStats& stats);

    static bool executeNativeFamily(MazePreparationLogicFamily family,SemanticExecutionState& state,
                                    std::size_t& equivalentOperations,std::string& error,
                                    GeneratedExecutionBoundary* boundary=nullptr);

    static std::vector<MazePreparationValidationRecord> runDifferentialValidation(
        const std::vector<std::uint8_t>& program,
        const std::vector<GeneratedOperation>& operations,
        MazePreparationStats& stats);
};

} // namespace pacripper
