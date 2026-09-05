#pragma once
// PacRipper HUD/board-state logic HUD / display / board-state native coverage
// Created by Jacob Hodgkins

#include "DisplayMapNativeLogic.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pacripper {

enum class HudBoardLogicFamily {
    HudTextRendererEntry,
    HudTextRendererCore,
    CommandDisplaySetupFirst,
    CommandDisplaySetupSecond,
    CommandDisplaySetupThird,
    CommandDisplayFinalize,
    BoardStateSetupFirst,
    BoardStateSetupSecond,
    BoardStateSetupThird,
    BoardStateSetupFinalize
};

struct HudBoardCoverageRecord {
    std::size_t id=0;
    std::string stableId;
    HudBoardLogicFamily family=HudBoardLogicFamily::HudTextRendererEntry;
    std::uint16_t entryPC=0;
    std::vector<std::uint16_t> sourcePCs;
    std::size_t units=0;
    bool directNative=false;
    bool sourcePresent=false;
    std::string evidence;
};

struct HudBoardValidationRecord {
    std::string stableId;
    bool passed=false;
    std::string evidenceKind;
    std::string diagnostic;
};

struct HudBoardStats {
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
    std::uint64_t lifecycleTextRendererFirstFrame=0;
    std::uint64_t lifecycleCommandDisplayFirstFrame=0;
    std::uint64_t lifecycleBoardStateFirstFrame=0;
    bool canonicalHybridPass=false;
    bool lifecycleInputScenarioPass=false;
    bool endToEndNative=false;
};

class HudBoardNativeLogicCoverage {
public:
    static constexpr std::size_t FixedRecoveredLogicUnits=5414;
    static constexpr std::size_t BaselineDirectNativeLogicUnits=484;
    static constexpr std::size_t AdditionalDirectNativeLogicUnits=103;
    static constexpr std::size_t DirectNativeLogicUnits=587;
    static constexpr std::size_t TransitionalLogicUnits=4827;
    static constexpr std::size_t AdditionalCoverageFamilies=10;

    static std::string familyText(HudBoardLogicFamily family);
    static const std::vector<HudBoardCoverageRecord>& coverageManifest();
    static bool familyForEntry(std::uint16_t pc,HudBoardLogicFamily& family);
    static bool isCoveredSourcePC(std::uint16_t pc);

    static void buildCoverageLedger(const std::vector<GeneratedOperation>& operations,
                                     std::vector<HudBoardCoverageRecord>& ledger,
                                     HudBoardStats& stats);

    static bool executeNativeFamily(HudBoardLogicFamily family,SemanticExecutionState& state,
                                    std::size_t& equivalentOperations,std::string& error,
                                    GeneratedExecutionBoundary* boundary=nullptr);

    static std::vector<HudBoardValidationRecord> runDifferentialValidation(
        const std::vector<std::uint8_t>& program,
        const std::vector<GeneratedOperation>& operations,
        HudBoardStats& stats);
};

} // namespace pacripper
