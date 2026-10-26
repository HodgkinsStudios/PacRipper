#pragma once
// PacRipper startup utility logic RST-return utility + measured startup-memory-test native coverage
// Created by Jacob Hodgkins

#include "CoordinateRenderNativeLogic.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pacripper {

enum class StartupUtilityLogicFamily {
    Utility23F3Prefix,
    Utility23FBRst,
    Utility23FCContinuation,
    Utility2400Prefix,
    Utility2408Rst,
    Utility2409Continuation,
    Utility240DPrefix,
    Utility2414Rst,
    Utility2415Continuation,
    Render24D7Prefix,
    Render24E7Rst,
    Render24E8Continuation,
    Render24F3Tail,
    SharedFill0008,
    StartupMemoryTest3042
};

struct StartupUtilityCoverageRecord {
    std::size_t id=0;
    std::string stableId;
    StartupUtilityLogicFamily family=StartupUtilityLogicFamily::Utility23F3Prefix;
    std::uint16_t entryPC=0;
    std::vector<std::uint16_t> sourcePCs;
    std::size_t units=0;
    bool directNative=false;
    bool sourcePresent=false;
    std::string implementationStatus;
    std::string evidence;
};

struct StartupUtilityValidationRecord {
    std::string stableId;
    std::uint16_t sourcePC=0;
    bool passed=false;
    std::string evidenceKind;
    std::string diagnostic;
};

struct StartupUtilityStats {
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
    bool protectedInlineDataUnowned=false;
    bool coverageReady=false;
    std::size_t differentialChecks=0;
    std::size_t differentialPassed=0;
    std::size_t differentialFailed=0;
    bool endToEndNative=false;
};

class StartupUtilityNativeLogicCoverage {
public:
    static constexpr std::size_t FixedRecoveredLogicUnits=5414;
    static constexpr std::size_t BaselineDirectNativeLogicUnits=1446;
    static constexpr std::size_t AdditionalDirectNativeLogicUnits=151;
    static constexpr std::size_t DirectNativeLogicUnits=1597;
    static constexpr std::size_t TransitionalLogicUnits=3817;
    static constexpr std::size_t AdditionalCoverageFamilies=15;

    static std::string familyText(StartupUtilityLogicFamily family);
    static const std::vector<StartupUtilityCoverageRecord>& coverageManifest();
    static bool familyForEntry(std::uint16_t pc,StartupUtilityLogicFamily& family);
    static bool familyForSourcePC(std::uint16_t pc,StartupUtilityLogicFamily& family);
    static bool isCoveredSourcePC(std::uint16_t pc);

    static void buildCoverageLedger(const std::vector<GeneratedOperation>& operations,
                                     std::vector<StartupUtilityCoverageRecord>& ledger,
                                     StartupUtilityStats& stats);

    // startup utility logic is deliberately instruction-micro-dispatched. Every owned source PC is
    // independently dispatchable so hot loops cannot overrun the 8,192-op frame quantum.
    static bool executeNativeFamily(StartupUtilityLogicFamily family,SemanticExecutionState& state,
                                    std::size_t& equivalentOperations,std::string& error,
                                    GeneratedExecutionBoundary* boundary=nullptr);

    static std::vector<StartupUtilityValidationRecord> runDifferentialValidation(
        const std::vector<std::uint8_t>& program,
        const std::vector<GeneratedOperation>& operations,
        StartupUtilityStats& stats);
};

} // namespace pacripper
