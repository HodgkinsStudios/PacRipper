#pragma once
// PacRipper interrupt/task-scan logic measured interrupt/task-scan native coverage
// Created by Jacob Hodgkins

#include "StartupRuntimeNativeLogic.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pacripper {

enum class InterruptSchedulerLogicFamily {
    InterruptContinuationCalls018C,
    TaskScanSetup0221,
    TaskScanSelector022E,
    TaskScanCountdown0235,
    TaskScanDispatch023B,
    MazeStreamDecoder2419,
    ScoreDigitHelper2ACE,
    BootClearSeams230B,
    StartupDelayLoop327C,
    ScoreDigitCaller2ABE,
    SchedulerIncrement058E,
    PatternPrelude3246
};

struct InterruptSchedulerCoverageRecord {
    std::size_t id=0;
    std::string stableId;
    InterruptSchedulerLogicFamily family=InterruptSchedulerLogicFamily::InterruptContinuationCalls018C;
    std::uint16_t entryPC=0;
    std::vector<std::uint16_t> sourcePCs;
    std::size_t units=0;
    bool directNative=false;
    bool sourcePresent=false;
    std::string implementationStatus;
    std::string evidence;
};

struct InterruptSchedulerValidationRecord {
    std::string stableId;
    std::uint16_t sourcePC=0;
    bool passed=false;
    std::string evidenceKind;
    std::string diagnostic;
};

struct InterruptSchedulerStats {
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
    bool taskDispatchInlineDataUnowned=false;
    bool schedulerUtilityOwnershipPreserved=false;
    bool coverageReady=false;
    std::size_t differentialChecks=0;
    std::size_t differentialPassed=0;
    std::size_t differentialFailed=0;
    bool endToEndNative=false;
};

class InterruptSchedulerNativeLogicCoverage {
public:
    static constexpr std::size_t FixedRecoveredLogicUnits=5414;
    static constexpr std::size_t BaselineDirectNativeLogicUnits=1864;
    static constexpr std::size_t AdditionalDirectNativeLogicUnits=107;
    static constexpr std::size_t DirectNativeLogicUnits=1971;
    static constexpr std::size_t TransitionalLogicUnits=3443;
    static constexpr std::size_t BaselineCoverageFamilies=228;
    static constexpr std::size_t AdditionalCoverageFamilies=12;

    static std::string familyText(InterruptSchedulerLogicFamily family);
    static const std::vector<InterruptSchedulerCoverageRecord>& coverageManifest();
    static bool familyForEntry(std::uint16_t pc,InterruptSchedulerLogicFamily& family);
    static bool familyForSourcePC(std::uint16_t pc,InterruptSchedulerLogicFamily& family);
    static bool isCoveredSourcePC(std::uint16_t pc);

    static void buildCoverageLedger(const std::vector<GeneratedOperation>& operations,
                                     std::vector<InterruptSchedulerCoverageRecord>& ledger,
                                     InterruptSchedulerStats& stats);

    static bool executeNativeFamily(InterruptSchedulerLogicFamily family,SemanticExecutionState& state,
                                    std::size_t& equivalentOperations,std::string& error,
                                    GeneratedExecutionBoundary* boundary=nullptr);

    static std::vector<InterruptSchedulerValidationRecord> runDifferentialValidation(
        const std::vector<std::uint8_t>& program,
        const std::vector<GeneratedOperation>& operations,
        InterruptSchedulerStats& stats);
};

} // namespace pacripper
