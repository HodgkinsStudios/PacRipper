#pragma once
// PacRipper scheduler/dispatch utility logic interrupt-safe scheduler/dispatch utility native coverage
// Created by Jacob Hodgkins

#include "RstUtilityNativeLogic.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pacripper {

enum class SchedulerUtilityLogicFamily {
    SchedulerLoadQueuePointer,
    SchedulerLoadCommand,
    SchedulerAndCommand,
    SchedulerJumpNegative,
    SchedulerMarkCommandConsumed,
    SchedulerIncrementQueueLow1,
    SchedulerLoadArgument,
    SchedulerMarkArgumentConsumed,
    SchedulerIncrementQueueLow2,
    SchedulerWrapBranch,
    SchedulerWrapLow,
    SchedulerStoreQueuePointer,
    SchedulerPrepareRestart,
    SchedulerPushRestart,
    SchedulerDispatchTask,
    UtilityIncrementCounterLoad,
    UtilityIncrementCounter,
    UtilityIncrementCounterReturn,
    UtilityDispatchLoadArgument,
    UtilityDispatchTask,
    UtilityNoopReturn
};

struct SchedulerUtilityCoverageRecord {
    std::size_t id=0;
    std::string stableId;
    SchedulerUtilityLogicFamily family=SchedulerUtilityLogicFamily::SchedulerLoadQueuePointer;
    std::uint16_t entryPC=0;
    std::vector<std::uint16_t> sourcePCs;
    std::size_t units=0;
    bool directNative=false;
    bool sourcePresent=false;
    std::string evidence;
};

struct SchedulerUtilityValidationRecord {
    std::string stableId;
    bool passed=false;
    std::string evidenceKind;
    std::string diagnostic;
};

struct SchedulerUtilityStats {
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
    bool endToEndNative=false;
};

class SchedulerUtilityNativeLogicCoverage {
public:
    static constexpr std::size_t FixedRecoveredLogicUnits=5414;
    static constexpr std::size_t BaselineDirectNativeLogicUnits=899;
    static constexpr std::size_t PrimarySchedulerUnits=15;
    static constexpr std::size_t SecondaryUtilityUnits=6;
    static constexpr std::size_t AdditionalDirectNativeLogicUnits=21;
    static constexpr std::size_t DirectNativeLogicUnits=920;
    static constexpr std::size_t TransitionalLogicUnits=4494;
    static constexpr std::size_t AdditionalCoverageFamilies=21;

    static std::string familyText(SchedulerUtilityLogicFamily family);
    static const std::vector<SchedulerUtilityCoverageRecord>& coverageManifest();
    static bool familyForEntry(std::uint16_t pc,SchedulerUtilityLogicFamily& family);
    static bool isCoveredSourcePC(std::uint16_t pc);

    static void buildCoverageLedger(const std::vector<GeneratedOperation>& operations,
                                     std::vector<SchedulerUtilityCoverageRecord>& ledger,
                                     SchedulerUtilityStats& stats);

    static bool executeNativeFamily(SchedulerUtilityLogicFamily family,SemanticExecutionState& state,
                                    std::size_t& equivalentOperations,std::string& error,
                                    GeneratedExecutionBoundary* boundary=nullptr);

    static std::vector<SchedulerUtilityValidationRecord> runDifferentialValidation(
        const std::vector<std::uint8_t>& program,
        const std::vector<GeneratedOperation>& operations,
        SchedulerUtilityStats& stats);
};

} // namespace pacripper
