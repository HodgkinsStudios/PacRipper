#pragma once
// PacRipper system utility logic measured residual-frontier native coverage
// Created by Jacob Hodgkins

#include "InterruptSchedulerNativeLogic.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pacripper {

enum class SystemUtilityLogicFamily {
    StartupOutputLatchLoop3174,
    MainModeDispatchTail03D4,
    TaskQueueAppend0580,
    DelayedCommand0593,
    ActorStateInit253D,
    CoinCounterHelper02DF,
    CreditStateHandlerBank045F,
    ScreenLabelWriter05BF,
    StartSubstateHandler05F3,
    StartCreditDisplayCall061B,
    CreditModeInit2698,
    CreditDigits26B2,
    DipInputDecode26D0,
    ScoreDisplayPrep2AE0,
    StartupSchedulerTransfer233B
};

struct SystemUtilityCoverageRecord {
    std::size_t id=0;
    std::string stableId;
    SystemUtilityLogicFamily family=SystemUtilityLogicFamily::StartupOutputLatchLoop3174;
    std::uint16_t entryPC=0;
    std::vector<std::uint16_t> sourcePCs;
    std::size_t units=0;
    bool directNative=false;
    bool sourcePresent=false;
    std::string implementationStatus;
    std::string evidence;
};

struct SystemUtilityValidationRecord {
    std::string stableId;
    std::uint16_t sourcePC=0;
    bool passed=false;
    std::string evidenceKind;
    std::string diagnostic;
};

struct SystemUtilityStats {
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
    bool systemUtilityInlineDataUnowned=false;
    bool schedulerUtilityOwnershipPreserved=false;
    bool coverageReady=false;
    std::size_t differentialChecks=0;
    std::size_t differentialPassed=0;
    std::size_t differentialFailed=0;
    bool endToEndNative=false;
};

class SystemUtilityNativeLogicCoverage {
public:
    static constexpr std::size_t FixedRecoveredLogicUnits=5414;
    static constexpr std::size_t BaselineDirectNativeLogicUnits=1971;
    static constexpr std::size_t AdditionalDirectNativeLogicUnits=349;
    static constexpr std::size_t DirectNativeLogicUnits=2320;
    static constexpr std::size_t TransitionalLogicUnits=3094;
    static constexpr std::size_t BaselineCoverageFamilies=240;
    static constexpr std::size_t AdditionalCoverageFamilies=15;

    static std::string familyText(SystemUtilityLogicFamily family);
    static const std::vector<SystemUtilityCoverageRecord>& coverageManifest();
    static bool familyForEntry(std::uint16_t pc,SystemUtilityLogicFamily& family);
    static bool familyForSourcePC(std::uint16_t pc,SystemUtilityLogicFamily& family);
    static bool isCoveredSourcePC(std::uint16_t pc);

    static void buildCoverageLedger(const std::vector<GeneratedOperation>& operations,
                                     std::vector<SystemUtilityCoverageRecord>& ledger,
                                     SystemUtilityStats& stats);

    static bool executeNativeFamily(SystemUtilityLogicFamily family,SemanticExecutionState& state,
                                    std::size_t& equivalentOperations,std::string& error,
                                    GeneratedExecutionBoundary* boundary=nullptr);

    static std::vector<SystemUtilityValidationRecord> runDifferentialValidation(
        const std::vector<std::uint8_t>& program,
        const std::vector<GeneratedOperation>& operations,
        SystemUtilityStats& stats);
};

} // namespace pacripper
