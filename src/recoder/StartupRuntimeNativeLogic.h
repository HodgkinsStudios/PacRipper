#pragma once
// PacRipper startup runtime logic startup-delay + measured expansion native coverage
// Created by Jacob Hodgkins

#include "StartupUtilityNativeLogic.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pacripper {

enum class StartupRuntimeLogicFamily {
    StartupDelay32ED,
    StartupChecksum3000,
    HotLdir00A6,
    HotLdir00DE,
    HotLdir017F,
    HotLdir018A,
    TaskScanHotHead022A,
    TaskScanTail025D,
    BoardClear231A,
    BoardClear232B,
    StartupClear30C6,
    StartupClear30D6,
    StartupClear30E4,
    PatternFill3253,
    UpdateRoutine01DC,
    InterruptPrologue008D,
    InterruptOutputPrep00A8,
    InterruptSpriteRotate00E0,
    InterruptSwap0114,
    InterruptBufferSwap0153,
    InterruptSecondCopy0181
};

struct StartupRuntimeCoverageRecord {
    std::size_t id=0;
    std::string stableId;
    StartupRuntimeLogicFamily family=StartupRuntimeLogicFamily::StartupDelay32ED;
    std::uint16_t entryPC=0;
    std::vector<std::uint16_t> sourcePCs;
    std::size_t units=0;
    bool directNative=false;
    bool sourcePresent=false;
    std::string implementationStatus;
    std::string evidence;
};

struct StartupRuntimeValidationRecord {
    std::string stableId;
    std::uint16_t sourcePC=0;
    bool passed=false;
    std::string evidenceKind;
    std::string diagnostic;
};

struct StartupRuntimeStats {
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

class StartupRuntimeNativeLogicCoverage {
public:
    static constexpr std::size_t FixedRecoveredLogicUnits=5414;
    static constexpr std::size_t BaselineDirectNativeLogicUnits=1597;
    static constexpr std::size_t AdditionalDirectNativeLogicUnits=267;
    static constexpr std::size_t DirectNativeLogicUnits=1864;
    static constexpr std::size_t TransitionalLogicUnits=3550;
    static constexpr std::size_t BaselineCoverageFamilies=207;
    static constexpr std::size_t AdditionalCoverageFamilies=21;

    static std::string familyText(StartupRuntimeLogicFamily family);
    static const std::vector<StartupRuntimeCoverageRecord>& coverageManifest();
    static bool familyForEntry(std::uint16_t pc,StartupRuntimeLogicFamily& family);
    static bool familyForSourcePC(std::uint16_t pc,StartupRuntimeLogicFamily& family);
    static bool isCoveredSourcePC(std::uint16_t pc);

    static void buildCoverageLedger(const std::vector<GeneratedOperation>& operations,
                                     std::vector<StartupRuntimeCoverageRecord>& ledger,
                                     StartupRuntimeStats& stats);

    // Every owned startup runtime logic source PC is an instruction-level dispatch boundary.
    static bool executeNativeFamily(StartupRuntimeLogicFamily family,SemanticExecutionState& state,
                                    std::size_t& equivalentOperations,std::string& error,
                                    GeneratedExecutionBoundary* boundary=nullptr);

    static std::vector<StartupRuntimeValidationRecord> runDifferentialValidation(
        const std::vector<std::uint8_t>& program,
        const std::vector<GeneratedOperation>& operations,
        StartupRuntimeStats& stats);
};

} // namespace pacripper
