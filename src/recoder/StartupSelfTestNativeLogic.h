#pragma once
// PacRipper startup self-test logic startup self-test residual native coverage
// Created by Jacob Hodgkins

#include "SystemUtilityNativeLogic.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pacripper {

enum class StartupSelfTestLogicFamily {
    StartupClearSeams30BD,
    StartupDiagnostic30FB,
    StartupConfiguration3188,
    StartupInputSelfTest3286
};

struct StartupSelfTestCoverageRecord {
    std::size_t id=0;
    std::string stableId;
    StartupSelfTestLogicFamily family=StartupSelfTestLogicFamily::StartupClearSeams30BD;
    std::uint16_t entryPC=0;
    std::vector<std::uint16_t> sourcePCs;
    std::size_t units=0;
    bool directNative=false;
    bool sourcePresent=false;
    std::string implementationStatus;
    std::string evidence;
};

struct StartupSelfTestValidationRecord { std::string stableId; std::uint16_t sourcePC=0; bool passed=false; std::string evidenceKind; std::string diagnostic; };
struct StartupSelfTestStats {
    std::size_t recoveredLogicUnits=0,baselineDirectNativeLogicUnits=0,additionalDirectNativeLogicUnits=0,directNativeLogicUnits=0,transitionalLogicUnits=0;
    std::size_t baselineCoverageFamilies=0,additionalCoverageFamilies=0,coverageFamilies=0;
    bool noOverlap=false,noGap=false,protectedInlineDataUnowned=false,taskDispatchInlineDataUnowned=false,systemUtilityInlineDataUnowned=false,startupTablesUnowned=false,schedulerUtilityOwnershipPreserved=false,coverageReady=false;
    std::size_t differentialChecks=0,differentialPassed=0,differentialFailed=0; bool endToEndNative=false;
};

class StartupSelfTestNativeLogicCoverage {
public:
    static constexpr std::size_t FixedRecoveredLogicUnits=5414;
    static constexpr std::size_t BaselineDirectNativeLogicUnits=2320;
    static constexpr std::size_t AdditionalDirectNativeLogicUnits=199;
    static constexpr std::size_t DirectNativeLogicUnits=2519;
    static constexpr std::size_t TransitionalLogicUnits=2895;
    static constexpr std::size_t BaselineCoverageFamilies=255;
    static constexpr std::size_t AdditionalCoverageFamilies=4;
    static std::string familyText(StartupSelfTestLogicFamily family);
    static const std::vector<StartupSelfTestCoverageRecord>& coverageManifest();
    static bool familyForEntry(std::uint16_t pc,StartupSelfTestLogicFamily& family);
    static bool familyForSourcePC(std::uint16_t pc,StartupSelfTestLogicFamily& family);
    static bool isCoveredSourcePC(std::uint16_t pc);
    static void buildCoverageLedger(const std::vector<GeneratedOperation>& operations,std::vector<StartupSelfTestCoverageRecord>& ledger,StartupSelfTestStats& stats);
    static bool executeNativeFamily(StartupSelfTestLogicFamily family,SemanticExecutionState& state,std::size_t& equivalentOperations,std::string& error,GeneratedExecutionBoundary* boundary=nullptr);
    static std::vector<StartupSelfTestValidationRecord> runDifferentialValidation(const std::vector<std::uint8_t>& program,const std::vector<GeneratedOperation>& operations,StartupSelfTestStats& stats);
};

} // namespace pacripper
