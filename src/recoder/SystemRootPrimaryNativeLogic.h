#pragma once
// PacRipper primary system-root logic system-root residual island native coverage
// Created by Jacob Hodgkins

#include "IntermissionStateNativeLogic.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pacripper {

enum class SystemRootPrimaryLogicFamily {
    SystemRootIsland171D,
    SystemRootIsland19C8,
    SystemRootIsland1A42,
    SystemRootIsland1C08,
    SystemRootIsland1C19,
    SystemRootIsland1CDF,
    SystemRootIsland1CF0,
    SystemRootIsland1DB6,
    SystemRootIsland1DC7,
    SystemRootIsland1E8D,
    SystemRootIsland1E9E
};

struct SystemRootPrimaryCoverageRecord {
    std::size_t id=0; std::string stableId; SystemRootPrimaryLogicFamily family=SystemRootPrimaryLogicFamily::SystemRootIsland171D; std::uint16_t entryPC=0;
    std::vector<std::uint16_t> sourcePCs; std::size_t units=0; bool directNative=false; bool sourcePresent=false; std::string implementationStatus; std::string evidence;
};
struct SystemRootPrimaryValidationRecord { std::string stableId; std::uint16_t sourcePC=0; bool passed=false; std::string evidenceKind; std::string diagnostic; };
struct SystemRootPrimaryStats {
    std::size_t recoveredLogicUnits=0,baselineDirectNativeLogicUnits=0,additionalDirectNativeLogicUnits=0,directNativeLogicUnits=0,transitionalLogicUnits=0;
    std::size_t baselineCoverageFamilies=0,additionalCoverageFamilies=0,coverageFamilies=0;
    bool noOverlap=false,noGap=false,allSystemRootEvidence=false,protectedIslandGapsUnowned=false,coreOwnershipPreserved=false,schedulerUtilityOwnershipPreserved=false,coverageReady=false;
    std::size_t differentialChecks=0,differentialPassed=0,differentialFailed=0; bool endToEndNative=false;
};
class SystemRootPrimaryNativeLogicCoverage { public:
    static constexpr std::size_t FixedRecoveredLogicUnits=5414;
    static constexpr std::size_t BaselineDirectNativeLogicUnits=3781;
    static constexpr std::size_t AdditionalDirectNativeLogicUnits=930;
    static constexpr std::size_t DirectNativeLogicUnits=4711;
    static constexpr std::size_t TransitionalLogicUnits=703;
    static constexpr std::size_t BaselineCoverageFamilies=349;
    static constexpr std::size_t AdditionalCoverageFamilies=11;
    static std::string familyText(SystemRootPrimaryLogicFamily family); static const std::vector<SystemRootPrimaryCoverageRecord>& coverageManifest();
    static bool familyForEntry(std::uint16_t pc,SystemRootPrimaryLogicFamily& family); static bool familyForSourcePC(std::uint16_t pc,SystemRootPrimaryLogicFamily& family); static bool isCoveredSourcePC(std::uint16_t pc);
    static void buildCoverageLedger(const std::vector<GeneratedOperation>& operations,std::vector<SystemRootPrimaryCoverageRecord>& ledger,SystemRootPrimaryStats& stats);
    static bool executeNativeFamily(SystemRootPrimaryLogicFamily family,SemanticExecutionState& state,std::size_t& equivalentOperations,std::string& error,GeneratedExecutionBoundary* boundary=nullptr);
    static std::vector<GeneratedOperation> validationOperations();
    static std::vector<SystemRootPrimaryValidationRecord> runDifferentialValidation(const std::vector<std::uint8_t>& program,const std::vector<GeneratedOperation>& operations,SystemRootPrimaryStats& stats);
};

} // namespace pacripper
