#pragma once
// PacRipper secondary system-root logic final system-root residual-bank native coverage
// Created by Jacob Hodgkins

#include "SystemRootPrimaryNativeLogic.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pacripper {

enum class SystemRootSecondaryLogicFamily {
    SystemRootIsland05A5,
    SystemRootIsland0A89,
    SystemRootIsland0AA6,
    SystemRootIsland0AC8,
    SystemRootIsland0C09,
    SystemRootIsland0C15,
    SystemRootIsland0C47,
    SystemRootIsland0E2B,
    SystemRootIsland0E3B,
    SystemRootIsland0EB2,
    SystemRootIsland0EFC,
    SystemRootIsland101F,
    SystemRootIsland109E,
    SystemRootIsland10A8,
    SystemRootIsland10B4,
    SystemRootIsland10C0,
    SystemRootIsland123F,
    SystemRootIsland1277,
    SystemRootIsland1376,
    SystemRootIsland13FD
};

struct SystemRootSecondaryCoverageRecord {
    std::size_t id=0; std::string stableId; SystemRootSecondaryLogicFamily family=SystemRootSecondaryLogicFamily::SystemRootIsland05A5; std::uint16_t entryPC=0;
    std::vector<std::uint16_t> sourcePCs; std::size_t units=0; bool directNative=false; bool sourcePresent=false; std::string implementationStatus; std::string evidence;
};
struct SystemRootSecondaryValidationRecord { std::string stableId; std::uint16_t sourcePC=0; bool passed=false; std::string evidenceKind; std::string diagnostic; };
struct SystemRootSecondaryStats {
    std::size_t recoveredLogicUnits=0,baselineDirectNativeLogicUnits=0,additionalDirectNativeLogicUnits=0,directNativeLogicUnits=0,transitionalLogicUnits=0;
    std::size_t baselineCoverageFamilies=0,additionalCoverageFamilies=0,coverageFamilies=0;
    bool noOverlap=false,noGap=false,allSystemRootEvidence=false,legacyRootDeferred=false,coreOwnershipPreserved=false,schedulerUtilityOwnershipPreserved=false,coverageReady=false;
    std::size_t differentialChecks=0,differentialPassed=0,differentialFailed=0; bool endToEndNative=false;
};
class SystemRootSecondaryNativeLogicCoverage { public:
    static constexpr std::size_t FixedRecoveredLogicUnits=5414;
    static constexpr std::size_t BaselineDirectNativeLogicUnits=4711;
    static constexpr std::size_t AdditionalDirectNativeLogicUnits=699;
    static constexpr std::size_t DirectNativeLogicUnits=5410;
    static constexpr std::size_t TransitionalLogicUnits=4;
    static constexpr std::size_t BaselineCoverageFamilies=360;
    static constexpr std::size_t AdditionalCoverageFamilies=20;
    static std::string familyText(SystemRootSecondaryLogicFamily family); static const std::vector<SystemRootSecondaryCoverageRecord>& coverageManifest();
    static bool familyForEntry(std::uint16_t pc,SystemRootSecondaryLogicFamily& family); static bool familyForSourcePC(std::uint16_t pc,SystemRootSecondaryLogicFamily& family); static bool isCoveredSourcePC(std::uint16_t pc);
    static void buildCoverageLedger(const std::vector<GeneratedOperation>& operations,std::vector<SystemRootSecondaryCoverageRecord>& ledger,SystemRootSecondaryStats& stats);
    static bool executeNativeFamily(SystemRootSecondaryLogicFamily family,SemanticExecutionState& state,std::size_t& equivalentOperations,std::string& error,GeneratedExecutionBoundary* boundary=nullptr);
    static std::vector<GeneratedOperation> validationOperations();
    static std::vector<SystemRootSecondaryValidationRecord> runDifferentialValidation(const std::vector<std::uint8_t>& program,const std::vector<GeneratedOperation>& operations,SystemRootSecondaryStats& stats);
};

} // namespace pacripper
