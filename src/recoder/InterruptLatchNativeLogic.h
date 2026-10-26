#pragma once
// PacRipper interrupt/latch logic final analyzer-root interrupt/latch island native coverage
// Created by Jacob Hodgkins

#include "SystemRootSecondaryNativeLogic.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pacripper {

enum class InterruptLatchLogicFamily {
    LegacyInterruptLatchIsland0038
};

struct InterruptLatchCoverageRecord {
    std::size_t id=0;
    std::string stableId;
    InterruptLatchLogicFamily family=InterruptLatchLogicFamily::LegacyInterruptLatchIsland0038;
    std::uint16_t entryPC=0;
    std::vector<std::uint16_t> sourcePCs;
    std::size_t units=0;
    bool directNative=false;
    bool sourcePresent=false;
    std::string implementationStatus;
    std::string evidence;
};

struct InterruptLatchValidationRecord {
    std::string stableId;
    std::uint16_t sourcePC=0;
    bool passed=false;
    std::string evidenceKind;
    std::string diagnostic;
};

struct InterruptLatchStats {
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
    bool legacyRootEvidence=false;
    bool closedInterruptLatchUnit=false;
    bool coreOwnershipPreserved=false;
    bool schedulerUtilityOwnershipPreserved=false;
    bool coverageReady=false;
    std::size_t differentialChecks=0;
    std::size_t differentialPassed=0;
    std::size_t differentialFailed=0;
    bool endToEndNative=false;
};

class InterruptLatchNativeLogicCoverage {
public:
    static constexpr std::size_t FixedRecoveredLogicUnits=5414;
    static constexpr std::size_t BaselineDirectNativeLogicUnits=5410;
    static constexpr std::size_t AdditionalDirectNativeLogicUnits=4;
    static constexpr std::size_t DirectNativeLogicUnits=5414;
    static constexpr std::size_t TransitionalLogicUnits=0;
    static constexpr std::size_t BaselineCoverageFamilies=380;
    static constexpr std::size_t AdditionalCoverageFamilies=1;

    static std::string familyText(InterruptLatchLogicFamily family);
    static const std::vector<InterruptLatchCoverageRecord>& coverageManifest();
    static bool familyForEntry(std::uint16_t pc,InterruptLatchLogicFamily& family);
    static bool familyForSourcePC(std::uint16_t pc,InterruptLatchLogicFamily& family);
    static bool isCoveredSourcePC(std::uint16_t pc);
    static void buildCoverageLedger(const std::vector<GeneratedOperation>& operations,std::vector<InterruptLatchCoverageRecord>& ledger,InterruptLatchStats& stats);
    static bool executeNativeFamily(InterruptLatchLogicFamily family,SemanticExecutionState& state,std::size_t& equivalentOperations,std::string& error,GeneratedExecutionBoundary* boundary=nullptr);
    static std::vector<GeneratedOperation> validationOperations();
    static std::vector<InterruptLatchValidationRecord> runDifferentialValidation(const std::vector<std::uint8_t>& program,const std::vector<GeneratedOperation>& operations,InterruptLatchStats& stats);
};

} // namespace pacripper
