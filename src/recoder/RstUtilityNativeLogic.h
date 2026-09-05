#pragma once
// PacRipper RST utility logic shared RST utility/finalizer native coverage
// Created by Jacob Hodgkins

#include "CommandInterpreterNativeLogic.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pacripper {

enum class RstUtilityLogicFamily {
    Rst10IndexedLookup,
    Rst18DescriptorPrelude,
    Rst18DescriptorReturn,
    Rst20DispatchPrelude,
    Rst20DispatchReturn,
    InterruptFinalizerCall,
    InterruptFinalizerReturn
};

struct RstUtilityCoverageRecord {
    std::size_t id=0;
    std::string stableId;
    RstUtilityLogicFamily family=RstUtilityLogicFamily::Rst10IndexedLookup;
    std::uint16_t entryPC=0;
    std::vector<std::uint16_t> sourcePCs;
    std::size_t units=0;
    bool directNative=false;
    bool sourcePresent=false;
    std::string evidence;
};

struct RstUtilityValidationRecord {
    std::string stableId;
    bool passed=false;
    std::string evidenceKind;
    std::string diagnostic;
};

struct RstUtilityStats {
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

class RstUtilityNativeLogicCoverage {
public:
    static constexpr std::size_t FixedRecoveredLogicUnits=5414;
    static constexpr std::size_t BaselineDirectNativeLogicUnits=859;
    static constexpr std::size_t PrimaryRstUtilityUnits=23;
    static constexpr std::size_t SecondaryFinalizerUnits=17;
    static constexpr std::size_t AdditionalDirectNativeLogicUnits=40;
    static constexpr std::size_t DirectNativeLogicUnits=899;
    static constexpr std::size_t TransitionalLogicUnits=4515;
    static constexpr std::size_t AdditionalCoverageFamilies=7;

    static std::string familyText(RstUtilityLogicFamily family);
    static const std::vector<RstUtilityCoverageRecord>& coverageManifest();
    static bool familyForEntry(std::uint16_t pc,RstUtilityLogicFamily& family);
    static bool isCoveredSourcePC(std::uint16_t pc);

    static void buildCoverageLedger(const std::vector<GeneratedOperation>& operations,
                                     std::vector<RstUtilityCoverageRecord>& ledger,
                                     RstUtilityStats& stats);

    static bool executeNativeFamily(RstUtilityLogicFamily family,SemanticExecutionState& state,
                                    std::size_t& equivalentOperations,std::string& error,
                                    GeneratedExecutionBoundary* boundary=nullptr);

    static std::vector<RstUtilityValidationRecord> runDifferentialValidation(
        const std::vector<std::uint8_t>& program,
        const std::vector<GeneratedOperation>& operations,
        RstUtilityStats& stats);
};

} // namespace pacripper
