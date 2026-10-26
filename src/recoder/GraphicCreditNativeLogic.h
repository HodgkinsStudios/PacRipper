#pragma once
// PacRipper graphic/credit utility logic RST-$20 consumer-cluster native coverage
// Created by Jacob Hodgkins

#include "SchedulerUtilityNativeLogic.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pacripper {

enum class GraphicCreditLogicFamily {
    GraphicSelector4D09,
    GraphicSelector4D08,
    GraphicSelector4D09Set7,
    GraphicSelector4D08Set6,
    CreditPresenceCallSetup
};

struct GraphicCreditCoverageRecord {
    std::size_t id=0;
    std::string stableId;
    GraphicCreditLogicFamily family=GraphicCreditLogicFamily::GraphicSelector4D09;
    std::uint16_t entryPC=0;
    std::vector<std::uint16_t> sourcePCs;
    std::size_t units=0;
    bool directNative=false;
    bool sourcePresent=false;
    std::string evidence;
};

struct GraphicCreditValidationRecord {
    std::string stableId;
    bool passed=false;
    std::string evidenceKind;
    std::string diagnostic;
};

struct GraphicCreditStats {
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

class GraphicCreditNativeLogicCoverage {
public:
    static constexpr std::size_t FixedRecoveredLogicUnits=5414;
    static constexpr std::size_t BaselineDirectNativeLogicUnits=920;
    static constexpr std::size_t PrimaryRst20ConsumerUnits=66;
    static constexpr std::size_t SecondaryNewConsumerUnits=1;
    static constexpr std::size_t AdditionalDirectNativeLogicUnits=67;
    static constexpr std::size_t DirectNativeLogicUnits=987;
    static constexpr std::size_t TransitionalLogicUnits=4427;
    static constexpr std::size_t AdditionalCoverageFamilies=5;

    static std::string familyText(GraphicCreditLogicFamily family);
    static const std::vector<GraphicCreditCoverageRecord>& coverageManifest();
    static bool familyForEntry(std::uint16_t pc,GraphicCreditLogicFamily& family);
    static bool isCoveredSourcePC(std::uint16_t pc);

    static void buildCoverageLedger(const std::vector<GeneratedOperation>& operations,
                                     std::vector<GraphicCreditCoverageRecord>& ledger,
                                     GraphicCreditStats& stats);

    static bool executeNativeFamily(GraphicCreditLogicFamily family,SemanticExecutionState& state,
                                    std::size_t& equivalentOperations,std::string& error,
                                    GeneratedExecutionBoundary* boundary=nullptr);

    static std::vector<GraphicCreditValidationRecord> runDifferentialValidation(
        const std::vector<std::uint8_t>& program,
        const std::vector<GeneratedOperation>& operations,
        GraphicCreditStats& stats);
};

} // namespace pacripper
