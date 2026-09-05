#pragma once
// PacRipper object/input logic main-frame callee cluster native coverage
// Created by Jacob Hodgkins

#include "FrameUpdateNativeLogic.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pacripper {

enum class ObjectInputLogicFamily {
    ObjectPositionProjection039D,
    CoinInputFront0267,
    CoinInputTail0286,
    CoinPulseFront02AD,
    CoinPulseTail02C4
};

struct ObjectInputCoverageRecord {
    std::size_t id=0;
    std::string stableId;
    ObjectInputLogicFamily family=ObjectInputLogicFamily::ObjectPositionProjection039D;
    std::uint16_t entryPC=0;
    std::vector<std::uint16_t> sourcePCs;
    std::size_t units=0;
    bool directNative=false;
    bool sourcePresent=false;
    std::string evidence;
};

struct ObjectInputValidationRecord {
    std::string stableId;
    bool passed=false;
    std::string evidenceKind;
    std::string diagnostic;
};

struct ObjectInputStats {
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

class ObjectInputNativeLogicCoverage {
public:
    static constexpr std::size_t FixedRecoveredLogicUnits=5414;
    static constexpr std::size_t BaselineDirectNativeLogicUnits=1002;
    static constexpr std::size_t AdditionalDirectNativeLogicUnits=80;
    static constexpr std::size_t DirectNativeLogicUnits=1082;
    static constexpr std::size_t TransitionalLogicUnits=4332;
    static constexpr std::size_t AdditionalCoverageFamilies=5;

    static std::string familyText(ObjectInputLogicFamily family);
    static const std::vector<ObjectInputCoverageRecord>& coverageManifest();
    static bool familyForEntry(std::uint16_t pc,ObjectInputLogicFamily& family);
    static bool isCoveredSourcePC(std::uint16_t pc);

    static void buildCoverageLedger(const std::vector<GeneratedOperation>& operations,
                                     std::vector<ObjectInputCoverageRecord>& ledger,
                                     ObjectInputStats& stats);

    static bool executeNativeFamily(ObjectInputLogicFamily family,SemanticExecutionState& state,
                                    std::size_t& equivalentOperations,std::string& error,
                                    GeneratedExecutionBoundary* boundary=nullptr);

    static std::vector<ObjectInputValidationRecord> runDifferentialValidation(
        const std::vector<std::uint8_t>& program,
        const std::vector<GeneratedOperation>& operations,
        ObjectInputStats& stats);
};

} // namespace pacripper
