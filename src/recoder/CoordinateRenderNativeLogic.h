#pragma once
// PacRipper coordinate/render logic coordinate/render + measured-frontier native coverage
// Created by Jacob Hodgkins

#include "FrameHelperNativeLogic.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pacripper {

enum class CoordinateRenderLogicFamily {
    CoordinatePrimary141F,
    CoordinateAlternate1490,
    SelectorDispatch14FE,
    PostSelector151C,
    RenderBase154B,
    RenderProjection154E,
    CallHelper15B4,
    CallHelper15B7,
    CallHelper15BA,
    RenderTail15BD,
    Helper15E6,
    Helper162D,
    Helper1652
};

struct CoordinateRenderCoverageRecord {
    std::size_t id=0;
    std::string stableId;
    CoordinateRenderLogicFamily family=CoordinateRenderLogicFamily::CoordinatePrimary141F;
    std::uint16_t entryPC=0;
    std::vector<std::uint16_t> sourcePCs;
    std::size_t units=0;
    bool directNative=false;
    bool sourcePresent=false;
    std::string implementationStatus;
    std::string evidence;
};

struct CoordinateRenderValidationRecord {
    std::string stableId;
    bool passed=false;
    std::string evidenceKind;
    std::string diagnostic;
};

struct CoordinateRenderStats {
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
    std::size_t differentialReferenceOperations=0;
    bool endToEndNative=false;
};

class CoordinateRenderNativeLogicCoverage {
public:
    static constexpr std::size_t FixedRecoveredLogicUnits=5414;
    static constexpr std::size_t BaselineDirectNativeLogicUnits=1149;
    static constexpr std::size_t AdditionalDirectNativeLogicUnits=297;
    static constexpr std::size_t DirectNativeLogicUnits=1446;
    static constexpr std::size_t TransitionalLogicUnits=3968;
    static constexpr std::size_t AdditionalCoverageFamilies=13;

    static std::string familyText(CoordinateRenderLogicFamily family);
    static const std::vector<CoordinateRenderCoverageRecord>& coverageManifest();
    static bool familyForEntry(std::uint16_t pc,CoordinateRenderLogicFamily& family);
    static bool isCoveredSourcePC(std::uint16_t pc);

    static void buildCoverageLedger(const std::vector<GeneratedOperation>& operations,
                                     std::vector<CoordinateRenderCoverageRecord>& ledger,
                                     CoordinateRenderStats& stats);

    static bool executeNativeFamily(CoordinateRenderLogicFamily family,SemanticExecutionState& state,
                                    std::size_t& equivalentOperations,std::string& error,
                                    GeneratedExecutionBoundary* boundary=nullptr);

    static std::vector<CoordinateRenderValidationRecord> runDifferentialValidation(
        const std::vector<std::uint8_t>& program,
        const std::vector<GeneratedOperation>& operations,
        CoordinateRenderStats& stats);
};

} // namespace pacripper
