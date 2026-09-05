#pragma once
// PacRipper cold helper logic residual RST-$20 / cold indirect native coverage
// Created by Jacob Hodgkins

#include "ColdStateNativeLogic.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pacripper {

enum class ColdHelperLogicFamily {
    ColdRst20Trampoline000D,
    ColdSetupTable070E,
    ColdSetupCopy0814,
    ColdSetupCopy083A,
    ColdMotion2730,
    ColdMotion276C,
    ColdMotion27A9,
    ColdMotion27F1,
    ColdMotion283B,
    ColdMotion2865,
    ColdMotion288F,
    ColdMotion28B9,
    ColdMotion28E3,
    ColdMotionSelect291E,
    ColdMotionSearch2966,
    ColdDistance29EA,
    ColdMultiply2A12,
    ColdIndex2A23,
    ColdScoreUpdate2A5A,
    ColdScoreRender2AAF,
    ColdScoreSelect2B0B,
    ColdExtraLife2B33,
    ColdFruitHud2BEA
};

struct ColdHelperCoverageRecord {
    std::size_t id=0; std::string stableId; ColdHelperLogicFamily family=ColdHelperLogicFamily::ColdRst20Trampoline000D; std::uint16_t entryPC=0;
    std::vector<std::uint16_t> sourcePCs; std::size_t units=0; bool directNative=false; bool sourcePresent=false; std::string implementationStatus; std::string evidence;
};
struct ColdHelperValidationRecord { std::string stableId; std::uint16_t sourcePC=0; bool passed=false; std::string evidenceKind; std::string diagnostic; };
struct ColdHelperStats {
    std::size_t recoveredLogicUnits=0,baselineDirectNativeLogicUnits=0,additionalDirectNativeLogicUnits=0,directNativeLogicUnits=0,transitionalLogicUnits=0;
    std::size_t baselineCoverageFamilies=0,additionalCoverageFamilies=0,coverageFamilies=0;
    bool noOverlap=false,noGap=false,protectedInlineDataUnowned=false,taskDispatchInlineDataUnowned=false,systemUtilityInlineDataUnowned=false,startupTablesUnowned=false,stateDispatchInlineDataUnowned=false,setupLookupDataUnowned=false,setupAuxDataUnowned=false,schedulerUtilityOwnershipPreserved=false,coverageReady=false;
    std::size_t differentialChecks=0,differentialPassed=0,differentialFailed=0; bool endToEndNative=false;
};
class ColdHelperNativeLogicCoverage { public:
    static constexpr std::size_t FixedRecoveredLogicUnits=5414;
    static constexpr std::size_t BaselineDirectNativeLogicUnits=2801;
    static constexpr std::size_t AdditionalDirectNativeLogicUnits=553;
    static constexpr std::size_t DirectNativeLogicUnits=3354;
    static constexpr std::size_t TransitionalLogicUnits=2060;
    static constexpr std::size_t BaselineCoverageFamilies=278;
    static constexpr std::size_t AdditionalCoverageFamilies=23;
    static std::string familyText(ColdHelperLogicFamily family); static const std::vector<ColdHelperCoverageRecord>& coverageManifest();
    static bool familyForEntry(std::uint16_t pc,ColdHelperLogicFamily& family); static bool familyForSourcePC(std::uint16_t pc,ColdHelperLogicFamily& family); static bool isCoveredSourcePC(std::uint16_t pc);
    static void buildCoverageLedger(const std::vector<GeneratedOperation>& operations,std::vector<ColdHelperCoverageRecord>& ledger,ColdHelperStats& stats);
    static bool executeNativeFamily(ColdHelperLogicFamily family,SemanticExecutionState& state,std::size_t& equivalentOperations,std::string& error,GeneratedExecutionBoundary* boundary=nullptr);
    static std::vector<ColdHelperValidationRecord> runDifferentialValidation(const std::vector<std::uint8_t>& program,const std::vector<GeneratedOperation>& operations,ColdHelperStats& stats);
};
} // namespace pacripper
