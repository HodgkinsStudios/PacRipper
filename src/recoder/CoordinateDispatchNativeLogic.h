#pragma once
// PacRipper coordinate/dispatch logic direct-cold coordinate/address helper coverage
// Created by Jacob Hodgkins

#include "ColdHelperNativeLogic.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pacripper {

enum class CoordinateDispatchLogicFamily {
    ColdCoordinateTrampoline0065,
    ColdCoordinateAccum2000,
    ColdCoordinateProbe200F,
    ColdCoordinateInverse2018,
    ColdCoordinateMap202D,
    ColdTaskDispatch0263,
    ColdTaskDispatch1000,
    ColdTaskDispatch100B,
    ColdTaskDispatch1272,
    ColdTileAddress2052,
    ColdTileCollision205A,
    ColdState2069,
    ColdState208C,
    ColdState20AF,
    ColdState20D7,
    ColdMode04D8,
    ColdMode04E0,
    ColdMode051C,
    ColdMode054B,
    ColdMode0556,
    ColdMode0561,
    ColdMode056C,
    ColdMode057C,
    ColdMainDispatch0940,
    ColdMainDispatch09E8,
    ColdMode211A,
    ColdMode2140,
    ColdMode214B,
    ColdMode2170,
    ColdMode217B,
    ColdMode2186
};

struct CoordinateDispatchCoverageRecord {
    std::size_t id=0; std::string stableId; CoordinateDispatchLogicFamily family=CoordinateDispatchLogicFamily::ColdCoordinateTrampoline0065; std::uint16_t entryPC=0;
    std::vector<std::uint16_t> sourcePCs; std::size_t units=0; bool directNative=false; bool sourcePresent=false; std::string implementationStatus; std::string evidence;
};
struct CoordinateDispatchValidationRecord { std::string stableId; std::uint16_t sourcePC=0; bool passed=false; std::string evidenceKind; std::string diagnostic; };
struct CoordinateDispatchStats {
    std::size_t recoveredLogicUnits=0,baselineDirectNativeLogicUnits=0,additionalDirectNativeLogicUnits=0,directNativeLogicUnits=0,transitionalLogicUnits=0;
    std::size_t baselineCoverageFamilies=0,additionalCoverageFamilies=0,coverageFamilies=0;
    bool noOverlap=false,noGap=false,protectedInlineDataUnowned=false,taskDispatchInlineDataUnowned=false,systemUtilityInlineDataUnowned=false,startupTablesUnowned=false,stateDispatchInlineDataUnowned=false,setupLookupDataUnowned=false,setupAuxDataUnowned=false,scoreDescriptorDataUnowned=false,coordinateGapDataUnowned=false,coordinateDispatchInlineDataUnowned=false,schedulerUtilityOwnershipPreserved=false,coverageReady=false;
    std::size_t differentialChecks=0,differentialPassed=0,differentialFailed=0; bool endToEndNative=false;
};
class CoordinateDispatchNativeLogicCoverage { public:
    static constexpr std::size_t FixedRecoveredLogicUnits=5414;
    static constexpr std::size_t BaselineDirectNativeLogicUnits=3354;
    static constexpr std::size_t AdditionalDirectNativeLogicUnits=314;
    static constexpr std::size_t DirectNativeLogicUnits=3668;
    static constexpr std::size_t TransitionalLogicUnits=1746;
    static constexpr std::size_t BaselineCoverageFamilies=301;
    static constexpr std::size_t AdditionalCoverageFamilies=31;
    static std::string familyText(CoordinateDispatchLogicFamily family); static const std::vector<CoordinateDispatchCoverageRecord>& coverageManifest();
    static bool familyForEntry(std::uint16_t pc,CoordinateDispatchLogicFamily& family); static bool familyForSourcePC(std::uint16_t pc,CoordinateDispatchLogicFamily& family); static bool isCoveredSourcePC(std::uint16_t pc);
    static void buildCoverageLedger(const std::vector<GeneratedOperation>& operations,std::vector<CoordinateDispatchCoverageRecord>& ledger,CoordinateDispatchStats& stats);
    static bool executeNativeFamily(CoordinateDispatchLogicFamily family,SemanticExecutionState& state,std::size_t& equivalentOperations,std::string& error,GeneratedExecutionBoundary* boundary=nullptr);
    static std::vector<CoordinateDispatchValidationRecord> runDifferentialValidation(const std::vector<std::uint8_t>& program,const std::vector<GeneratedOperation>& operations,CoordinateDispatchStats& stats);
};

} // namespace pacripper
