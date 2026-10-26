#pragma once
// PacRipper intermission-state logic intermission indirect-dispatch native coverage
// Created by Jacob Hodgkins

#include "CoordinateDispatchNativeLogic.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pacripper {

enum class IntermissionStateLogicFamily {
    SecondIntermissionState0_21C2,
    SecondIntermissionState2_21E1,
    SecondIntermissionState3_21F5,
    SecondIntermissionState4_220C,
    SecondIntermissionState5_221E,
    SecondIntermissionRefresh2237,
    SecondIntermissionState6_2244,
    SecondIntermissionState7_225D,
    SecondIntermissionState9_226A,
    SecondIntermissionState11_2286,
    SecondIntermissionState13_228D,
    ThirdIntermissionState0_22A7,
    ThirdIntermissionState1_22BE,
    ThirdIntermissionState3_22DD,
    ThirdIntermissionSharedTail22E4,
    ThirdIntermissionState4_22F5,
    ThirdIntermissionState5_22FE
};

struct IntermissionStateCoverageRecord {
    std::size_t id=0; std::string stableId; IntermissionStateLogicFamily family=IntermissionStateLogicFamily::SecondIntermissionState0_21C2; std::uint16_t entryPC=0;
    std::vector<std::uint16_t> sourcePCs; std::size_t units=0; bool directNative=false; bool sourcePresent=false; std::string implementationStatus; std::string evidence;
};
struct IntermissionStateValidationRecord { std::string stableId; std::uint16_t sourcePC=0; bool passed=false; std::string evidenceKind; std::string diagnostic; };
struct IntermissionStateStats {
    std::size_t recoveredLogicUnits=0,baselineDirectNativeLogicUnits=0,additionalDirectNativeLogicUnits=0,directNativeLogicUnits=0,transitionalLogicUnits=0;
    std::size_t baselineCoverageFamilies=0,additionalCoverageFamilies=0,coverageFamilies=0;
    bool noOverlap=false,noGap=false,protectedInlineDataUnowned=false,taskDispatchInlineDataUnowned=false,systemUtilityInlineDataUnowned=false,startupTablesUnowned=false,stateDispatchInlineDataUnowned=false,setupLookupDataUnowned=false,setupAuxDataUnowned=false,scoreDescriptorDataUnowned=false,coordinateGapDataUnowned=false,coordinateDispatchInlineDataUnowned=false;
    bool intermissionSelectTableUnowned=false,firstIntermissionTableUnowned=false,secondIntermissionTableUnowned=false,thirdIntermissionTableUnowned=false,intermissionStateInlineDataUnowned=false,coreOwnershipPreserved=false,schedulerUtilityOwnershipPreserved=false,coverageReady=false;
    std::size_t differentialChecks=0,differentialPassed=0,differentialFailed=0; bool endToEndNative=false;
};
class IntermissionStateNativeLogicCoverage { public:
    static constexpr std::size_t FixedRecoveredLogicUnits=5414;
    static constexpr std::size_t BaselineDirectNativeLogicUnits=3668;
    static constexpr std::size_t AdditionalDirectNativeLogicUnits=113;
    static constexpr std::size_t DirectNativeLogicUnits=3781;
    static constexpr std::size_t TransitionalLogicUnits=1633;
    static constexpr std::size_t BaselineCoverageFamilies=332;
    static constexpr std::size_t AdditionalCoverageFamilies=17;
    static std::string familyText(IntermissionStateLogicFamily family); static const std::vector<IntermissionStateCoverageRecord>& coverageManifest();
    static bool familyForEntry(std::uint16_t pc,IntermissionStateLogicFamily& family); static bool familyForSourcePC(std::uint16_t pc,IntermissionStateLogicFamily& family); static bool isCoveredSourcePC(std::uint16_t pc);
    static void buildCoverageLedger(const std::vector<GeneratedOperation>& operations,std::vector<IntermissionStateCoverageRecord>& ledger,IntermissionStateStats& stats);
    static bool executeNativeFamily(IntermissionStateLogicFamily family,SemanticExecutionState& state,std::size_t& equivalentOperations,std::string& error,GeneratedExecutionBoundary* boundary=nullptr);
    static std::vector<IntermissionStateValidationRecord> runDifferentialValidation(const std::vector<std::uint8_t>& program,const std::vector<GeneratedOperation>& operations,IntermissionStateStats& stats);
};

} // namespace pacripper
