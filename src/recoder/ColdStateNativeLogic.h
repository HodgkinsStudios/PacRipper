#pragma once
// PacRipper cold-state logic static/cold frontier native coverage
// Created by Jacob Hodgkins

#include "StartupSelfTestNativeLogic.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pacripper {

enum class ColdStateLogicFamily {
    ColdFill3AF4,
    ColdStateGate08DE,
    ColdStageUpdate1017,
    ColdTimer13DD,
    ColdFlag0C42,
    ColdCounter0E23,
    ColdFlag0E36,
    ColdFlag0AC3,
    ColdActorInit0BD6,
    ColdCounter0C0D,
    ColdProgressFlags0E6C,
    ColdFlag0EAD,
    ColdStateDispatch1291,
    ColdStateTimer12B7,
    ColdStateHandlerBank12CB,
    ColdFlag268B,
    ColdClear26A2,
    ColdScan2A35,
    ColdTileTransform2448
};

struct ColdStateCoverageRecord {
    std::size_t id=0; std::string stableId; ColdStateLogicFamily family=ColdStateLogicFamily::ColdFill3AF4; std::uint16_t entryPC=0;
    std::vector<std::uint16_t> sourcePCs; std::size_t units=0; bool directNative=false; bool sourcePresent=false; std::string implementationStatus; std::string evidence;
};
struct ColdStateValidationRecord { std::string stableId; std::uint16_t sourcePC=0; bool passed=false; std::string evidenceKind; std::string diagnostic; };
struct ColdStateStats {
    std::size_t recoveredLogicUnits=0,baselineDirectNativeLogicUnits=0,additionalDirectNativeLogicUnits=0,directNativeLogicUnits=0,transitionalLogicUnits=0;
    std::size_t baselineCoverageFamilies=0,additionalCoverageFamilies=0,coverageFamilies=0;
    bool noOverlap=false,noGap=false,protectedInlineDataUnowned=false,taskDispatchInlineDataUnowned=false,systemUtilityInlineDataUnowned=false,startupTablesUnowned=false,stateDispatchInlineDataUnowned=false,schedulerUtilityOwnershipPreserved=false,coverageReady=false;
    std::size_t differentialChecks=0,differentialPassed=0,differentialFailed=0; bool endToEndNative=false;
};
class ColdStateNativeLogicCoverage { public:
    static constexpr std::size_t FixedRecoveredLogicUnits=5414;
    static constexpr std::size_t BaselineDirectNativeLogicUnits=2519;
    static constexpr std::size_t AdditionalDirectNativeLogicUnits=282;
    static constexpr std::size_t DirectNativeLogicUnits=2801;
    static constexpr std::size_t TransitionalLogicUnits=2613;
    static constexpr std::size_t BaselineCoverageFamilies=259;
    static constexpr std::size_t AdditionalCoverageFamilies=19;
    static std::string familyText(ColdStateLogicFamily family); static const std::vector<ColdStateCoverageRecord>& coverageManifest();
    static bool familyForEntry(std::uint16_t pc,ColdStateLogicFamily& family); static bool familyForSourcePC(std::uint16_t pc,ColdStateLogicFamily& family); static bool isCoveredSourcePC(std::uint16_t pc);
    static void buildCoverageLedger(const std::vector<GeneratedOperation>& operations,std::vector<ColdStateCoverageRecord>& ledger,ColdStateStats& stats);
    static bool executeNativeFamily(ColdStateLogicFamily family,SemanticExecutionState& state,std::size_t& equivalentOperations,std::string& error,GeneratedExecutionBoundary* boundary=nullptr);
    static std::vector<ColdStateValidationRecord> runDifferentialValidation(const std::vector<std::uint8_t>& program,const std::vector<GeneratedOperation>& operations,ColdStateStats& stats);
};
} // namespace pacripper
