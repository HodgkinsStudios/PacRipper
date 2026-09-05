#pragma once
// PacRipper frame-update logic main-frame/update epilogue native coverage
// Created by Jacob Hodgkins

#include "GraphicCreditNativeLogic.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pacripper {

enum class FrameUpdateLogicFamily {
    MainFrameUpdateGate,
    Call039D,
    Call1490,
    Call141F,
    Call0267,
    Call02AD,
    Call02FD,
    PostUpdateBoardCall
};

struct FrameUpdateCoverageRecord {
    std::size_t id=0;
    std::string stableId;
    FrameUpdateLogicFamily family=FrameUpdateLogicFamily::MainFrameUpdateGate;
    std::uint16_t entryPC=0;
    std::vector<std::uint16_t> sourcePCs;
    std::size_t units=0;
    bool directNative=false;
    bool sourcePresent=false;
    std::string evidence;
};

struct FrameUpdateValidationRecord {
    std::string stableId;
    bool passed=false;
    std::string evidenceKind;
    std::string diagnostic;
};

struct FrameUpdateStats {
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

class FrameUpdateNativeLogicCoverage {
public:
    static constexpr std::size_t FixedRecoveredLogicUnits=5414;
    static constexpr std::size_t BaselineDirectNativeLogicUnits=987;
    static constexpr std::size_t AdditionalDirectNativeLogicUnits=15;
    static constexpr std::size_t DirectNativeLogicUnits=1002;
    static constexpr std::size_t TransitionalLogicUnits=4412;
    static constexpr std::size_t AdditionalCoverageFamilies=8;

    static std::string familyText(FrameUpdateLogicFamily family);
    static const std::vector<FrameUpdateCoverageRecord>& coverageManifest();
    static bool familyForEntry(std::uint16_t pc,FrameUpdateLogicFamily& family);
    static bool isCoveredSourcePC(std::uint16_t pc);

    static void buildCoverageLedger(const std::vector<GeneratedOperation>& operations,
                                     std::vector<FrameUpdateCoverageRecord>& ledger,
                                     FrameUpdateStats& stats);

    static bool executeNativeFamily(FrameUpdateLogicFamily family,SemanticExecutionState& state,
                                    std::size_t& equivalentOperations,std::string& error,
                                    GeneratedExecutionBoundary* boundary=nullptr);

    static std::vector<FrameUpdateValidationRecord> runDifferentialValidation(
        const std::vector<std::uint8_t>& program,
        const std::vector<GeneratedOperation>& operations,
        FrameUpdateStats& stats);
};

} // namespace pacripper
