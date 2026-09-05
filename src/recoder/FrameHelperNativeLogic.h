#pragma once
// PacRipper frame-helper logic main-frame helper/output cluster native coverage
// Created by Jacob Hodgkins

#include "ObjectInputNativeLogic.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pacripper {

enum class FrameHelperLogicFamily {
    MainHelperFront02FD,
    CallContinuation0340,
    Return0343,
    OutputBranch0344,
    CallContinuation0353,
    JumpContinuation0356,
    AlternateBranch0359,
    CallContinuation035E,
    OutputGate0361,
    Return0368,
    IxLabelHelper0369,
    IyLabelHelper0376,
    IxBlankHelper0383,
    IyBlankHelper0390
};

struct FrameHelperCoverageRecord {
    std::size_t id=0;
    std::string stableId;
    FrameHelperLogicFamily family=FrameHelperLogicFamily::MainHelperFront02FD;
    std::uint16_t entryPC=0;
    std::vector<std::uint16_t> sourcePCs;
    std::size_t units=0;
    bool directNative=false;
    bool sourcePresent=false;
    std::string evidence;
};

struct FrameHelperValidationRecord {
    std::string stableId;
    bool passed=false;
    std::string evidenceKind;
    std::string diagnostic;
};

struct FrameHelperStats {
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

class FrameHelperNativeLogicCoverage {
public:
    static constexpr std::size_t FixedRecoveredLogicUnits=5414;
    static constexpr std::size_t BaselineDirectNativeLogicUnits=1082;
    static constexpr std::size_t AdditionalDirectNativeLogicUnits=67;
    static constexpr std::size_t DirectNativeLogicUnits=1149;
    static constexpr std::size_t TransitionalLogicUnits=4265;
    static constexpr std::size_t AdditionalCoverageFamilies=14;

    static std::string familyText(FrameHelperLogicFamily family);
    static const std::vector<FrameHelperCoverageRecord>& coverageManifest();
    static bool familyForEntry(std::uint16_t pc,FrameHelperLogicFamily& family);
    static bool isCoveredSourcePC(std::uint16_t pc);

    static void buildCoverageLedger(const std::vector<GeneratedOperation>& operations,
                                     std::vector<FrameHelperCoverageRecord>& ledger,
                                     FrameHelperStats& stats);

    static bool executeNativeFamily(FrameHelperLogicFamily family,SemanticExecutionState& state,
                                    std::size_t& equivalentOperations,std::string& error,
                                    GeneratedExecutionBoundary* boundary=nullptr);

    static std::vector<FrameHelperValidationRecord> runDifferentialValidation(
        const std::vector<std::uint8_t>& program,
        const std::vector<GeneratedOperation>& operations,
        FrameHelperStats& stats);
};

} // namespace pacripper
