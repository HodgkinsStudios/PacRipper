#pragma once
// PacRipper board-record interpreter board/record interpreter native coverage
// Created by Jacob Hodgkins

#include "HudBoardNativeLogic.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pacripper {

enum class BoardInterpreterLogicFamily {
    BoardInterpreterEntry,
    BoardInactiveReset,
    BoardRecordActivate,
    BoardCountdownMotion,
    BoardPositionAccumulate,
    BoardScaleShift,
    BoardOutputPack,
    BoardHandlerValueRead,
    BoardHandlerCountdownDirect,
    BoardHandlerCountdownEvery2,
    BoardHandlerCountdownGate,
    BoardHandlerCountdownCore,
    BoardHandlerCountdownEvery4,
    BoardHandlerCountdownEvery8,
    BoardHandlerNoop0,
    BoardHandlerNoop1,
    BoardHandlerNoop2,
    BoardHandlerNoop3,
    BoardHandlerNoop4,
    BoardHandlerNoop5,
    BoardHandlerNoop6,
    BoardHandlerNoop7,
    BoardHandlerNoop8,
    BoardHandlerNoop9,
    BoardHandlerNoop10
};

struct BoardInterpreterCoverageRecord {
    std::size_t id=0;
    std::string stableId;
    BoardInterpreterLogicFamily family=BoardInterpreterLogicFamily::BoardInterpreterEntry;
    std::uint16_t entryPC=0;
    std::vector<std::uint16_t> sourcePCs;
    std::size_t units=0;
    bool directNative=false;
    bool sourcePresent=false;
    std::string evidence;
};

struct BoardInterpreterValidationRecord {
    std::string stableId;
    bool passed=false;
    std::string evidenceKind;
    std::string diagnostic;
};

struct BoardInterpreterStats {
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

class BoardInterpreterNativeLogicCoverage {
public:
    static constexpr std::size_t FixedRecoveredLogicUnits=5414;
    static constexpr std::size_t BaselineDirectNativeLogicUnits=587;
    static constexpr std::size_t AdditionalDirectNativeLogicUnits=160;
    static constexpr std::size_t DirectNativeLogicUnits=747;
    static constexpr std::size_t TransitionalLogicUnits=4667;
    static constexpr std::size_t AdditionalCoverageFamilies=25;

    static std::string familyText(BoardInterpreterLogicFamily family);
    static const std::vector<BoardInterpreterCoverageRecord>& coverageManifest();
    static bool familyForEntry(std::uint16_t pc,BoardInterpreterLogicFamily& family);
    static bool isCoveredSourcePC(std::uint16_t pc);

    static void buildCoverageLedger(const std::vector<GeneratedOperation>& operations,
                                     std::vector<BoardInterpreterCoverageRecord>& ledger,
                                     BoardInterpreterStats& stats);

    static bool executeNativeFamily(BoardInterpreterLogicFamily family,SemanticExecutionState& state,
                                    std::size_t& equivalentOperations,std::string& error,
                                    GeneratedExecutionBoundary* boundary=nullptr);

    static std::vector<BoardInterpreterValidationRecord> runDifferentialValidation(
        const std::vector<std::uint8_t>& program,
        const std::vector<GeneratedOperation>& operations,
        BoardInterpreterStats& stats);
};

} // namespace pacripper
