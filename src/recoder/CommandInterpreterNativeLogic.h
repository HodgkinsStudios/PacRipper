#pragma once
// PacRipper command-stream interpreter command-stream interpreter native coverage
// Created by Jacob Hodgkins

#include "BoardInterpreterNativeLogic.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pacripper {

enum class CommandInterpreterLogicFamily {
    CommandEntryBitScan,
    CommandLookupReturn,
    CommandPointerReload,
    CommandFetchDispatch,
    CommandTokenSetup,
    CommandPostSpeedLookup,
    CommandPostDurationLookup,
    CommandOutputPack,
    CommandHandlerPointerReplace,
    CommandHandlerField3,
    CommandHandlerField4,
    CommandHandlerField9,
    CommandHandlerField11,
    CommandHandlerReset
};

struct CommandInterpreterCoverageRecord {
    std::size_t id=0;
    std::string stableId;
    CommandInterpreterLogicFamily family=CommandInterpreterLogicFamily::CommandEntryBitScan;
    std::uint16_t entryPC=0;
    std::vector<std::uint16_t> sourcePCs;
    std::size_t units=0;
    bool directNative=false;
    bool sourcePresent=false;
    std::string evidence;
};

struct CommandInterpreterValidationRecord {
    std::string stableId;
    bool passed=false;
    std::string evidenceKind;
    std::string diagnostic;
};

struct CommandInterpreterStats {
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

class CommandInterpreterNativeLogicCoverage {
public:
    static constexpr std::size_t FixedRecoveredLogicUnits=5414;
    static constexpr std::size_t BaselineDirectNativeLogicUnits=747;
    static constexpr std::size_t AdditionalDirectNativeLogicUnits=112;
    static constexpr std::size_t DirectNativeLogicUnits=859;
    static constexpr std::size_t TransitionalLogicUnits=4555;
    static constexpr std::size_t AdditionalCoverageFamilies=14;

    static std::string familyText(CommandInterpreterLogicFamily family);
    static const std::vector<CommandInterpreterCoverageRecord>& coverageManifest();
    static bool familyForEntry(std::uint16_t pc,CommandInterpreterLogicFamily& family);
    static bool isCoveredSourcePC(std::uint16_t pc);

    static void buildCoverageLedger(const std::vector<GeneratedOperation>& operations,
                                     std::vector<CommandInterpreterCoverageRecord>& ledger,
                                     CommandInterpreterStats& stats);

    static bool executeNativeFamily(CommandInterpreterLogicFamily family,SemanticExecutionState& state,
                                    std::size_t& equivalentOperations,std::string& error,
                                    GeneratedExecutionBoundary* boundary=nullptr);

    static std::vector<CommandInterpreterValidationRecord> runDifferentialValidation(
        const std::vector<std::uint8_t>& program,
        const std::vector<GeneratedOperation>& operations,
        CommandInterpreterStats& stats);
};

} // namespace pacripper
