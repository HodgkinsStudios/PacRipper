#pragma once
// PacRipper semantic-oracle analysis complete rooted semantic lift + independent oracle
// Created by Jacob Hodgkins

#include "SemanticLiftEngine.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pacripper {

enum class SemanticOracleExtensionKind {
    None,
    Ldi,
    Ldir,
    Cpir,
    BitIndirectHl
};

struct SemanticOracleLiftedOperation {
    std::size_t id=0;
    std::string stableId;
    std::string blockId;
    std::uint16_t blockStart=0;
    std::uint16_t sourcePC=0;
    std::uint16_t fallthroughPC=0;
    SemanticKind baseKind=SemanticKind::Unsupported;
    SemanticOracleExtensionKind extension=SemanticOracleExtensionKind::None;
    bool supported=false;
    std::vector<std::uint8_t> bytes;
    std::string mnemonic;
    std::string operands;
    std::string rawText;
    std::string note;
};

struct SemanticOracleLiftedBlock {
    std::string stableId;
    std::uint16_t start=0;
    std::uint16_t end=0;
    std::vector<std::size_t> operationIds;
    bool fullySupported=false;
};

struct SemanticOracleOracleRecord {
    std::size_t id=0;
    std::string blockId;
    std::uint16_t blockStart=0;
    std::size_t snapshots=0;
    std::size_t operationsCompared=0;
    bool supported=false;
    bool accepted=false;
    std::uint16_t firstDivergencePC=0xFFFF;
    std::vector<std::uint8_t> firstDivergenceBytes;
    std::string diagnostic;
};

struct SemanticOracleGeneratedSourceRecord {
    std::size_t id=0;
    std::string blockId;
    std::string operationId;
    std::uint16_t blockStart=0;
    std::uint16_t sourcePC=0;
    std::uint16_t fallthroughPC=0;
    std::string semanticKind;
    std::vector<std::uint8_t> bytes;
    std::string generatedFunction;
};

struct SemanticOracleStats {
    std::size_t rootedCodeInstructions=0;
    std::size_t mechanicallyLiftedInstructions=0;
    std::size_t unsupportedInstructionSemantics=0;
    std::size_t liftedBlocks=0;
    std::size_t fullySupportedBlocks=0;
    std::size_t independentlyVerifiedBlocks=0;
    std::size_t independentOracleMismatches=0;
    std::size_t independentOracleSnapshots=0;
    std::size_t independentOracleOperations=0;
    std::size_t generatedBlocks=0;
    std::size_t generatedOperations=0;
    std::size_t generatedSourceMapRecords=0;
    bool generatedCorpusDeterministic=false;
    bool generatedCorpusCompilable=false;
    bool boardBoundaryModelPresent=false;
    bool completeRootedSemanticCoverage=false;
};

struct SemanticOracleBoardState {
    std::array<std::uint8_t,0x4000> rom{};
    std::array<std::uint8_t,0x0400> videoRam{};
    std::array<std::uint8_t,0x0400> colorRam{};
    std::array<std::uint8_t,0x0400> workRam{};
    std::array<std::uint8_t,0x0010> spriteRam{};
    std::array<std::uint8_t,0x0010> spriteCoords{};
    std::array<std::uint8_t,0x0020> soundRegisters{};
    std::array<std::uint8_t,8> outputLatch{};
    std::array<std::uint8_t,4> inputPorts{{0xFF,0xFF,0xFF,0xFF}};
    bool irqEnable=false;
    bool soundEnable=false;
    bool flipScreen=false;
    std::uint8_t vectorLatch=0;
    std::uint64_t watchdogWrites=0;
    std::uint64_t coinCounterPulses=0;
};

class SemanticOraclePacmanBoard {
public:
    static std::uint8_t readMemory(const SemanticOracleBoardState& state,std::uint16_t address);
    static void writeMemory(SemanticOracleBoardState& state,std::uint16_t address,std::uint8_t value);
    static std::uint8_t readPort(const SemanticOracleBoardState& state,std::uint16_t port);
    static void writePort(SemanticOracleBoardState& state,std::uint16_t port,std::uint8_t value);
    static std::uint8_t interruptAcknowledge(const SemanticOracleBoardState& state);
};

class SemanticOracleEngine {
public:
    static std::string extensionKindText(SemanticOracleExtensionKind kind);
    static std::string semanticKindText(const SemanticOracleLiftedOperation& operation);

    static void liftFromSemanticLift(const std::vector<SemanticLiftedOperation>& semanticLiftOperations,
                               const std::vector<SemanticLiftedBlock>& semanticLiftBlocks,
                               std::vector<SemanticOracleLiftedOperation>& operations,
                               std::vector<SemanticOracleLiftedBlock>& blocks,
                               SemanticOracleStats& stats);

    static bool executeLifted(const SemanticOracleLiftedOperation& operation,
                              SemanticExecutionState& state,
                              std::string& error);

    static std::vector<SemanticOracleOracleRecord> verifyWithIndependentOracle(
        const std::vector<std::uint8_t>& program,
        const std::vector<SemanticOracleLiftedOperation>& operations,
        const std::vector<SemanticOracleLiftedBlock>& blocks,
        SemanticOracleStats& stats,
        unsigned snapshotsPerBlock=3);

    static std::vector<SemanticOracleGeneratedSourceRecord> buildGeneratedSourceMap(
        const std::vector<SemanticOracleLiftedOperation>& operations);

    static bool emitGeneratedCorpus(const std::string& directory,
                                    const std::vector<SemanticOracleLiftedOperation>& operations,
                                    const std::vector<SemanticOracleLiftedBlock>& blocks,
                                    std::vector<SemanticOracleGeneratedSourceRecord>& sourceMap,
                                    std::string& error);
};

} // namespace pacripper
