#pragma once
// PacRipper semantic-lift engine recompilable semantic-lift foundation
// Created by Jacob Hodgkins

#include "../analysis/Analyzer.h"
#include "RomClosure.h"
#include "ResidualExtentAnalysis.h"
#include "Im2VectorAnalysis.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace pacripper {

constexpr std::uint8_t SemanticFlagS  = 0x80;
constexpr std::uint8_t SemanticFlagZ  = 0x40;
constexpr std::uint8_t SemanticFlagY  = 0x20;
constexpr std::uint8_t SemanticFlagH  = 0x10;
constexpr std::uint8_t SemanticFlagX  = 0x08;
constexpr std::uint8_t SemanticFlagPV = 0x04;
constexpr std::uint8_t SemanticFlagN  = 0x02;
constexpr std::uint8_t SemanticFlagC  = 0x01;

enum class SemanticKind {
    Nop,
    Load8,
    Load16,
    Increment8,
    Decrement8,
    Increment16,
    Decrement16,
    Add8,
    AddCarry8,
    Subtract8,
    SubtractCarry8,
    Add16,
    SubtractCarry16,
    And8,
    Xor8,
    Or8,
    Compare8,
    RotateAccumulator,
    RotateShift,
    BitTest,
    BitSet,
    BitReset,
    DecimalAdjust,
    ComplementAccumulator,
    SetCarry,
    ComplementCarry,
    Jump,
    RelativeJump,
    Djnz,
    Call,
    Return,
    Restart,
    Push,
    Pop,
    Exchange,
    ExchangeAlternate,
    Halt,
    InterruptDisable,
    InterruptEnable,
    InterruptMode,
    IoRead,
    IoWrite,
    Unsupported
};

enum class SemanticEffectKind {
    MemoryRead,
    MemoryWrite,
    PortRead,
    PortWrite,
    InterruptControl
};

struct SemanticMachineState {
    std::uint8_t a=0,f=0,b=0,c=0,d=0,e=0,h=0,l=0;
    std::uint8_t aAlt=0,fAlt=0,bAlt=0,cAlt=0,dAlt=0,eAlt=0,hAlt=0,lAlt=0;
    std::uint16_t ix=0,iy=0,sp=0,pc=0;
    std::uint8_t i=0,r=0;
    std::uint8_t interruptMode=0;
    bool iff1=false;
    bool iff2=false;
    bool halted=false;
    bool eiDelay=false;
    std::array<std::uint8_t,65536> memory{};
};

struct SemanticEffect {
    std::size_t sequence=0;
    SemanticEffectKind kind=SemanticEffectKind::MemoryRead;
    std::uint16_t address=0;
    std::uint8_t value=0;
    std::uint16_t sourcePC=0;
};

struct SemanticExecutionState {
    SemanticMachineState cpu;
    std::array<std::uint8_t,256> portInputs{};
    std::vector<SemanticEffect> effects;
};

struct SemanticBlockInput {
    std::uint16_t start=0;
    std::uint16_t end=0;
    std::vector<std::uint16_t> instructionPCs;
};

struct SemanticRomProvenanceRecord {
    std::uint16_t address=0;
    RomClosurePrimary primary=RomClosurePrimary::Unresolved;
    bool resolved=false;
    bool code=false;
    bool hardData=false;
    bool staticExactDataUse=false;
    bool dynamicDataUse=false;
    bool boundedConsumer=false;
    bool pointerTarget=false;
    bool provenUnused=false;
    bool overlappingEvidence=false;
    bool provenanceComplete=false;
    std::set<std::uint16_t> instructionPCs;
    std::set<std::uint16_t> consumerPCs;
    std::set<std::size_t> residualExtentNegativeProofIds;
    std::set<std::size_t> im2VectorSystemNegativeProofIds;
    std::set<std::size_t> im2VectorVectorDomainProofIds;
    std::set<std::string> sourceTags;
    std::string note;
};

struct SemanticLiftedOperation {
    std::size_t id=0;
    std::string stableId;
    std::string blockId;
    std::uint16_t blockStart=0;
    std::uint16_t sourcePC=0;
    std::uint16_t fallthroughPC=0;
    SemanticKind kind=SemanticKind::Unsupported;
    bool supported=false;
    std::vector<std::uint8_t> bytes;
    std::string mnemonic;
    std::string operands;
    std::string rawText;
    std::string note;
};

struct SemanticLiftedBlock {
    std::string stableId;
    std::uint16_t start=0;
    std::uint16_t end=0;
    std::vector<std::size_t> operationIds;
    bool fullySupported=false;
};

struct SemanticDifferentialRecord {
    std::size_t id=0;
    std::string blockId;
    std::uint16_t blockStart=0;
    std::size_t snapshots=0;
    std::size_t operationsCompared=0;
    bool supported=false;
    bool accepted=false;
    std::uint16_t firstDivergencePC=0xFFFF;
    std::string diagnostic;
};

struct SemanticLiftStats {
    std::size_t provenanceRecords=0;
    std::size_t resolvedRomBytes=0;
    std::size_t unresolvedRomBytes=0;
    std::size_t codeBytes=0;
    std::size_t codeBytesWithRootedInstructionProvenance=0;
    std::size_t positiveDataBytes=0;
    std::size_t positiveDataBytesWithProvenance=0;
    std::size_t provenUnusedBytes=0;
    std::size_t provenUnusedBytesWithNegativeProvenance=0;
    std::size_t overlappingEvidenceBytes=0;
    std::size_t incompleteProvenanceBytes=0;
    std::size_t rootedCodeInstructions=0;
    std::size_t mechanicallyLiftedInstructions=0;
    std::size_t unsupportedInstructionSemantics=0;
    std::size_t liftedBlocks=0;
    std::size_t fullySupportedBlocks=0;
    std::size_t differentiallyVerifiedBlocks=0;
    std::size_t differentialMismatches=0;
    std::size_t differentialSnapshots=0;
    std::size_t differentialOperations=0;
    bool romByteAccountingFrozen=false;
    bool wholeRomProvenanceComplete=false;
    bool deterministicSourceMap=true;
};

class SemanticLiftEngine {
public:
    static std::uint8_t wrap8(unsigned value) { return static_cast<std::uint8_t>(value&0xFFu); }
    static std::uint16_t wrap16(unsigned value) { return static_cast<std::uint16_t>(value&0xFFFFu); }
    static bool evenParity(std::uint8_t value);

    static std::uint8_t add8Flags(std::uint8_t lhs,std::uint8_t rhs,std::uint8_t carry,std::uint8_t result);
    static std::uint8_t sub8Flags(std::uint8_t lhs,std::uint8_t rhs,std::uint8_t carry,std::uint8_t result,bool compare=false);
    static std::uint8_t inc8Flags(std::uint8_t oldValue,std::uint8_t result,std::uint8_t oldFlags);
    static std::uint8_t dec8Flags(std::uint8_t oldValue,std::uint8_t result,std::uint8_t oldFlags);
    static std::uint8_t logicFlags(std::uint8_t result,bool halfCarry);

    static std::string semanticKindText(SemanticKind kind);
    static std::string effectKindText(SemanticEffectKind kind);
    static std::string stableBlockId(std::uint16_t start);
    static std::string stableOperationId(std::uint16_t blockStart,std::uint16_t sourcePC);

    static SemanticLiftedOperation lowerInstruction(const Instruction& instruction,
                                                  std::uint16_t blockStart,
                                                  std::uint16_t fallthroughPC,
                                                  std::size_t id);

    static std::vector<SemanticRomProvenanceRecord> buildProvenanceLedger(
        const Analyzer& analyzer,
        const std::vector<RomByteClosureRecord>& closure,
        const std::vector<ResidualExtentClosureProvenanceRecord>& residualExtentProvenance,
        const std::vector<Im2VectorClosureProvenanceRecord>& im2VectorProvenance,
        const std::vector<Im2VectorVectorDomainProofRecord>& im2VectorVectorDomains,
        const std::set<std::uint16_t>& rootedInstructionPCs,
        SemanticLiftStats& stats);

    static void lowerBlocks(const Analyzer& analyzer,
                            const std::vector<SemanticBlockInput>& blocks,
                            const std::vector<std::uint16_t>& fallthroughByPC,
                            std::vector<SemanticLiftedOperation>& operations,
                            std::vector<SemanticLiftedBlock>& liftedBlocks,
                            SemanticLiftStats& stats);

    static SemanticExecutionState deterministicSnapshot(const std::vector<std::uint8_t>& program,
                                                      std::uint16_t pc,
                                                      unsigned seed);
    static bool executeReference(const Instruction& instruction,std::uint16_t fallthroughPC,
                                 SemanticExecutionState& state,std::string& error);
    static bool executeLifted(const SemanticLiftedOperation& operation,
                              SemanticExecutionState& state,std::string& error);
    static bool compareExecutionStates(const SemanticExecutionState& reference,
                                       const SemanticExecutionState& lifted,
                                       std::string& diagnostic);

    static std::vector<SemanticDifferentialRecord> verifyBlocks(
        const Analyzer& analyzer,
        const std::vector<SemanticBlockInput>& blocks,
        const std::vector<SemanticLiftedOperation>& operations,
        const std::vector<SemanticLiftedBlock>& liftedBlocks,
        SemanticLiftStats& stats,
        unsigned snapshotsPerBlock=3);
};

} // namespace pacripper
