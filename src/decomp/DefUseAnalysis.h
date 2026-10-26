#pragma once
// PacRipper def-use analysis def-use / expression reconstruction
// Created by Jacob Hodgkins

#include "../disasm/Z80Disassembler.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace pacripper {

enum class DefExpressionKind {
    EntryValue,
    Constant,
    Copy,
    Add,
    Subtract,
    BitAnd,
    BitOr,
    BitXor,
    Increment,
    Decrement,
    Add16,
    DirectMemoryRead,
    IndirectMemoryRead,
    HighByte,
    LowByte,
    Unknown
};

struct ReachingDefinitionFact {
    std::set<std::size_t> definitionIds;
    bool includesEntryValue = false;
    bool includesClobberedUnknown = false;
    std::set<std::uint16_t> unknownSourceAddresses;

    bool exactDefinition() const {
        return definitionIds.size()==1 && !includesEntryValue && !includesClobberedUnknown;
    }
    bool exactEntryValue() const {
        return definitionIds.empty() && includesEntryValue && !includesClobberedUnknown;
    }
    bool ambiguous() const {
        const std::size_t alternatives=definitionIds.size()+(includesEntryValue?1u:0u)+(includesClobberedUnknown?1u:0u);
        return alternatives>1;
    }
    bool operator==(const ReachingDefinitionFact& other) const {
        return definitionIds==other.definitionIds && includesEntryValue==other.includesEntryValue &&
               includesClobberedUnknown==other.includesClobberedUnknown && unknownSourceAddresses==other.unknownSourceAddresses;
    }
    bool operator!=(const ReachingDefinitionFact& other) const { return !(*this==other); }
};

struct DefOperandSpec {
    bool constant = false;
    std::uint16_t constantValue = 0;
    unsigned bits = 0;
    std::string entity;
};

struct DefinitionRecord {
    std::size_t id = 0;
    std::uint16_t instructionAddress = 0;
    std::string entity;
    unsigned bits = 0;
    std::string sourceInstruction;
    DefExpressionKind operation = DefExpressionKind::Unknown;
    std::vector<DefOperandSpec> operands;
    std::map<std::string,ReachingDefinitionFact> reachingOperands;
    std::set<std::size_t> sourceDefinitionIds;
    bool semanticExact = false;
    bool callBoundaryClobber = false;
    bool aliasInvalidation = false;
    std::string note;
};

struct UseRecord {
    std::uint16_t instructionAddress = 0;
    std::string entity;
    ReachingDefinitionFact reaching;
    bool staticProof = true;
};

struct ExpressionRecord {
    std::size_t definitionId = 0;
    std::uint16_t instructionAddress = 0;
    std::string entity;
    unsigned bits = 0;
    DefExpressionKind operation = DefExpressionKind::Unknown;
    bool exact = false;
    bool ambiguous = false;
    bool constantKnown = false;
    std::uint16_t constantValue = 0;
    bool objectAware = false;
    bool memoryAddressKnown = false;
    std::uint16_t memoryAddress = 0;
    std::set<std::size_t> romObjectIds;
    std::set<std::uint16_t> provenance;
    std::set<std::string> referencedEntities;
    std::string text;
    std::string note;
};

struct LivenessRecord {
    std::uint16_t instructionAddress = 0;
    std::set<std::string> liveBefore;
    std::set<std::string> liveAfter;
};

struct DefUseBlockInput {
    std::uint16_t start = 0;
    std::uint16_t functionEntry = 0;
    std::vector<std::uint16_t> instructions;
    std::set<std::uint16_t> successors;
    bool staticProof = true;
};

struct FunctionEffectInput {
    std::uint16_t functionEntry = 0;
    std::set<std::string> preservedRegisters;
    std::set<std::uint16_t> ramMayWrite;
    bool unknownMemoryWrite = false;
};

struct RomObjectView {
    std::size_t id = 0;
    std::uint16_t start = 0;
    std::uint16_t end = 0;
    std::size_t entrySize = 0;
    bool dynamicOnly = false;
};

struct DefUseStats {
    std::size_t analyzedFunctions = 0;
    std::size_t analyzedBlocks = 0;
    std::size_t analyzedInstructions = 0;
    std::size_t definitions = 0;
    std::size_t uses = 0;
    std::size_t exactUses = 0;
    std::size_t ambiguousUses = 0;
    std::size_t exactExpressions = 0;
    std::size_t ambiguousExpressions = 0;
    std::size_t callPreservedFacts = 0;
    std::size_t callClobberedFacts = 0;
    std::size_t objectAwareExpressions = 0;
    std::size_t exactRomReads = 0;
};

struct DefUseResult {
    std::vector<DefinitionRecord> definitions;
    std::vector<UseRecord> uses;
    std::vector<ExpressionRecord> expressions;
    std::map<std::uint16_t,LivenessRecord> liveness;
    std::map<std::uint16_t,std::map<std::string,ReachingDefinitionFact>> stateBeforeInstruction;
    std::map<std::uint16_t,std::map<std::string,ReachingDefinitionFact>> stateAfterInstruction;
    DefUseStats stats;
};

class DefUseAnalysis {
public:
    static const std::set<std::string>& trackedRegisters();
    static bool isTrackedRegister(const std::string& entity);
    static bool isPhysicalRam(std::uint16_t address);
    static std::string ram8Entity(std::uint16_t address);
    static std::string ram16Entity(std::uint16_t address);
    static std::string expressionKindText(DefExpressionKind kind);

    static DefUseResult analyze(const std::map<std::uint16_t,Instruction>& instructions,
                                const std::vector<DefUseBlockInput>& blocks,
                                const std::map<std::uint16_t,FunctionEffectInput>& functionEffects,
                                const std::vector<RomObjectView>& romObjects,
                                std::size_t romSize);
};

} // namespace pacripper
