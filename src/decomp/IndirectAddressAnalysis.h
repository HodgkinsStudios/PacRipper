#pragma once
// PacRipper indirect-address analysis bounded indirect-memory address proof
// Created by Jacob Hodgkins

#include "DefUseAnalysis.h"
#include "RomClosure.h"
#include "RomObjects.h"
#include "ValueFlow.h"
#include "../disasm/Z80Disassembler.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace pacripper {

enum class AddressValueKind {
    Unknown,
    Exact,
    FiniteSet,
    ContiguousRange,
    StridedRange,
    AmbiguousAlternatives
};

enum class IndirectMemoryDirection { Read, Write, ReadWrite };

enum class AddressFlowEdgeKind {
    Structural,
    BranchTaken,
    BranchNotTaken,
    Call,
    Restart,
    Dispatch,
    Return,
    Indirect
};

struct AddressLatticeValue {
    AddressValueKind kind=AddressValueKind::Unknown;
    std::set<std::uint16_t> values;
    std::uint16_t rangeStart=0;
    std::uint16_t rangeEnd=0; // inclusive when kind is a range
    std::uint16_t stride=0;
    bool hasUnknownAlternative=false;
    bool wraparound=false;
    bool staticProof=true;
    bool dynamicOnly=false;
    bool compressedRange=false; // rangeStart/rangeEnd are the complete proven set without enumerating every member
    std::set<std::size_t> originDefinitionIds;
    std::set<std::uint16_t> provenancePCs;
    std::set<std::uint16_t> ramOriginAddresses;
    std::set<std::uint16_t> callEvidencePCs;
    std::string note;
};

struct AddressFlowEdgeInput {
    int to=-1;
    AddressFlowEdgeKind kind=AddressFlowEdgeKind::Structural;
};

struct AddressBlockInput {
    std::uint16_t start=0;
    std::vector<std::uint16_t> instructions;
    std::vector<AddressFlowEdgeInput> outgoing;
};

struct IndirectMemoryAccessRecord {
    std::size_t id=0;
    std::uint16_t pc=0;
    std::string operand;
    std::string addressRegister;
    int displacement=0;
    IndirectMemoryDirection direction=IndirectMemoryDirection::Read;
    AddressLatticeValue address;
    std::set<std::uint16_t> functionOwners;
    bool pathBounded=false;
    bool throughRamPointer=false;
    bool throughStackRestore=false;
    bool acrossPreservedCall=false;
    bool fromDefiniteCallOutput=false;
    std::string arithmeticChain;
    std::string note;
};

struct IndirectRomConsumerProofRecord {
    std::size_t id=0;
    std::size_t accessId=0;
    std::uint16_t pc=0;
    std::uint16_t start=0;
    std::uint16_t end=0; // exclusive
    bool exact=false;
    bool bounded=false;
    bool accepted=false;
    bool mixedNonRomAlternatives=false;
    bool rangeBased=false;
    std::uint16_t stride=0;
    std::set<std::uint16_t> exactAddressSet;
    std::set<std::size_t> originDefinitionIds;
    std::set<std::uint16_t> provenancePCs;
    std::set<std::uint16_t> ramOriginAddresses;
    std::set<std::uint16_t> callEvidencePCs;
    std::string note;
};

struct IndirectAddressClosureProvenanceRecord {
    std::uint16_t address=0;
    bool exact=false;
    bool bounded=false;
    std::set<std::size_t> consumerProofIds;
    std::set<std::size_t> accessIds;
    std::set<std::uint16_t> accessPCs;
    std::set<std::size_t> originDefinitionIds;
    std::set<std::uint16_t> provenancePCs;
    std::string note;
};

struct IndirectAddressStats {
    std::size_t indirectAccesses=0;
    std::size_t exactAddresses=0;
    std::size_t finiteSetAddresses=0;
    std::size_t rangeAddresses=0;
    std::size_t ambiguousAddresses=0;
    std::size_t unknownAddresses=0;
    std::size_t ramReloadAddresses=0;
    std::size_t stackRestoreAddresses=0;
    std::size_t preservedCallAddresses=0;
    std::size_t returnedOutputAddresses=0;
    std::size_t acceptedRomConsumers=0;
    std::size_t exactRomConsumers=0;
    std::size_t boundedRomConsumers=0;
    std::size_t rejectedMixedAddressConsumers=0;
};

class IndirectAddressAnalysis {
public:
    static AddressLatticeValue exact(std::uint16_t value,std::uint16_t provenancePC=0);
    static AddressLatticeValue finiteSet(const std::set<std::uint16_t>& values,bool unknownAlternative=false);
    static AddressLatticeValue merge(const AddressLatticeValue& a,const AddressLatticeValue& b,std::size_t maxValues=512);
    static AddressLatticeValue shifted(const AddressLatticeValue& value,int delta,unsigned bits=16);
    static AddressLatticeValue added(const AddressLatticeValue& a,const AddressLatticeValue& b,unsigned bits=16,std::size_t maxValues=512);
    static AddressLatticeValue combineBytes(const AddressLatticeValue& high,const AddressLatticeValue& low,std::size_t maxValues=512);
    static AddressLatticeValue classifyKnownValues(AddressLatticeValue value);

    static bool parseIndirectOperand(const std::string& operand,std::string& reg,int& displacement);
    static std::vector<IndirectMemoryAccessRecord> analyze(
        const std::map<std::uint16_t,Instruction>& instructions,
        const std::vector<AddressBlockInput>& blocks,
        const std::set<std::uint16_t>& rootBlocks,
        const std::map<std::uint16_t,std::set<std::uint16_t>>& blockOwners,
        const std::map<std::uint16_t,FunctionRegisterSummary>& functionSummaries,
        const DefUseResult& defUse,
        const std::vector<CallBindingRecord>& callBindings,
        const std::vector<std::uint8_t>& program);

    static std::vector<IndirectRomConsumerProofRecord> synthesizeRomConsumers(
        const std::vector<IndirectMemoryAccessRecord>& accesses,
        std::size_t romSize,
        std::vector<RomConsumerRecord>& consumers);

    static std::vector<IndirectAddressClosureProvenanceRecord> applyClosureOverlay(
        const std::vector<RomByteClosureRecord>& baseline,
        const std::vector<IndirectRomConsumerProofRecord>& proofs,
        std::vector<RomByteClosureRecord>& overlay);

    static IndirectAddressStats stats(const std::vector<IndirectMemoryAccessRecord>& accesses,
                                      const std::vector<IndirectRomConsumerProofRecord>& consumers);
    static std::string kindText(AddressValueKind kind);
    static std::string directionText(IndirectMemoryDirection direction);
};

} // namespace pacripper
