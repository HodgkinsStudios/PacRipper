#pragma once
// PacRipper contract-aware value flow stable machine-value identities and call bindings
// Created by Jacob Hodgkins

#include "DefUseAnalysis.h"
#include "RoutineContracts.h"
#include "RomObjects.h"
#include "StackModel.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace pacripper {

struct MachineValueRecord {
    std::size_t id=0;
    std::size_t definitionId=0;
    std::uint16_t definitionPC=0;
    std::string entity;
    unsigned bits=0;
    std::string localName;
    std::string originName;
    std::set<std::size_t> originDefinitionIds;
    bool includesEntryOrigin=false;
    bool includesUnknownOrigin=false;
    bool semanticExact=false;
    bool copyAlias=false;
    std::set<std::uint16_t> provenancePCs;
    std::string expression;
};

struct MergeValueRecord {
    std::size_t id=0;
    std::uint16_t pc=0;
    std::string entity;
    std::set<std::size_t> definitionIds;
    bool includesEntryValue=false;
    bool includesClobberedUnknown=false;
    std::set<std::uint16_t> unknownSourcePCs;
    std::string phiText;
};

enum class CallPostValueKind { None, PreservedInput, ProducedOutput };

struct CallBindingRecord {
    std::size_t id=0;
    std::uint16_t callerFunction=0;
    std::uint16_t callPC=0;
    std::uint16_t calleeFunction=0;
    std::string reg;
    ContractCertainty inputCertainty=ContractCertainty::Possible;
    bool hasInputBinding=false;
    bool hasOutputBinding=false;
    std::set<std::size_t> definitionIds;
    bool includesEntryValue=false;
    bool includesClobberedUnknown=false;
    std::vector<std::string> valueNames;
    std::vector<std::string> expressions;
    std::set<std::string> roles;
    bool provenPreserved=false;
    bool provenReturningOutput=false;
    CallPostValueKind postValueKind=CallPostValueKind::None;
    std::string postValueName;
    std::set<std::uint16_t> outputSourcePCs;
};

struct ValueFlowStats {
    std::size_t machineValues=0;
    std::size_t exactMachineValues=0;
    std::size_t copyAliases=0;
    std::size_t mergeValues=0;
    std::size_t callBindings=0;
    std::size_t definiteCallBindings=0;
    std::size_t possibleCallBindings=0;
    std::size_t outputBindings=0;
    std::size_t preservedPostCallValues=0;
    std::size_t returnedPostCallValues=0;
};

class ValueFlow {
public:
    static std::vector<MachineValueRecord> buildMachineValues(const DefUseResult& defUse);
    static std::vector<MergeValueRecord> buildMergeValues(const DefUseResult& defUse);
    static std::vector<CallBindingRecord> buildCallBindings(
        const std::vector<CallSiteRecord>& callSites,
        const std::vector<RoutineContractRecord>& contracts,
        const std::map<std::uint16_t,FunctionRegisterSummary>& summaries,
        const DefUseResult& defUse,
        const std::vector<MachineValueRecord>& values);
    static ValueFlowStats stats(const std::vector<MachineValueRecord>& values,
                                const std::vector<MergeValueRecord>& merges,
                                const std::vector<CallBindingRecord>& bindings);
    static std::string postValueKindText(CallPostValueKind kind);
};

} // namespace pacripper
