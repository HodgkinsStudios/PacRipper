#pragma once
// PacRipper type/contract analysis routine machine contracts
// Created by Jacob Hodgkins

#include "HardwareSemantics.h"
#include "DefUseAnalysis.h"
#include "RomObjects.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace pacripper {

enum class ContractCertainty { Definite, Possible };

struct RegisterContractFact {
    std::string reg;
    ContractCertainty certainty=ContractCertainty::Possible;
    std::set<std::uint16_t> sourcePCs;
    std::set<std::string> roles;
};

struct CallInputLink {
    std::uint16_t callPC=0;
    std::uint16_t callee=0;
    std::string reg;
    std::set<std::size_t> definitionIds;
    bool callerEntryAlternative=false;
    bool survivesCall=false;
};

struct RoutineContractRecord {
    std::uint16_t functionEntry=0;
    std::vector<RegisterContractFact> inputs;
    std::vector<RegisterContractFact> outputs;
    std::set<std::uint16_t> definiteRamReads;
    std::set<std::uint16_t> possibleRamReads;
    std::set<std::uint16_t> definiteRamWrites;
    std::set<std::uint16_t> possibleRamWrites;
    std::set<BoardDeviceKind> definiteHardwareReads;
    std::set<BoardDeviceKind> possibleHardwareReads;
    std::set<BoardDeviceKind> definiteHardwareWrites;
    std::set<BoardDeviceKind> possibleHardwareWrites;
    std::set<std::uint16_t> directCallees;
    std::set<std::string> preservedRegisters;
    std::set<std::string> clobberedRegisters;
    bool unknownCallEffects=false;
    bool unknownMemoryWrite=false;
    bool nonReturningOrUnknownExit=false;
    std::vector<CallInputLink> callInputLinks;
};

struct RoutineContractStats {
    std::size_t routines=0;
    std::size_t definiteRegisterInputs=0;
    std::size_t possibleRegisterInputs=0;
    std::size_t returningRegisterOutputs=0;
    std::size_t ramReadFacts=0;
    std::size_t ramWriteFacts=0;
    std::size_t hardwareReadFacts=0;
    std::size_t hardwareWriteFacts=0;
    std::size_t callInputLinks=0;
    std::size_t preservedCallLinks=0;
};

class RoutineContracts {
public:
    static bool survivesDirectCall(const std::string& reg,const FunctionRegisterSummary* calleeSummary);
    static bool classifyEntryInput(const ReachingDefinitionFact& fact,ContractCertainty& certainty);
    static bool isProducedReturnValue(const ReachingDefinitionFact& fact);
    static void normalize(RoutineContractRecord& record);
    static RoutineContractStats stats(const std::vector<RoutineContractRecord>& records);
    static std::string certaintyText(ContractCertainty certainty);
};

} // namespace pacripper
