#pragma once
// PacRipper contract-aware value flow neutral routine behavior summaries
// Created by Jacob Hodgkins

#include "RoutineContracts.h"
#include "TableSchemas.h"

#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace pacripper {

struct RoutineBehaviorRecord {
    std::uint16_t functionEntry=0;
    std::vector<RegisterContractFact> machineInputs;
    std::vector<RegisterContractFact> machineOutputs;
    std::set<std::uint16_t> definiteRamReads;
    std::set<std::uint16_t> possibleRamReads;
    std::set<std::uint16_t> definiteRamWrites;
    std::set<std::uint16_t> possibleRamWrites;
    std::set<BoardDeviceKind> definiteHardwareReads;
    std::set<BoardDeviceKind> possibleHardwareReads;
    std::set<BoardDeviceKind> definiteHardwareWrites;
    std::set<BoardDeviceKind> possibleHardwareWrites;
    std::set<std::uint16_t> directCallees;
    std::set<std::size_t> readSchemaIds;
    std::set<std::size_t> writeSchemaIds;
    bool unknownCallEffects=false;
    bool unknownMemoryWrite=false;
    bool nonReturningOrUnknownExit=false;
};

struct RoutineBehaviorStats {
    std::size_t routines=0;
    std::size_t schemaAwareRoutines=0;
    std::size_t hardwareAwareRoutines=0;
};

class RoutineBehavior {
public:
    static std::vector<RoutineBehaviorRecord> build(const std::vector<RoutineContractRecord>& contracts,
                                                    const std::vector<TableSchemaRecord>& schemas);
    static RoutineBehaviorStats stats(const std::vector<RoutineBehaviorRecord>& records);
};

} // namespace pacripper
