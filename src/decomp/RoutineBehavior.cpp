// PacRipper contract-aware value flow neutral routine behavior summaries
// Created by Jacob Hodgkins

#include "RoutineBehavior.h"

namespace pacripper {
namespace {
void addSchemaHits(const std::set<std::uint16_t>&addresses,const std::vector<TableSchemaRecord>&schemas,std::set<std::size_t>&out){for(auto a:addresses)for(const auto&s:schemas)if(s.staticProof&&a>=s.start&&a<s.end)out.insert(s.id);}
}

std::vector<RoutineBehaviorRecord> RoutineBehavior::build(const std::vector<RoutineContractRecord>&contracts,const std::vector<TableSchemaRecord>&schemas){std::vector<RoutineBehaviorRecord> out;for(const auto&c:contracts){RoutineBehaviorRecord r;r.functionEntry=c.functionEntry;r.machineInputs=c.inputs;r.machineOutputs=c.outputs;r.definiteRamReads=c.definiteRamReads;r.possibleRamReads=c.possibleRamReads;r.definiteRamWrites=c.definiteRamWrites;r.possibleRamWrites=c.possibleRamWrites;r.definiteHardwareReads=c.definiteHardwareReads;r.possibleHardwareReads=c.possibleHardwareReads;r.definiteHardwareWrites=c.definiteHardwareWrites;r.possibleHardwareWrites=c.possibleHardwareWrites;r.directCallees=c.directCallees;r.unknownCallEffects=c.unknownCallEffects;r.unknownMemoryWrite=c.unknownMemoryWrite;r.nonReturningOrUnknownExit=c.nonReturningOrUnknownExit;addSchemaHits(r.definiteRamReads,schemas,r.readSchemaIds);addSchemaHits(r.possibleRamReads,schemas,r.readSchemaIds);addSchemaHits(r.definiteRamWrites,schemas,r.writeSchemaIds);addSchemaHits(r.possibleRamWrites,schemas,r.writeSchemaIds);out.push_back(r);}return out;}
RoutineBehaviorStats RoutineBehavior::stats(const std::vector<RoutineBehaviorRecord>&records){RoutineBehaviorStats s;s.routines=records.size();for(const auto&r:records){if(!r.readSchemaIds.empty()||!r.writeSchemaIds.empty())++s.schemaAwareRoutines;if(!r.definiteHardwareReads.empty()||!r.possibleHardwareReads.empty()||!r.definiteHardwareWrites.empty()||!r.possibleHardwareWrites.empty())++s.hardwareAwareRoutines;}return s;}

} // namespace pacripper
