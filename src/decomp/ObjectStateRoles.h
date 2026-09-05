#pragma once
// PacRipper residual-closure analysis neutral semantic ROM/RAM/state roles and state xrefs
// Created by Jacob Hodgkins

#include "DefUseAnalysis.h"
#include "MemoryXrefs.h"
#include "RamShapes.h"
#include "RomObjects.h"
#include "RoutineRoles.h"
#include "TableSchemas.h"
#include "TypeEvidence.h"
#include "TypedLifting.h"
#include "../analysis/Analyzer.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace pacripper {

enum class ObjectRoleTargetKind { RomObject, RamObject, RamShape, RamSchema };
enum class ObjectStateRoleKind {
    RomDataObject,
    RomLookupTable,
    RomPointerTable,
    RomCommandStream,
    RomRecordTable,
    StateStorage,
    StateCounter,
    StateFlagMask,
    StateIndex,
    StateTimerLike,
    StateCoordinatePair,
    StatePointer,
    VideoState,
    InputSample,
    SoundRegisterSource
};

struct ObjectRoleRecord {
    std::size_t id=0;
    ObjectRoleTargetKind targetKind=ObjectRoleTargetKind::RomObject;
    std::size_t targetId=0;
    std::uint16_t start=0;
    std::uint16_t end=0;
    ObjectStateRoleKind role=ObjectStateRoleKind::StateStorage;
    bool staticProof=false;
    bool exact=true;
    std::set<std::uint16_t> sourcePCs;
    std::set<std::size_t> typeEvidenceIds;
    std::set<std::size_t> schemaIds;
    std::set<std::uint16_t> routineEntries;
    std::set<BoardDeviceKind> correlatedDevices;
    std::set<std::size_t> alternativeRoleIds;
    std::set<std::size_t> conflictingRoleIds;
    std::string evidenceSummary;
    // Researcher annotations are intentionally separate from automatic inference.
    std::string researcherName;
    std::string researcherComment;
    std::string researcherTypeHint;
};

enum class StateXrefTargetKind { RamObject, RamSchema };
struct StateXrefRecord {
    std::size_t id=0;
    StateXrefTargetKind targetKind=StateXrefTargetKind::RamObject;
    std::size_t targetId=0;
    std::uint16_t start=0;
    std::uint16_t end=0;
    std::set<std::uint16_t> definiteReaderPCs;
    std::set<std::uint16_t> possibleReaderPCs;
    std::set<std::uint16_t> definiteWriterPCs;
    std::set<std::uint16_t> possibleWriterPCs;
    std::set<std::uint16_t> definiteReaderRoutines;
    std::set<std::uint16_t> possibleReaderRoutines;
    std::set<std::uint16_t> definiteWriterRoutines;
    std::set<std::uint16_t> possibleWriterRoutines;
    std::set<std::size_t> writeDefinitionIds;
    std::set<std::uint16_t> writeValueOriginPCs;
    std::set<std::size_t> typeEvidenceIds;
    std::set<std::uint16_t> masks;
    std::set<std::pair<std::uint16_t,std::uint16_t>> ranges;
    std::set<BoardDeviceKind> hardwareCorrelations;
    std::set<std::uint16_t> callPathNeighbors;
    std::set<std::uint16_t> dynamicReaderPCs;
    std::set<std::uint16_t> dynamicWriterPCs;
    bool dynamicCorroborated=false;
    std::string note;
};

struct ObjectStateRoleStats {
    std::size_t roleRecords=0;
    std::size_t romRoleRecords=0;
    std::size_t ramRoleRecords=0;
    std::size_t conflictingAlternatives=0;
    std::size_t researcherAnnotatedRecords=0;
    std::size_t stateXrefs=0;
    std::size_t stateXrefsWithDefiniteReaders=0;
    std::size_t stateXrefsWithDefiniteWriters=0;
    std::size_t dynamicallyCorroboratedStateXrefs=0;
};

class ObjectStateRoles {
public:
    static std::string targetKindText(ObjectRoleTargetKind kind);
    static std::string roleText(ObjectStateRoleKind role);
    static std::string stateXrefTargetText(StateXrefTargetKind kind);
    static bool rolesConflict(ObjectStateRoleKind a,ObjectStateRoleKind b);

    static std::vector<StateXrefRecord> buildStateXrefs(
        const std::vector<RamObjectRecord>& ramObjects,
        const std::vector<RamShapeRecord>& ramShapes,
        const std::vector<TableSchemaRecord>& schemas,
        const std::vector<MemoryXrefRecord>& memoryXrefs,
        const std::vector<TypeEvidenceRecord>& types,
        const std::vector<RoutineRoleSignatureRecord>& routineRoles,
        const std::vector<RoutineNavigationRecord>& navigation,
        const std::map<std::uint16_t,RamAddressUsage>& ramUsage);

    static std::vector<ObjectRoleRecord> inferRoles(
        const std::vector<RomObjectRecord>& romObjects,
        const std::vector<RamObjectRecord>& ramObjects,
        const std::vector<RamShapeRecord>& ramShapes,
        const std::vector<TableSchemaRecord>& schemas,
        const std::vector<TypeEvidenceRecord>& types,
        const DefUseResult& defUse,
        const std::vector<IndexedExpressionRecord>& indexedExpressions,
        const std::map<std::uint16_t,Instruction>& instructions,
        const std::vector<StateXrefRecord>& stateXrefs,
        const std::map<std::uint16_t,std::set<std::uint16_t>>& pcOwners,
        const std::vector<RoutineRoleSignatureRecord>& routineRoles,
        const SymbolDatabase& symbols);

    static void attachResearchAnnotation(ObjectRoleRecord& record,
                                         const std::string& name,
                                         const std::string& comment,
                                         const std::string& typeHint);

    static ObjectStateRoleStats stats(const std::vector<ObjectRoleRecord>& roles,
                                      const std::vector<StateXrefRecord>& xrefs);
};

} // namespace pacripper
