#pragma once
// PacRipper residual-closure analysis residual ROM closure audit and proof helpers
// Created by Jacob Hodgkins

#include "RomObjects.h"
#include "TableSchemas.h"
#include "../disasm/Z80Disassembler.h"

#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace pacripper {

enum class ResidualAuditReason {
    NoKnownConsumer,
    PointerTargetUnconsumed,
    BoundedConsumerOverlap,
    DynamicOnlyRomObservation,
    DormantCodeCandidate,
    FillerRepetitionCandidate,
    KnownObjectExtentUnproven,
    ConflictingInterpretations
};

enum class DormantCodeSeedKind {
    StaticCodePointer,
    PointerTableCodeUse,
    ExistingControlTarget,
    TraceObservedPc
};

struct DormantCodeSeedRecord {
    std::size_t id=0;
    std::uint16_t address=0;
    DormantCodeSeedKind kind=DormantCodeSeedKind::StaticCodePointer;
    bool staticProof=false;
    bool dynamicOnly=false;
    std::set<std::uint16_t> sourcePCs;
    std::string note;
};

struct DormantCodeDiscoveryRecord {
    std::size_t id=0;
    std::size_t seedId=0;
    std::uint16_t entry=0;
    DormantCodeSeedKind seedKind=DormantCodeSeedKind::StaticCodePointer;
    bool staticProof=false;
    bool dynamicOnly=false;
    bool accepted=false;
    bool hardDataConflict=false;
    bool indirectExit=false;
    bool reachesKnownCode=false;
    std::set<std::uint16_t> instructionPCs;
    std::set<std::uint16_t> byteAddresses;
    std::set<std::uint16_t> provenancePCs;
    std::string note;
};

struct ResidualAuditRecord {
    std::size_t id=0;
    std::uint16_t start=0;
    std::uint16_t end=0; // exclusive
    std::size_t length=0;
    std::set<ResidualAuditReason> reasons;
    std::set<std::size_t> nearbyObjectIds;
    std::set<std::uint16_t> nearbyConsumerPCs;
    std::set<std::size_t> dormantSeedIds;
    bool staticEvidence=false;
    bool dynamicEvidence=false;
    bool repetitionCandidate=false;
    std::string note;
};

enum class RomExtentProofKind {
    BoundedConsumer,
    CountedConsumer,
    SentinelConsumer,
    ExactSchema,
    RepeatedExactConsumers
};

struct RomExtentRefinementRecord {
    std::size_t id=0;
    std::size_t objectId=0;
    std::uint16_t oldStart=0;
    std::uint16_t oldEnd=0;
    std::uint16_t newStart=0;
    std::uint16_t newEnd=0;
    RomExtentProofKind proofKind=RomExtentProofKind::BoundedConsumer;
    bool exactClosure=false;
    bool boundedClosure=false;
    bool accepted=false;
    std::set<std::uint16_t> sourcePCs;
    std::set<std::size_t> schemaIds;
    std::string note;
};

struct ResidualPriorityV2Record {
    std::size_t auditId=0;
    std::uint16_t start=0;
    std::uint16_t end=0;
    std::size_t length=0;
    int score=0;
    std::size_t codeSeedEvidence=0;
    std::size_t pointerProximity=0;
    std::size_t objectBoundaryProximity=0;
    std::size_t repeatedConsumers=0;
    std::size_t routineRelevance=0;
    std::size_t dynamicObservation=0;
    std::size_t conflictPenalty=0;
    std::string reason;
};

struct ResidualResearchStats {
    std::size_t auditSpans=0;
    std::size_t auditedUnresolvedBytes=0;
    std::size_t noKnownConsumerSpans=0;
    std::size_t dormantSeeds=0;
    std::size_t acceptedDormantDiscoveries=0;
    std::size_t dormantCodeBytes=0;
    std::size_t rejectedHardDataOverlaps=0;
    std::size_t extentRefinements=0;
    std::size_t exactExtentRefinements=0;
    std::size_t boundedExtentRefinements=0;
    std::size_t priorityRecords=0;
};

class ResidualResearch {
public:
    static std::string auditReasonText(ResidualAuditReason reason);
    static std::string seedKindText(DormantCodeSeedKind kind);
    static std::string extentProofText(RomExtentProofKind kind);

    static std::vector<DormantCodeDiscoveryRecord> discoverDormantCode(
        const std::vector<std::uint8_t>& program,
        const std::vector<RomByteClosureRecord>& closure,
        const std::vector<DormantCodeSeedRecord>& seeds);

    static std::vector<RomExtentRefinementRecord> refineObjectExtents(
        const std::vector<RomObjectRecord>& objects,
        const std::vector<RomConsumerRecord>& consumers,
        const std::vector<TableSchemaRecord>& schemas,
        const std::vector<RomByteClosureRecord>& closure);

    static std::vector<ResidualAuditRecord> auditResidualSpans(
        const std::vector<RomByteClosureRecord>& closure,
        const std::vector<RomObjectRecord>& objects,
        const std::vector<RomConsumerRecord>& consumers,
        const std::vector<DormantCodeSeedRecord>& seeds,
        const std::vector<std::uint8_t>& program);

    static std::vector<ResidualPriorityV2Record> prioritizeV2(
        const std::vector<ResidualAuditRecord>& audit,
        const std::vector<RomByteClosureRecord>& closure,
        const std::vector<RomConsumerRecord>& consumers,
        std::size_t maxSpans=128);

    static ResidualResearchStats stats(const std::vector<ResidualAuditRecord>& audit,
                                       const std::vector<DormantCodeSeedRecord>& seeds,
                                       const std::vector<DormantCodeDiscoveryRecord>& discoveries,
                                       const std::vector<RomExtentRefinementRecord>& extents,
                                       const std::vector<ResidualPriorityV2Record>& priority);
};

} // namespace pacripper
