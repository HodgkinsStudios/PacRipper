#pragma once
// PacRipper IM2/vector-domain analysis final IM2 vector-latch domain / ROM-tail closure model
// Created by Jacob Hodgkins

#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace pacripper {

enum class Im2VectorOutputKind {
    ImmediatePortA,
    RegisterPort,
    BlockOutput
};

struct Im2VectorOutputInventoryRecord {
    std::size_t id=0;
    std::uint16_t pc=0;
    Im2VectorOutputKind kind=Im2VectorOutputKind::ImmediatePortA;
    std::string mnemonic;
    std::string operands;
    bool independentlyStatic=false;
    bool systemRootRootReachable=false;
    bool portDomainComplete=false;
    std::set<std::uint8_t> portLowValues;
    bool canSelectVectorLatch=false;
    bool dataDomainComplete=false;
    std::set<std::uint8_t> dataValues;
    std::set<std::uint16_t> proofPCs;
    std::string note;
};

struct Im2VectorCpuModeProofRecord {
    std::size_t id=0;
    std::uint8_t interruptPage=0;
    std::set<std::uint16_t> iWritePCs;
    std::set<std::uint16_t> interruptModePCs;
    std::set<std::uint16_t> interruptEnablePCs;
    std::set<std::uint16_t> vectorLatchWriterPCs;
    bool iWriterInventoryComplete=false;
    bool interruptModeInventoryComplete=false;
    bool iPageExact=false;
    bool im2Exact=false;
    bool latchInitializedBeforeEnable=false;
    bool accepted=false;
    std::set<std::uint16_t> proofPCs;
    std::string note;
};

struct Im2VectorVectorDomainProofRecord {
    std::size_t id=0;
    std::size_t cpuModeProofId=0;
    std::uint8_t interruptPage=0;
    std::set<std::size_t> outputInventoryIds;
    std::set<std::size_t> vectorWriterIds;
    std::set<std::uint16_t> unknownAliasWriterPCs;
    std::set<std::uint8_t> vectorValues;
    std::set<std::uint16_t> vectorWordAddresses;
    std::set<std::uint8_t> tailSelectingValues;
    bool rootedOutputInventoryComplete=false;
    bool allVectorWritersFinite=false;
    bool completeValueUnion=false;
    bool tailSelectionExcluded=false;
    bool accepted=false;
    std::set<std::uint16_t> proofPCs;
    std::string note;
};

struct Im2VectorSystemNegativeRecord {
    std::size_t id=0;
    std::uint16_t start=0;
    std::uint16_t end=0; // exclusive
    std::size_t residualExtentNegativeProofId=static_cast<std::size_t>(-1);
    std::size_t vectorDomainProofId=static_cast<std::size_t>(-1);
    bool residualExtentGenericNegativeExhaustive=false;
    bool cpuModeProofAccepted=false;
    bool vectorDomainProofAccepted=false;
    bool tailNotSelected=false;
    bool accepted=false;
    std::set<std::uint16_t> proofPCs;
    std::string note;
};

struct Im2VectorClosureProvenanceRecord {
    std::uint16_t address=0;
    bool provenUnused=false;
    std::set<std::size_t> systemNegativeProofIds;
    std::set<std::size_t> vectorDomainProofIds;
    std::set<std::size_t> outputInventoryIds;
    std::set<std::uint16_t> proofPCs;
    std::string note;
};

struct Im2VectorFinalResidualRecord {
    std::size_t id=0;
    std::uint16_t start=0;
    std::uint16_t end=0;
    std::size_t length=0;
    std::string reason;
};

struct Im2VectorStats {
    std::size_t rootedOutputInstructions=0;
    std::size_t vectorLatchWriters=0;
    std::size_t unknownAliasWriters=0;
    std::size_t finiteVectorValues=0;
    std::size_t reachableVectorWords=0;
    std::size_t tailSelectingVectorValues=0;
    std::size_t systemNegativeProofs=0;
    std::size_t acceptedSystemNegativeProofs=0;
    std::size_t newlyUnusedExplainedBytes=0;
    std::size_t newlyExplainedBytes=0;
    std::size_t unresolvedAfterIm2Vector=0;
    std::size_t residualSpansAfterIm2Vector=0;
    bool rootedOutputInventoryComplete=false;
    bool cpuModeProofAccepted=false;
    bool vectorDomainComplete=false;
    bool tailSelectionExcluded=false;
};

class Im2VectorAnalysis {
public:
    static std::uint16_t vectorWordAddress(std::uint8_t interruptPage,std::uint8_t vectorByte);
    static bool vectorWordIntersects(std::uint8_t interruptPage,std::uint8_t vectorByte,
                                     std::uint16_t start,std::uint16_t end);
    static bool qualifiesFinalUnused(const Im2VectorSystemNegativeRecord& record);
    static std::string outputKindText(Im2VectorOutputKind kind);
};

} // namespace pacripper
