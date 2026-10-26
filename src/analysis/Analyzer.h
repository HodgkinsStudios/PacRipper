#pragma once
// Created by Jacob Hodgkins

#include "../disasm/Z80Disassembler.h"
#include "../rom/RomSet.h"
#include "SymbolDatabase.h"

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace pacripper {

enum class EvidenceKind : std::uint8_t {
    VectorSeed = 1,
    DirectFlow = 2,
    Rst20Dispatch = 4,
    DynamicTrace = 8
};

enum class DataKind : std::uint8_t {
    None = 0,
    Rst20DispatchTable,
    Rst28InlineArgs,
    Rst30InlinePayload,
    CallInlineFiveBytes
};

enum class CandidateKind : std::uint8_t {
    GeneralPointerTable,
    ByteLookupTable,
    WordLookupTable,
    CoordinatePairTable,
    TileTextStream
};

struct DispatchEntry {
    std::size_t index = 0;
    std::uint16_t entryAddress = 0;
    std::uint16_t target = 0;
};

struct DispatchTable {
    std::uint16_t rstAddress = 0;
    std::uint16_t start = 0;
    std::uint16_t end = 0; // exclusive
    std::string boundaryReason;
    std::vector<DispatchEntry> entries;
};

struct DataRegion {
    std::uint16_t sourceAddress = 0;
    std::uint16_t start = 0;
    std::uint16_t end = 0; // exclusive
    DataKind kind = DataKind::None;
};

struct DataCandidate {
    std::uint16_t start = 0;
    std::uint16_t end = 0; // exclusive
    CandidateKind kind = CandidateKind::ByteLookupTable;
    unsigned confidence = 0; // 0-100 heuristic confidence, never treated as proof
    std::size_t observedReadEvents = 0;
    std::set<std::uint16_t> sourcePCs;
    std::set<std::uint16_t> staticRefPCs;
    std::string reason;
};

struct RomDataUsage {
    std::uint16_t address = 0;
    std::size_t readEvents = 0;
    std::set<std::uint16_t> sourcePCs;
};

struct RamAddressUsage {
    std::uint16_t address = 0;
    std::string region;
    std::string symbol;
    std::set<std::uint16_t> staticReaders;
    std::set<std::uint16_t> staticWriters;
    std::set<std::uint16_t> staticAddressRefs;
    std::set<std::uint16_t> dynamicReaders;
    std::set<std::uint16_t> dynamicWriters;
    std::set<std::uint8_t> readValues;
    std::set<std::uint8_t> writeValues;
    std::size_t dynamicReads = 0;
    std::size_t dynamicWrites = 0;
    std::uint64_t firstObservedCycle = 0;
    std::uint64_t lastObservedCycle = 0;
};


struct BoardAddressUsage {
    std::uint16_t address = 0;
    std::set<std::uint16_t> dynamicReaders;
    std::set<std::uint16_t> dynamicWriters;
    std::set<std::uint8_t> readValues;
    std::set<std::uint8_t> writeValues;
    std::size_t dynamicReads = 0;
    std::size_t dynamicWrites = 0;
    std::uint64_t firstObservedCycle = 0;
    std::uint64_t lastObservedCycle = 0;
};

struct AnalysisStats {
    std::size_t romBytes = 0;
    std::size_t codeBytes = 0;
    std::size_t codeInstructions = 0;
    std::size_t dataBytes = 0;
    std::size_t classifiedDataBytes = 0;
    std::size_t unclassifiedBytes = 0;
    std::size_t labels = 0;
    std::size_t calls = 0;
    std::size_t jumps = 0;
    std::size_t memoryReferences = 0;
    std::size_t dispatchTables = 0;
    std::size_t dispatchEntries = 0;
    std::size_t dispatchTargets = 0;
    std::size_t rst28InlineRegions = 0;
    std::size_t rst30InlineRegions = 0;
    std::size_t callInlineFiveByteRegions = 0;
    std::size_t unresolvedIndirectJumps = 0;
    std::size_t classificationConflicts = 0;
    std::size_t traceFilesImported = 0;
    std::size_t dynamicSeedPCs = 0;
    std::size_t dynamicNewInstructions = 0;
    std::size_t dynamicFlowEdgePairs = 0;
    std::size_t dynamicFlowTransitions = 0;
    std::size_t traceMemoryReads = 0;
    std::size_t traceMemoryWrites = 0;
    std::size_t attributedMemoryEvents = 0;
    std::size_t observedRomDataAddresses = 0;
    std::size_t observedRomDataReads = 0;
    std::size_t bulkRomScanPCs = 0;
    std::size_t observedRamAddresses = 0;
    std::size_t dataCandidates = 0;
    std::size_t pointerTableCandidates = 0;
    std::size_t lookupTableCandidates = 0;
    std::size_t coordinateCandidates = 0;
    std::size_t tileTextCandidates = 0;
};

class Analyzer {
public:
    bool analyze(const RomSet& set, std::string& error);
    bool importPacmanArcadeTrace(const std::string& tracePath, std::string& error);
    void clear();

    bool ready() const { return ready_; }
    const std::vector<std::uint8_t>& program() const { return program_; }
    const std::map<std::uint16_t, Instruction>& instructions() const { return instructions_; }
    const std::set<std::uint16_t>& labels() const { return labels_; }
    const std::map<std::uint16_t, std::vector<std::uint16_t>>& codeXrefs() const { return codeXrefs_; }
    const std::map<std::uint16_t, std::vector<std::uint16_t>>& memoryXrefs() const { return memoryXrefs_; }
    const std::map<std::uint16_t, DispatchTable>& dispatchTables() const { return dispatchTables_; }
    const std::map<std::uint16_t, DataRegion>& dataRegions() const { return dataRegions_; }
    const std::vector<DataCandidate>& dataCandidates() const { return dataCandidates_; }
    const std::map<std::uint16_t, RomDataUsage>& romDataUsage() const { return romDataUsage_; }
    const std::map<std::uint16_t, RamAddressUsage>& ramUsage() const { return ramUsage_; }
    const std::map<std::uint16_t, BoardAddressUsage>& boardUsage() const { return boardUsage_; }
    const std::map<std::uint16_t, std::map<std::uint16_t, std::size_t>>& dynamicFlowEdges() const { return dynamicFlowEdges_; }
    const AnalysisStats& stats() const { return stats_; }
    std::uint16_t irqEntry() const { return irqEntry_; }
    std::uint16_t irqVectorAddress() const { return 0x3FFA; }
    bool hasStaticInstructionProof(std::uint16_t address) const {
        const auto it=instructionEvidence_.find(address);
        if(it==instructionEvidence_.end()) return false;
        const std::uint8_t staticMask=static_cast<std::uint8_t>(EvidenceKind::VectorSeed)|
                                      static_cast<std::uint8_t>(EvidenceKind::DirectFlow)|
                                      static_cast<std::uint8_t>(EvidenceKind::Rst20Dispatch);
        return (it->second&staticMask)!=0;
    }
    // A trace seed can discover a new instruction and normal direct-flow tracing can
    // then give its descendants DirectFlow evidence. Keep that ancestry explicit so
    // later proof passes cannot accidentally treat trace-discovered code as an
    // independently static root merely because its descendants have DirectFlow bits.
    bool isTraceDiscoveredInstruction(std::uint16_t address) const {
        return traceDiscoveredInstructionAddresses_.count(address)!=0;
    }
    std::uint8_t instructionEvidenceMask(std::uint16_t address) const {
        const auto it=instructionEvidence_.find(address);return it==instructionEvidence_.end()?0:it->second;
    }
    const std::string& sourcePath() const { return sourcePath_; }
    const SymbolDatabase& symbols() const { return symbols_; }

    bool loadSymbols(const std::string& path, std::string& error);
    bool saveSymbols(const std::string& path, std::string& error) const;
    bool setSymbol(std::uint16_t address, const std::string& name, const std::string& comment, std::string& error);
    std::string symbolFor(std::uint16_t address) const;

    std::string labelFor(std::uint16_t address) const;
    std::string hardwareAnnotation(std::uint16_t address, RefAccess access) const;
    std::vector<std::string> annotatedLines() const;
    std::vector<std::string> linearLines() const;
    std::vector<std::string> summaryLines() const;
    std::vector<std::string> dispatchLines() const;
    std::vector<std::string> dataRegionLines() const;
    std::vector<std::string> dataCandidateLines() const;
    std::vector<std::string> ramUsageLines() const;
    std::vector<std::string> provenanceLines() const;
    std::vector<std::string> symbolLines() const;

    bool exportAll(const std::string& outputDir, std::string& error) const;

private:
    struct WorkItem {
        std::uint16_t address = 0;
        std::uint8_t evidence = 0;
    };
    struct PendingMemoryEvent {
        bool write = false;
        std::uint16_t address = 0;
        std::uint8_t value = 0;
        std::uint64_t machineCycle = 0;
    };

    void traceFrom(std::uint16_t entry, std::uint8_t evidence, std::vector<WorkItem>& work);
    void rebuildDerivedState();
    void rebuildDataCandidates();
    void rebuildStaticRamUsage();
    void recordTraceMemoryEvent(const PendingMemoryEvent& event, int sourcePC, bool sourceReliable);
    bool resolveRst20Table(std::uint16_t rstAddress, std::vector<WorkItem>& work);
    bool markInlineData(std::uint16_t rstAddress, std::uint16_t start, std::size_t length, DataKind kind);
    bool markDataRange(std::uint16_t sourceAddress, std::uint16_t start, std::size_t length, DataKind kind);
    void addCodeXref(std::uint16_t target, std::uint16_t source, bool indirect);
    void queueTarget(std::uint16_t target, std::uint16_t source, std::uint8_t evidence,
                     bool indirect, std::vector<WorkItem>& work);
    std::uint16_t pushedContinuationBefore(std::uint16_t rstAddress) const;
    std::string formatInstruction(const Instruction& in, bool useLabels) const;
    std::string evidenceText(std::uint16_t address) const;
    std::string dataKindText(DataKind kind) const;
    std::string candidateKindText(CandidateKind kind) const;
    std::string jsonEscape(const std::string& s) const;
    bool isPhysicalRamAddress(std::uint16_t address) const;
    std::string ramRegionName(std::uint16_t address) const;
    std::string defaultRamSymbol(std::uint16_t address) const;
    std::string observedAccessClass(const RamAddressUsage& usage) const;
    std::string observedValueProfile(const RamAddressUsage& usage) const;

    bool ready_ = false;
    std::string sourcePath_;
    std::vector<std::uint8_t> program_;
    Z80Disassembler dis_;
    std::map<std::uint16_t, Instruction> instructions_;
    std::vector<bool> codeBytes_;
    std::vector<DataKind> dataBytes_;
    std::set<std::uint16_t> labels_;
    std::set<std::uint16_t> entries_;
    std::map<std::uint16_t, std::vector<std::uint16_t>> codeXrefs_;
    std::map<std::uint16_t, std::vector<std::uint16_t>> indirectCodeXrefs_;
    std::map<std::uint16_t, std::vector<std::uint16_t>> memoryXrefs_;
    std::map<std::uint16_t, DispatchTable> dispatchTables_;
    std::map<std::uint16_t, DataRegion> dataRegions_;
    std::map<std::uint16_t, std::uint8_t> instructionEvidence_;
    std::set<std::uint16_t> unresolvedIndirectSites_;
    std::vector<std::string> traceSources_;
    std::set<std::uint16_t> dynamicSeedAddresses_;
    std::set<std::uint16_t> traceDiscoveredInstructionAddresses_;
    std::map<std::uint16_t, RomDataUsage> romDataUsage_;
    std::map<std::uint16_t, RamAddressUsage> ramUsage_;
    std::map<std::uint16_t, BoardAddressUsage> boardUsage_;
    std::map<std::uint16_t, std::map<std::uint16_t, std::size_t>> dynamicFlowEdges_;
    std::set<std::uint16_t> bulkRomScanPCs_;
    std::vector<DataCandidate> dataCandidates_;
    std::size_t classificationConflictsCount_ = 0;
    std::size_t dynamicNewInstructionsCount_ = 0;
    std::size_t traceMemoryReadEvents_ = 0;
    std::size_t traceMemoryWriteEvents_ = 0;
    std::size_t attributedMemoryEvents_ = 0;
    AnalysisStats stats_;
    std::vector<ValidationItem> validation_;
    std::uint16_t irqEntry_ = 0xFFFF;
    SymbolDatabase symbols_;
};

} // namespace pacripper
