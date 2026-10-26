#pragma once
// PacRipper command-stream memory analysis byte-value memory lattice / command-stream lifecycle proofs
// Created by Jacob Hodgkins

#include "MemoryAliasAnalysis.h"
#include "../analysis/Analyzer.h"

#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace pacripper {

enum class CommandStreamByteValueKind { Unknown, Exact, FiniteSet, ContiguousRange };
enum class CommandStreamProofKind { ByteValueLifecycle, LoopCarriedIndex, CommandObjectFlags, CommandStreamGraph };

struct CommandStreamByteValue {
    CommandStreamByteValueKind kind=CommandStreamByteValueKind::Unknown;
    std::set<std::uint8_t> values;
    bool hasUnknownAlternative=true;
    bool staticProof=false;
    bool dynamicOnly=false;
    std::set<std::uint16_t> provenancePCs;
    std::string note;
};

struct CommandStreamWriterAliasRecord {
    std::size_t id=0;
    std::set<std::uint16_t> targetAddresses;
    std::set<std::uint16_t> directWriterPCs;
    std::set<std::uint16_t> indirectWriterPCs;
    std::set<std::uint16_t> unknownAliasWriterPCs;
    std::set<std::size_t> indirectWriterProofIds;
    std::set<std::uint16_t> proofPCs;
    bool complete=false;
    std::string note;
};

struct CommandStreamValueProofRecord {
    std::size_t id=0;
    std::string name;
    std::set<std::uint16_t> targetAddresses;
    CommandStreamByteValue value;
    std::set<std::size_t> writerAliasRecordIds;
    std::set<std::uint16_t> proofPCs;
    bool accepted=false;
    std::string note;
};

struct CommandStreamCommandStreamRecord {
    std::size_t id=0;
    std::uint16_t objectBase=0;
    std::uint8_t selector=0;
    std::uint16_t root=0;
    std::set<std::uint16_t> tokenAddresses;
    std::set<std::uint16_t> f0PayloadAddresses;
    std::set<std::uint16_t> f1PayloadAddresses;
    std::set<std::uint16_t> f2PayloadAddresses;
    std::set<std::uint16_t> f3PayloadAddresses;
    std::set<std::uint16_t> f4PayloadAddresses;
    std::set<std::uint16_t> replacementTargets;
    std::set<std::uint16_t> proofPCs;
    bool hasCycle=false;
    bool complete=false;
    std::string note;
};

struct CommandStreamAddressProofRecord {
    std::size_t id=0;
    std::uint16_t pc=0;
    std::string operand;
    CommandStreamProofKind kind=CommandStreamProofKind::ByteValueLifecycle;
    AddressLatticeValue address;
    RootContextDomainClass domainClass=RootContextDomainClass::Unresolved;
    bool inheritedMemoryAliasBlocker=false;
    bool newlyRootedMemoryAliasBlocker=false;
    bool accepted=false;
    std::set<std::size_t> valueProofIds;
    std::set<std::size_t> writerAliasRecordIds;
    std::set<std::size_t> commandStreamRecordIds;
    std::set<std::uint16_t> proofPCs;
    std::string note;
};

struct CommandStreamClosureProvenanceRecord {
    std::uint16_t address=0;
    bool exact=false;
    bool bounded=false;
    std::set<std::size_t> addressProofIds;
    std::set<std::size_t> valueProofIds;
    std::set<std::size_t> writerAliasRecordIds;
    std::set<std::size_t> commandStreamRecordIds;
    std::set<std::uint16_t> sourcePCs;
    std::string note;
};

struct CommandStreamStats {
    std::size_t writerAliasInventories=0;
    std::size_t completeWriterAliasInventories=0;
    std::size_t valueProofs=0;
    std::size_t acceptedValueProofs=0;
    std::size_t commandStreamRoots=0;
    std::size_t completeCommandStreams=0;
    std::size_t commandTokenAddresses=0;
    std::size_t commandPayloadAddresses=0;
    std::size_t commandReplacementTargets=0;
    std::size_t commandCycles=0;
    std::size_t addressProofs=0;
    std::size_t acceptedAddressProofs=0;
    std::size_t inheritedBlockers=0;
    std::size_t refinedInheritedBlockers=0;
    std::size_t remainingInheritedBlockers=0;
    std::size_t newlyRootedBlockers=0;
    std::size_t refinedNewlyRootedBlockers=0;
    std::size_t remainingNewlyRootedBlockers=0;
    std::size_t totalRemainingBlockers=0;
    std::size_t closureProvenanceRecords=0;
    std::size_t newlyExplainedBytes=0;
    std::size_t newlyExactExplainedBytes=0;
    std::size_t newlyBoundedExplainedBytes=0;
    std::size_t unresolvedAfterCommandStream=0;
    std::size_t residualSpansAfterCommandStream=0;
};

struct CommandStreamAnalysisResult {
    std::vector<CommandStreamWriterAliasRecord> writerAliases;
    std::vector<CommandStreamValueProofRecord> valueProofs;
    std::vector<CommandStreamCommandStreamRecord> commandStreams;
    std::vector<CommandStreamAddressProofRecord> addressProofs;
    std::set<std::uint16_t> inheritedBlockerPCs;
    std::set<std::uint16_t> newlyRootedBlockerPCs;
    std::set<std::uint16_t> refinedInheritedBlockerPCs;
    std::set<std::uint16_t> refinedNewlyRootedBlockerPCs;
    std::set<std::uint16_t> remainingInheritedBlockerPCs;
    std::set<std::uint16_t> remainingNewlyRootedBlockerPCs;
};

class CommandStreamAnalysis {
public:
    static CommandStreamAnalysisResult analyze(const Analyzer& analyzer,
                                        const std::vector<SystemRootReachabilityRecord>& rootedReachability,
                                        const std::vector<RootContextAddressProofRecord>& writerProofs,
                                        const std::vector<MemoryAliasWriterAliasRecord>& memoryAliasWriterAliases);
    static std::string byteValueKindText(CommandStreamByteValueKind kind);
    static std::string proofKindText(CommandStreamProofKind kind);
    static bool semanticRomClosureEligible(const CommandStreamAddressProofRecord& proof);
};

} // namespace pacripper
