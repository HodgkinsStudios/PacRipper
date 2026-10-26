#pragma once
// PacRipper high-ROM semantic analysis high-ROM decoder grammar and semantic closure
// Created by Jacob Hodgkins

#include "RomClosure.h"

#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace pacripper {

enum class RomDecoderGrammarKind {
    Delimited2FNormal,
    CommandDispatchF0,
    SignedPairZero
};

enum class HighRomAuditCategory {
    StreamTargetGap,
    PointerTableGap,
    RecordFieldGap,
    PossibleSharedObjectOverlap,
    DecoderUnreachedPayload,
    ConstantFillCandidate,
    NoSemanticConsumer
};

struct RomDecoderCommandRule {
    std::uint8_t opcodeLo=0;
    std::uint8_t opcodeHi=0;
    unsigned payloadBytes=0;
    bool littleEndianJump=false;
    bool terminates=false;
    std::set<std::uint16_t> proofPCs;
    std::string note;
};

struct RomDecoderRecord {
    std::size_t id=0;
    std::uint16_t routine=0;
    RomDecoderGrammarKind grammar=RomDecoderGrammarKind::Delimited2FNormal;
    std::string pointerIdentity;
    std::set<std::uint16_t> readPCs;
    std::set<std::uint16_t> commandTestPCs;
    std::set<std::uint16_t> terminatorPCs;
    std::set<std::uint16_t> pointerUpdatePCs;
    std::set<std::uint16_t> sourcePCs;
    std::vector<RomDecoderCommandRule> rules;
    std::uint8_t delimiter=0;
    unsigned prefixBytes=0;
    bool staticGrammarProof=false;
    bool pointerContinuityProven=false;
    bool dynamicOnly=false;
    bool dynamicSeededCode=false;
    std::string note;
};

struct PointerIndexRange {
    std::uint16_t lo=0;
    std::uint16_t hi=0;
};

struct PointerTableDomainRecord {
    std::size_t id=0;
    std::size_t decoderId=0;
    std::uint16_t base=0;
    unsigned stride=2;
    std::vector<PointerIndexRange> ranges;
    std::set<std::uint16_t> indices;
    std::set<std::uint16_t> entryAddresses;
    std::set<std::uint16_t> callPCs;
    std::set<std::uint16_t> proofPCs;
    std::set<std::size_t> originDefinitionIds;
    bool staticProof=false;
    bool sparse=false;
    bool exact=false;
    bool bounded=false;
    std::string note;
};

struct StreamSemanticRecord {
    std::size_t id=0;
    std::size_t decoderId=0;
    std::set<std::size_t> tableDomainIds;
    std::set<std::uint16_t> tableIndices;
    std::set<std::uint16_t> tableEntryAddresses;
    std::uint16_t start=0;
    std::uint16_t end=0; // exclusive bounding extent; coveredAddresses is canonical
    std::set<std::uint16_t> coveredAddresses;
    std::set<std::uint16_t> readPCs;
    std::set<std::uint16_t> proofPCs;
    std::set<std::size_t> originDefinitionIds;
    bool exact=false;
    bool bounded=false;
    bool terminated=false;
    bool cyclic=false;
    bool contiguous=false;
    bool accepted=false;
    bool staticProof=false;
    bool dynamicOnly=false;
    std::string terminationReason;
    std::string note;
};

struct StreamFamilyRecord {
    std::size_t id=0;
    std::size_t decoderId=0;
    std::string name;
    std::set<std::size_t> tableDomainIds;
    std::set<std::size_t> streamIds;
    std::set<std::uint16_t> tableIndices;
    std::set<std::uint16_t> streamStarts;
    bool staticProof=false;
    std::string note;
};

struct BoundedBlockSemanticRecord {
    std::size_t id=0;
    std::uint16_t base=0;
    std::uint16_t startOffsetLo=0;
    std::uint16_t startOffsetHi=0;
    unsigned width=0;
    std::set<std::uint16_t> coveredAddresses;
    std::set<std::uint16_t> readPCs;
    std::set<std::uint16_t> proofPCs;
    std::set<std::size_t> originDefinitionIds;
    bool exact=false;
    bool bounded=false;
    bool staticProof=false;
    std::string note;
};

struct FixedRecordSemanticRecord {
    std::size_t id=0;
    std::uint16_t base=0;
    unsigned stride=0;
    std::set<std::uint16_t> recordIndices;
    std::set<unsigned> fieldOffsets;
    std::set<std::uint16_t> coveredAddresses;
    std::set<std::uint16_t> readPCs;
    std::set<std::uint16_t> proofPCs;
    std::set<std::size_t> originDefinitionIds;
    bool exact=false;
    bool bounded=false;
    bool staticProof=false;
    std::string note;
};

struct HighRomClosureProvenanceRecord {
    std::uint16_t address=0;
    bool exact=false;
    bool bounded=false;
    std::set<std::size_t> decoderIds;
    std::set<std::size_t> tableDomainIds;
    std::set<std::size_t> streamIds;
    std::set<std::size_t> recordIds;
    std::set<std::size_t> blockIds;
    std::set<std::uint16_t> readPCs;
    std::set<std::uint16_t> proofPCs;
    std::set<std::size_t> originDefinitionIds;
    std::string note;
};

struct HighRomResidualAuditRecord {
    std::size_t id=0;
    std::uint16_t start=0;
    std::uint16_t end=0;
    std::size_t length=0;
    std::set<HighRomAuditCategory> categories;
    std::set<std::size_t> nearbyDecoderIds;
    std::set<std::size_t> nearbyTableDomainIds;
    std::set<std::size_t> nearbyStreamIds;
    std::set<std::size_t> nearbyRecordIds;
    std::set<std::size_t> nearbyBlockIds;
    bool constantRun=false;
    std::uint8_t constantValue=0;
    std::string note;
};

struct SemanticCoverageStats {
    std::size_t romBytes=0;
    std::size_t indirectAddressExplainedBytes=0;
    std::size_t checksumOnlyBytes=0;
    std::size_t semanticBytesBeforeHighRom=0;
    std::size_t highRomNewSemanticBytes=0;
    std::size_t semanticBytesAfterHighRom=0;
    std::size_t unresolvedAfterHighRom=0;
};

struct StreamParseResult {
    bool accepted=false;
    bool terminated=false;
    bool cyclic=false;
    bool contiguous=false;
    std::uint16_t start=0;
    std::uint16_t end=0;
    std::set<std::uint16_t> coveredAddresses;
    std::string reason;
};

class HighRomSemantics {
public:
    static PointerTableDomainRecord pointerTableDomain(std::uint16_t base,unsigned stride,
                                                       const std::set<std::uint16_t>& indices,
                                                       std::size_t romSize,bool staticProof);
    static StreamParseResult parseDelimited2FNormal(const std::vector<std::uint8_t>& program,
                                                    std::uint16_t start,const RomDecoderRecord& decoder);
    static StreamParseResult parseCommandDispatchF0(const std::vector<std::uint8_t>& program,
                                                    std::uint16_t start,const RomDecoderRecord& decoder,
                                                    std::size_t maxSteps=4096);
    static StreamParseResult parseSignedPairZero(const std::vector<std::uint8_t>& program,
                                                 std::uint16_t start,const RomDecoderRecord& decoder,
                                                 std::size_t maxSteps=4096);
    static FixedRecordSemanticRecord fixedRecordFieldUnion(std::uint16_t base,unsigned stride,
                                                           const std::set<std::uint16_t>& recordIndices,
                                                           const std::set<unsigned>& fieldOffsets,
                                                           std::size_t romSize,bool staticProof);
    static BoundedBlockSemanticRecord boundedBlockWindowUnion(std::uint16_t base,
                                                              std::uint16_t startOffsetLo,
                                                              std::uint16_t startOffsetHi,
                                                              unsigned width,
                                                              std::size_t romSize,bool staticProof);
    static bool applySemanticByte(std::vector<RomByteClosureRecord>& overlay,std::uint16_t address,
                                  bool exact,bool bounded,const std::set<std::uint16_t>& readPCs);
    static std::string decoderKindText(RomDecoderGrammarKind kind);
    static std::string auditCategoryText(HighRomAuditCategory kind);
};

} // namespace pacripper
