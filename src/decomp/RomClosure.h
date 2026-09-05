#pragma once
// Created by Jacob Hodgkins

#include <cstddef>
#include <cstdint>
#include <set>
#include <string>

namespace pacripper {

enum class RomClosurePrimary {
    Code,
    CodeAndDataUse,
    HardData,
    ProvenDataUse,
    BoundedConsumer,
    Candidate,
    PointerTarget,
    ProvenUnused,
    Unresolved
};

enum class RomConsumerKind {
    DirectAbsoluteRead,
    IndirectRegisterRead,
    IndexedRegisterRead,
    BlockTransferRead,
    StackRead,
    Rst10ByteLookup,
    Rst18WordLookup,
    DynamicObservedRead,
    CountedSequentialRead,
    SentinelSequentialRead,
    EncodedSentinelRead,
    InterproceduralRead,
    DelimitedStreamRead,
    PreservedCalleeRead,
    RamPointerReloadRead,
    StackPointerRestoreRead
};

struct RomConsumerRecord {
    std::uint16_t pc = 0;
    std::uint16_t start = 0;
    std::uint16_t end = 0; // exclusive
    RomConsumerKind kind = RomConsumerKind::IndirectRegisterRead;
    std::string pointerRegister;
    std::string indexRegister;
    bool exact = false;          // every byte in [start,end) is an exact statically resolved access
    bool bounded = false;        // [start,end) is a proven address bound, not necessarily all visited
    bool dynamic = false;        // observed bus evidence rather than static proof
    std::string note;
};

struct RomByteClosureRecord {
    std::uint16_t address = 0;
    bool code = false;
    bool hardData = false;
    bool staticExactDataUse = false;
    bool dynamicDataUse = false;
    bool boundedConsumer = false;
    bool candidate = false;
    bool pointerTarget = false;
    bool provenUnused = false; // residual-extent analysis+ exhaustive static negative-reference proof
    std::set<std::uint16_t> consumerPCs;
    RomClosurePrimary primary = RomClosurePrimary::Unresolved;
};

struct RamPairEvidenceRecord {
    std::uint16_t address = 0; // low byte address; pair covers address,address+1
    std::string pairRegister;
    bool read = false;
    bool write = false;
    bool pointerLike = false;
    std::set<std::uint16_t> sourcePCs;
    std::string note;
};

struct RomClosureStats {
    std::size_t romBytes = 0;
    std::size_t codeBytes = 0;
    std::size_t codeAndDataUseBytes = 0;
    std::size_t hardDataBytes = 0;
    std::size_t provenDataUseBytes = 0;
    std::size_t boundedConsumerBytes = 0;
    std::size_t candidateBytes = 0;
    std::size_t pointerTargetBytes = 0;
    std::size_t provenUnusedBytes = 0;
    std::size_t unresolvedBytes = 0;
    std::size_t evidenceBackedExplainedBytes = 0; // code/hard data/proven exact-or-dynamic data use
    std::size_t boundedExplainedBytes = 0;        // evidenceBacked + bounded consumer coverage
    std::size_t consumers = 0;
    std::size_t exactStaticConsumers = 0;
    std::size_t boundedConsumers = 0;
    std::size_t dynamicConsumers = 0;
    std::size_t immediateRomPointerSeeds = 0;
    std::size_t derivedRomPointerTargets = 0;
    std::size_t ramPairs = 0;
    std::size_t pointerLikeRamPairs = 0;
};

class RomClosure {
public:
    static RomClosurePrimary classify(const RomByteClosureRecord& record);
    static std::string primaryText(RomClosurePrimary kind);
    static std::string consumerKindText(RomConsumerKind kind);
    static bool boundedLookupRange(std::uint16_t base,std::uint16_t indexLo,std::uint16_t indexHi,
                                   std::uint16_t scale,std::size_t romSize,
                                   std::uint16_t& start,std::uint16_t& end);
};

} // namespace pacripper
