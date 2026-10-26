#pragma once
// PacRipper def-use analysis RAM object evidence
// Created by Jacob Hodgkins

#include "../analysis/Analyzer.h"
#include "RomClosure.h"

#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace pacripper {

enum class RamObjectKind {
    ByteField,
    WordField,
    BoundedByteArray,
    BoundedWordArray,
    RecordCandidate,
    UnknownGroupedRegion
};

struct RamObjectRecord {
    std::size_t id=0;
    std::uint16_t start=0;
    std::uint16_t end=0; // exclusive
    RamObjectKind kind=RamObjectKind::ByteField;
    std::size_t elementSize=1;
    std::size_t elementCount=1;
    bool staticProof=false;
    bool dynamicOnly=false;
    bool pointerLike=false;
    bool read=false;
    bool write=false;
    std::set<std::uint16_t> sourcePCs;
    std::set<std::uint16_t> overlappingObjectIds;
    std::string note;
};

struct RamObjectStats {
    std::size_t objects=0;
    std::size_t byteFields=0;
    std::size_t wordFields=0;
    std::size_t arrays=0;
    std::size_t recordCandidates=0;
    std::size_t staticObjects=0;
    std::size_t dynamicOnlyObjects=0;
    std::size_t pointerLikeObjects=0;
};

class RamObjects {
public:
    static std::string kindText(RamObjectKind kind);
    static std::vector<RamObjectRecord> reconstruct(const std::map<std::uint16_t,RamAddressUsage>& usage,
                                                    const std::vector<RamPairEvidenceRecord>& pairEvidence);
    static RamObjectStats stats(const std::vector<RamObjectRecord>& objects);
};

} // namespace pacripper
