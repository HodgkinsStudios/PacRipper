#pragma once
// PacRipper hardware-semantics analysis conservative RAM shape refinement
// Created by Jacob Hodgkins

#include "RamObjects.h"

#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace pacripper {

enum class RamShapeKind { BoundedByteArray, BoundedWordArray, RecordCandidate };
enum class RamShapeEvidenceKind { BlockTransfer, BlockScan, ProvenStrideAndBounds, RepeatedRecordStride };

struct RamShapeEvidence {
    std::uint16_t start=0;
    std::size_t elementSize=1;
    std::size_t elementCount=0;
    std::size_t stride=1;
    bool boundsExact=false;
    bool staticProof=false;
    bool dynamicObserved=false;
    RamShapeEvidenceKind kind=RamShapeEvidenceKind::ProvenStrideAndBounds;
    std::set<std::uint16_t> sourcePCs;
    std::string note;
};

struct RamShapeRecord {
    std::size_t id=0;
    RamShapeKind kind=RamShapeKind::BoundedByteArray;
    std::uint16_t start=0;
    std::uint16_t end=0; // exclusive
    std::size_t elementSize=1;
    std::size_t elementCount=0;
    std::size_t stride=1;
    bool staticProof=false;
    bool dynamicObserved=false;
    RamShapeEvidenceKind evidenceKind=RamShapeEvidenceKind::ProvenStrideAndBounds;
    std::set<std::uint16_t> sourcePCs;
    std::set<std::size_t> underlyingRamObjectIds;
    std::string note;
};

struct RamShapeStats {
    std::size_t shapes=0;
    std::size_t arrays=0;
    std::size_t records=0;
    std::size_t staticShapes=0;
};

class RamShapes {
public:
    static std::vector<RamShapeRecord> reconstruct(const std::vector<RamObjectRecord>& baseObjects,
                                                   const std::vector<RamShapeEvidence>& evidence);
    static RamShapeStats stats(const std::vector<RamShapeRecord>& records);
    static std::string kindText(RamShapeKind kind);
    static std::string evidenceKindText(RamShapeEvidenceKind kind);
};

} // namespace pacripper
