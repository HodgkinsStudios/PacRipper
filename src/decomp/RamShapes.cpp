// PacRipper hardware-semantics analysis conservative RAM shape refinement
// Created by Jacob Hodgkins

#include "RamShapes.h"

#include <algorithm>
#include <cstdint>
#include <map>
#include <tuple>

namespace pacripper {

std::string RamShapes::kindText(RamShapeKind k){switch(k){case RamShapeKind::BoundedByteArray:return"bounded-byte-array";case RamShapeKind::BoundedWordArray:return"bounded-word-array";case RamShapeKind::RecordCandidate:return"record-candidate";}return"unknown";}
std::string RamShapes::evidenceKindText(RamShapeEvidenceKind k){switch(k){case RamShapeEvidenceKind::BlockTransfer:return"block-transfer";case RamShapeEvidenceKind::BlockScan:return"block-scan";case RamShapeEvidenceKind::ProvenStrideAndBounds:return"proven-stride-and-bounds";case RamShapeEvidenceKind::RepeatedRecordStride:return"repeated-record-stride";}return"unknown";}

std::vector<RamShapeRecord> RamShapes::reconstruct(const std::vector<RamObjectRecord>& baseObjects,const std::vector<RamShapeEvidence>& evidence){
    std::vector<RamShapeRecord> out;
    std::map<std::tuple<std::uint16_t,std::size_t,std::size_t,std::size_t,RamShapeEvidenceKind>,std::size_t> seen;
    for(const auto& e:evidence){
        // hardware-semantics analysis deliberately requires actual shape proof. Dynamic-only runs,
        // adjacency, or a stride without an exact bound are insufficient.
        if(!e.staticProof||!e.boundsExact||e.elementCount<2||e.elementSize==0||e.stride==0)continue;
        if(e.kind!=RamShapeEvidenceKind::RepeatedRecordStride&&e.stride!=e.elementSize)continue;
        const std::uint64_t span=static_cast<std::uint64_t>(e.stride)*(e.elementCount-1)+e.elementSize;
        if(span==0||static_cast<std::uint64_t>(e.start)+span>0x10000u)continue;
        const auto end=static_cast<std::uint16_t>(static_cast<std::uint64_t>(e.start)+span);
        const auto key=std::make_tuple(e.start,e.elementSize,e.elementCount,e.stride,e.kind);
        auto si=seen.find(key);
        if(si!=seen.end()){auto& r=out[si->second];r.sourcePCs.insert(e.sourcePCs.begin(),e.sourcePCs.end());r.dynamicObserved=r.dynamicObserved||e.dynamicObserved;continue;}
        RamShapeRecord r;r.id=out.size();r.start=e.start;r.end=end;r.elementSize=e.elementSize;r.elementCount=e.elementCount;r.stride=e.stride;r.staticProof=true;r.dynamicObserved=e.dynamicObserved;r.evidenceKind=e.kind;r.sourcePCs=e.sourcePCs;r.note=e.note;
        if(e.kind==RamShapeEvidenceKind::RepeatedRecordStride)r.kind=RamShapeKind::RecordCandidate;else r.kind=e.elementSize==2?RamShapeKind::BoundedWordArray:RamShapeKind::BoundedByteArray;
        for(const auto& b:baseObjects)if(r.start<b.end&&b.start<r.end)r.underlyingRamObjectIds.insert(b.id);
        seen[key]=r.id;out.push_back(r);
    }
    return out;
}

RamShapeStats RamShapes::stats(const std::vector<RamShapeRecord>& records){RamShapeStats s;s.shapes=records.size();for(const auto& r:records){if(r.staticProof)++s.staticShapes;if(r.kind==RamShapeKind::RecordCandidate)++s.records;else ++s.arrays;}return s;}

} // namespace pacripper
