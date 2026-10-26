// PacRipper residual-reference analysis residual high-ROM reference / negative-proof model
// Created by Jacob Hodgkins

#include "ResidualReferenceAnalysis.h"

#include <algorithm>

namespace pacripper {
namespace {
bool inSpan(std::uint16_t value,std::uint16_t start,std::uint16_t end){return value>=start&&value<end;}
}

bool ResidualReferenceAnalysis::addressValueIntersects(const AddressLatticeValue& value,
                                                        std::uint16_t start,std::uint16_t end){
    if(start>=end)return false;
    switch(value.kind){
        case AddressValueKind::Exact:
        case AddressValueKind::FiniteSet:
        case AddressValueKind::AmbiguousAlternatives:
            for(auto v:value.values)if(inSpan(v,start,end))return true;
            return false;
        case AddressValueKind::ContiguousRange:
            if(value.wraparound)return true; // conservative: wrapped range may cross any local span
            return value.rangeStart<end&&start<=value.rangeEnd;
        case AddressValueKind::StridedRange:{
            if(value.wraparound)return true;
            if(value.rangeStart>=end||start>value.rangeEnd)return false;
            const unsigned stride=value.stride?value.stride:1;
            const unsigned lo=std::max<unsigned>(start,value.rangeStart);
            const unsigned delta=lo-value.rangeStart;
            const unsigned first=value.rangeStart+((delta+stride-1)/stride)*stride;
            return first<end&&first<=value.rangeEnd;
        }
        case AddressValueKind::Unknown:return false;
    }
    return false;
}

bool ResidualReferenceAnalysis::qualifiesUnused(const NegativeReferenceRecord& r){
    const bool boundaries=(r.leftBoundaryProven||r.leftRomBoundary)&&
                          (r.rightBoundaryProven||r.rightRomBoundary);
    return r.directReferenceAbsent&&r.finiteIndirectReferenceAbsent&&r.controlReferenceAbsent&&
           r.systemSemanticAbsent&&r.exhaustiveModeledStaticAbsence&&boundaries&&
           r.dynamicReadEvents==0;
}

UnusedRomRegionRecord ResidualReferenceAnalysis::unusedRegion(const NegativeReferenceRecord& r,
                                                               std::size_t id){
    UnusedRomRegionRecord out;out.id=id;out.negativeReferenceId=r.id;out.start=r.start;out.end=r.end;
    out.accepted=qualifiesUnused(r);
    out.note=out.accepted
        ?"Accepted only because the modeled static reference inventory is exhaustive for this span, all positive reference classes are absent, both boundaries are proven, and no dynamic read contradicts the result."
        :"Not classified unused: absence in non-exhaustive reference classes is diagnostic only.";
    return out;
}

bool ResidualReferenceAnalysis::applyExactSystemSemantic(const SystemRomSemanticRecord& s,
                                                          const std::vector<RomByteClosureRecord>& baseline,
                                                          std::vector<RomByteClosureRecord>& overlay,
                                                          std::vector<ResidualReferenceClosureProvenanceRecord>& provenance){
    if(!s.staticProof||!s.exact||s.start>=s.end||s.end>overlay.size()||baseline.size()!=overlay.size())return false;
    bool changed=false;
    for(std::size_t a=s.start;a<s.end;++a){
        if(baseline[a].primary!=RomClosurePrimary::Unresolved)continue;
        RomByteClosureRecord& b=overlay[a];const bool was=b.primary==RomClosurePrimary::Unresolved;
        b.staticExactDataUse=true;b.primary=RomClosure::classify(b);
        if(was&&b.primary!=RomClosurePrimary::Unresolved){
            changed=true;ResidualReferenceClosureProvenanceRecord p;p.address=static_cast<std::uint16_t>(a);p.exact=true;
            p.systemSemanticIds.insert(s.id);p.proofPCs=s.proofPCs;p.note=s.note;provenance.push_back(p);
        }
    }
    return changed;
}

std::string ResidualReferenceAnalysis::systemSemanticKindText(SystemRomSemanticKind kind){
    switch(kind){case SystemRomSemanticKind::InterruptVectorWord:return"interrupt-vector-word";}
    return"system-rom-semantic";
}

} // namespace pacripper
