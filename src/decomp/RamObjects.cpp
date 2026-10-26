// PacRipper def-use analysis RAM object evidence
// Created by Jacob Hodgkins

#include "RamObjects.h"

#include <algorithm>
#include <map>
#include <sstream>

namespace pacripper {

std::string RamObjects::kindText(RamObjectKind k){
    switch(k){case RamObjectKind::ByteField:return"byte-field";case RamObjectKind::WordField:return"word-field-le16";case RamObjectKind::BoundedByteArray:return"bounded-byte-array";case RamObjectKind::BoundedWordArray:return"bounded-word-array";case RamObjectKind::RecordCandidate:return"record-candidate";case RamObjectKind::UnknownGroupedRegion:return"unknown-grouped-region";}return"unknown";
}

std::vector<RamObjectRecord> RamObjects::reconstruct(const std::map<std::uint16_t,RamAddressUsage>& usage,
                                                     const std::vector<RamPairEvidenceRecord>& pairs){
    std::vector<RamObjectRecord> out;
    std::map<std::uint16_t,RamObjectRecord> words;
    for(const auto& p:pairs){
        auto& r=words[p.address];r.start=p.address;r.end=static_cast<std::uint16_t>(p.address+2);r.kind=RamObjectKind::WordField;r.elementSize=2;r.elementCount=1;r.staticProof=true;r.read=r.read||p.read;r.write=r.write||p.write;r.pointerLike=r.pointerLike||p.pointerLike;r.sourcePCs.insert(p.sourcePCs.begin(),p.sourcePCs.end());
        r.note="direct Z80 16-bit little-endian access proves the two adjacent bytes are one machine word at these access sites";
    }
    std::set<std::uint16_t> wordCovered;
    for(auto& kv:words){kv.second.id=out.size();out.push_back(kv.second);wordCovered.insert(kv.first);wordCovered.insert(static_cast<std::uint16_t>(kv.first+1));}

    for(const auto& kv:usage){const auto& u=kv.second;if(wordCovered.count(u.address))continue;const bool staticRead=!u.staticReaders.empty(),staticWrite=!u.staticWriters.empty(),staticAddress=!u.staticAddressRefs.empty();const bool dynamic=(u.dynamicReads||u.dynamicWrites)>0;if(!staticRead&&!staticWrite&&!staticAddress&&!dynamic)continue;
        RamObjectRecord r;r.id=out.size();r.start=u.address;r.end=static_cast<std::uint16_t>(u.address+1);r.kind=RamObjectKind::ByteField;r.elementSize=1;r.elementCount=1;r.staticProof=staticRead||staticWrite||staticAddress;r.dynamicOnly=!r.staticProof&&dynamic;r.read=staticRead||u.dynamicReads;r.write=staticWrite||u.dynamicWrites;r.sourcePCs.insert(u.staticReaders.begin(),u.staticReaders.end());r.sourcePCs.insert(u.staticWriters.begin(),u.staticWriters.end());r.sourcePCs.insert(u.staticAddressRefs.begin(),u.staticAddressRefs.end());
        if(r.staticProof)r.note="single-byte RAM field evidenced by exact static address references; no larger grouping is asserted";else r.note="dynamic-only observed RAM byte; retained for navigation but not promoted to static grouping proof";out.push_back(r);
    }

    // Preserve overlap metadata instead of flattening alternate byte/word interpretations.
    for(std::size_t i=0;i<out.size();++i)for(std::size_t j=i+1;j<out.size();++j)if(out[i].start<out[j].end&&out[j].start<out[i].end){out[i].overlappingObjectIds.insert(out[j].id);out[j].overlappingObjectIds.insert(out[i].id);}
    return out;
}

RamObjectStats RamObjects::stats(const std::vector<RamObjectRecord>& objects){RamObjectStats s;s.objects=objects.size();for(const auto& o:objects){if(o.staticProof)++s.staticObjects;if(o.dynamicOnly)++s.dynamicOnlyObjects;if(o.pointerLike)++s.pointerLikeObjects;switch(o.kind){case RamObjectKind::ByteField:++s.byteFields;break;case RamObjectKind::WordField:++s.wordFields;break;case RamObjectKind::BoundedByteArray:case RamObjectKind::BoundedWordArray:++s.arrays;break;case RamObjectKind::RecordCandidate:++s.recordCandidates;break;case RamObjectKind::UnknownGroupedRegion:break;}}return s;}

} // namespace pacripper
