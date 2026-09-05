// Created by Jacob Hodgkins
#include "RomObjects.h"

#include <algorithm>
#include <map>
#include <sstream>
#include <tuple>

namespace pacripper {

std::string RomObjects::objectKindText(RomObjectKind kind) {
    switch(kind) {
        case RomObjectKind::ExactAccessCluster: return "exact ROM access cluster";
        case RomObjectKind::ByteLookupTable: return "byte lookup table";
        case RomObjectKind::WordPointerTable: return "word pointer table";
        case RomObjectKind::SequentialStream: return "sequential ROM stream";
        case RomObjectKind::RecordTable: return "fixed/count-based record table";
        case RomObjectKind::BoundedRegion: return "bounded ROM consumer region";
        case RomObjectKind::DynamicObservedRegion: return "dynamic observed ROM region";
    }
    return "ROM object";
}

RomObjectKind RomObjects::objectKindForConsumer(RomConsumerKind kind,bool dynamic) {
    if(dynamic) return RomObjectKind::DynamicObservedRegion;
    switch(kind) {
        case RomConsumerKind::Rst10ByteLookup: return RomObjectKind::ByteLookupTable;
        case RomConsumerKind::Rst18WordLookup: return RomObjectKind::WordPointerTable;
        case RomConsumerKind::CountedSequentialRead:
        case RomConsumerKind::BlockTransferRead: return RomObjectKind::RecordTable;
        case RomConsumerKind::SentinelSequentialRead:
        case RomConsumerKind::EncodedSentinelRead:
        case RomConsumerKind::DelimitedStreamRead: return RomObjectKind::SequentialStream;
        default: return RomObjectKind::ExactAccessCluster;
    }
}

std::size_t RomObjects::entrySizeForConsumer(RomConsumerKind kind) {
    if(kind==RomConsumerKind::Rst18WordLookup) return 2;
    if(kind==RomConsumerKind::Rst10ByteLookup) return 1;
    return 0;
}

bool RomObjects::isStrongPointeeObject(const RomObjectRecord& object) {
    if(object.dynamicOnly) return false;
    if(!(object.exactBoundary||object.boundedBoundary)) return false;
    return object.kind==RomObjectKind::SequentialStream ||
           object.kind==RomObjectKind::RecordTable ||
           object.kind==RomObjectKind::ByteLookupTable ||
           object.kind==RomObjectKind::WordPointerTable;
}

std::vector<RomObjectRecord> RomObjects::reconstruct(const std::vector<RomConsumerRecord>& consumers,
                                                     std::size_t romSize) {
    struct Seed {
        std::uint16_t start=0,end=0;
        RomObjectKind kind=RomObjectKind::ExactAccessCluster;
        bool exact=false,bounded=false,dynamic=false;
        std::size_t entrySize=0;
        std::string pointerRegister,indexRegister;
        std::set<std::size_t> consumerIndices;
        std::set<std::uint16_t> consumerPCs;
        std::string note;
    };
    std::vector<Seed> seeds;
    for(std::size_t i=0;i<consumers.size();++i) {
        const auto& c=consumers[i];
        if(c.start>=romSize||c.end<=c.start) continue;
        Seed s;s.start=c.start;s.end=static_cast<std::uint16_t>(std::min<std::size_t>(romSize,c.end));
        s.kind=objectKindForConsumer(c.kind,c.dynamic);s.exact=c.exact&&!c.dynamic;s.bounded=c.bounded&&!c.dynamic;s.dynamic=c.dynamic;if(s.bounded&&s.kind==RomObjectKind::ExactAccessCluster)s.kind=RomObjectKind::BoundedRegion;
        s.entrySize=entrySizeForConsumer(c.kind);s.pointerRegister=c.pointerRegister;s.indexRegister=c.indexRegister;
        s.consumerIndices.insert(i);s.consumerPCs.insert(c.pc);s.note=c.note;
        // A lone dynamic byte is an observation, not a defensible object boundary. Dynamic
        // bytes are grouped later only when the same PC observed a contiguous region.
        if(s.dynamic && s.end==static_cast<std::uint16_t>(s.start+1)) { seeds.push_back(s); continue; }
        seeds.push_back(s);
    }

    // Merge only compatible, touching ranges. Overlapping-but-different bases are retained
    // as separate objects so alternate table views remain representable.
    std::stable_sort(seeds.begin(),seeds.end(),[](const Seed& a,const Seed& b){
        return std::tie(a.dynamic,a.kind,a.pointerRegister,a.indexRegister,a.start,a.end) <
               std::tie(b.dynamic,b.kind,b.pointerRegister,b.indexRegister,b.start,b.end);
    });
    std::vector<Seed> merged;
    for(const auto& s:seeds) {
        bool combined=false;
        for(auto it=merged.rbegin();it!=merged.rend();++it) {
            Seed& m=*it;
            if(m.kind!=s.kind||m.dynamic!=s.dynamic||m.pointerRegister!=s.pointerRegister||m.indexRegister!=s.indexRegister) continue;
            if(m.entrySize!=s.entrySize) continue;
            if(m.start==s.start&&m.end==s.end) {
                m.exact=m.exact||s.exact;m.bounded=m.bounded||s.bounded;
                m.consumerIndices.insert(s.consumerIndices.begin(),s.consumerIndices.end());m.consumerPCs.insert(s.consumerPCs.begin(),s.consumerPCs.end());combined=true;break;
            }
            const bool tableKind=m.kind==RomObjectKind::ByteLookupTable||m.kind==RomObjectKind::WordPointerTable;
            const bool dynamicCluster=m.kind==RomObjectKind::DynamicObservedRegion;
            const bool boundedCluster=m.kind==RomObjectKind::BoundedRegion;
            if(boundedCluster && m.consumerPCs==s.consumerPCs && s.start<=m.end && m.start<=s.end) {
                m.start=std::min(m.start,s.start);m.end=std::max(m.end,s.end);m.exact=false;m.bounded=true;
                m.consumerIndices.insert(s.consumerIndices.begin(),s.consumerIndices.end());m.consumerPCs.insert(s.consumerPCs.begin(),s.consumerPCs.end());combined=true;break;
            }
            if((tableKind||dynamicCluster) && m.end==s.start) {
                // For lookup tables, only join touching slices produced by the same helper
                // PC set. This reconstructs a table slice while preserving overlapping
                // alternate bases as distinct objects.
                if(tableKind && m.consumerPCs!=s.consumerPCs) continue;
                m.end=s.end;m.exact=m.exact&&s.exact;m.bounded=m.bounded||s.bounded;
                m.consumerIndices.insert(s.consumerIndices.begin(),s.consumerIndices.end());m.consumerPCs.insert(s.consumerPCs.begin(),s.consumerPCs.end());combined=true;break;
            }
            if(m.start>s.end) break;
        }
        if(!combined) merged.push_back(s);
    }

    // Dynamic single-byte observations from the same PC can be combined into contiguous
    // observed regions; they remain explicitly dynamic-only and never become static proof.
    std::vector<Seed> second;
    std::map<std::uint16_t,std::vector<Seed>> dynByPc;
    for(const auto& s:merged) {
        if(s.dynamic&&s.consumerPCs.size()==1)dynByPc[*s.consumerPCs.begin()].push_back(s);
        else second.push_back(s);
    }
    for(auto& kv:dynByPc) {
        auto& v=kv.second;std::sort(v.begin(),v.end(),[](const Seed&a,const Seed&b){return a.start<b.start;});
        for(const auto& s:v) {
            if(!second.empty()) {
                Seed& p=second.back();
                if(p.dynamic&&p.consumerPCs==s.consumerPCs&&p.end==s.start) {
                    p.end=s.end;p.consumerIndices.insert(s.consumerIndices.begin(),s.consumerIndices.end());continue;
                }
            }
            second.push_back(s);
        }
    }

    std::vector<RomObjectRecord> out;
    for(const auto& s:second) {
        // Single exact byte reads are useful xrefs but are not promoted to object records
        // unless they are a lookup table slice or a grouped dynamic region.
        const std::size_t len=static_cast<std::size_t>(s.end-s.start);
        if(len<2 && s.kind==RomObjectKind::ExactAccessCluster && !s.dynamic) continue;
        RomObjectRecord o;o.id=out.size();o.start=s.start;o.end=s.end;o.kind=s.kind;o.exactBoundary=s.exact;o.boundedBoundary=s.bounded;o.dynamicOnly=s.dynamic;
        o.entrySize=s.entrySize;if(o.entrySize&&len%o.entrySize==0)o.entryCount=len/o.entrySize;
        o.consumerIndices=s.consumerIndices;o.consumerPCs=s.consumerPCs;
        std::ostringstream note;note<<objectKindText(o.kind)<<" reconstructed from "<<o.consumerIndices.size()<<" compatible consumer record(s)";
        if(o.exactBoundary)note<<"; exact static extent";else if(o.boundedBoundary)note<<"; bounded static extent";else if(o.dynamicOnly)note<<"; dynamic-only extent";
        o.note=note.str();out.push_back(o);
    }

    // Preserve overlap relationships explicitly instead of flattening dual-use/table views.
    for(std::size_t i=0;i<out.size();++i)for(std::size_t j=i+1;j<out.size();++j) {
        if(out[i].start<out[j].end&&out[j].start<out[i].end) {
            out[i].overlappingObjectIds.insert(out[j].id);out[j].overlappingObjectIds.insert(out[i].id);
        }
    }
    return out;
}

std::vector<RomPointerLinkRecord> RomObjects::decodePointerLinks(const std::vector<RomObjectRecord>& objects,
                                                                 const std::vector<std::uint8_t>& program) {
    std::vector<RomPointerLinkRecord> out;
    for(const auto& table:objects) {
        if(table.kind!=RomObjectKind::WordPointerTable||table.entrySize!=2||table.end<=table.start) continue;
        std::size_t idx=0;
        for(std::size_t a=table.start;a+1<table.end&&a+1<program.size();a+=2,++idx) {
            const std::uint16_t target=static_cast<std::uint16_t>(program[a]|(static_cast<std::uint16_t>(program[a+1])<<8));
            if(target>=program.size()) continue;
            RomPointerLinkRecord link;link.tableObjectId=table.id;link.tableEntryIndex=idx;link.entryAddress=static_cast<std::uint16_t>(a);link.target=target;
            for(const auto& object:objects) if(object.start==target) link.targetObjectIds.insert(object.id);
            // If multiple overlapping objects begin at the target, choose the strongest/smallest
            // reproducible extent for the summary while retaining all object IDs.
            const RomObjectRecord* best=nullptr;
            for(auto oid:link.targetObjectIds) {
                if(oid>=objects.size()) continue;
                const auto& object=objects[oid];
                if(!isStrongPointeeObject(object)) continue;
                if(!best || (object.exactBoundary&&!best->exactBoundary) ||
                   (object.exactBoundary==best->exactBoundary && (object.end-object.start)<(best->end-best->start))) best=&object;
            }
            if(best) {link.pointeeExtentProven=true;link.pointeeStart=best->start;link.pointeeEnd=best->end;}
            std::ostringstream n;n<<"little-endian word table entry points to ROM $"<<std::hex<<std::uppercase<<target;
            if(link.pointeeExtentProven)n<<"; consumer-backed pointee extent linked";
            else if(!link.targetObjectIds.empty())n<<"; target object exists but extent is not strong enough for pointee proof";
            else n<<"; no consumer-backed pointee extent yet";
            link.note=n.str();out.push_back(link);
        }
    }
    return out;
}

std::vector<UnresolvedPrioritySpan> RomObjects::prioritizeUnresolved(const std::vector<RomByteClosureRecord>& closure,
                                                                     const std::vector<RomObjectRecord>& objects,
                                                                     std::size_t maxSpans) {
    std::vector<UnresolvedPrioritySpan> spans;
    std::size_t i=0;
    while(i<closure.size()) {
        if(closure[i].primary!=RomClosurePrimary::Unresolved){++i;continue;}
        const std::size_t start=i;while(i<closure.size()&&closure[i].primary==RomClosurePrimary::Unresolved)++i;const std::size_t end=i;
        UnresolvedPrioritySpan s;s.start=static_cast<std::uint16_t>(start);s.end=static_cast<std::uint16_t>(end);s.length=end-start;
        const std::size_t lo=start>16?start-16:0,hi=std::min<std::size_t>(closure.size(),end+16);
        for(const auto& o:objects)if(o.start<hi&&o.end>lo)++s.nearbyObjectCount;
        std::set<std::uint16_t> pcs;
        for(std::size_t a=lo;a<hi;++a){if(closure[a].pointerTarget)++s.nearbyPointerTargetCount;pcs.insert(closure[a].consumerPCs.begin(),closure[a].consumerPCs.end());}
        s.nearbyConsumerCount=pcs.size();
        std::ostringstream r;r<<"unresolved span adjacent to "<<s.nearbyObjectCount<<" reconstructed object(s), "<<s.nearbyPointerTargetCount<<" pointer target byte(s), and "<<s.nearbyConsumerCount<<" consumer PC(s) within 16 bytes";s.reason=r.str();
        spans.push_back(s);
    }
    std::stable_sort(spans.begin(),spans.end(),[](const UnresolvedPrioritySpan&a,const UnresolvedPrioritySpan&b){
        const std::size_t scoreA=a.length*16+a.nearbyObjectCount*8+a.nearbyPointerTargetCount*4+a.nearbyConsumerCount;
        const std::size_t scoreB=b.length*16+b.nearbyObjectCount*8+b.nearbyPointerTargetCount*4+b.nearbyConsumerCount;
        if(scoreA!=scoreB) return scoreA>scoreB;
        return a.start<b.start;
    });
    if(spans.size()>maxSpans)spans.resize(maxSpans);
    return spans;
}

} // namespace pacripper
