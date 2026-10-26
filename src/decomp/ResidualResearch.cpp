// PacRipper residual-closure analysis residual ROM closure audit and proof helpers
// Created by Jacob Hodgkins

#include "ResidualResearch.h"

#include <algorithm>
#include <map>
#include <queue>
#include <sstream>
#include <tuple>

namespace pacripper {
namespace {
bool intersects(std::uint16_t a0,std::uint16_t a1,std::uint16_t b0,std::uint16_t b1){return a0<b1&&b0<a1;}
bool touchesOrNear(std::uint16_t a0,std::uint16_t a1,std::uint16_t b0,std::uint16_t b1,unsigned distance=4){
    if(intersects(a0,a1,b0,b1))return true;
    const unsigned aa0=a0,aa1=a1,bb0=b0,bb1=b1;
    return aa1<=bb0 ? bb0-aa1<=distance : aa0>=bb1 ? aa0-bb1<=distance : true;
}
bool repeatedPattern(const std::vector<std::uint8_t>& p,std::size_t start,std::size_t end){
    if(end<=start||end-start<8||end>p.size())return false;
    for(std::size_t period=1;period<=4;++period){bool same=true;for(std::size_t i=start+period;i<end;++i)if(p[i]!=p[start+(i-start)%period]){same=false;break;}if(same)return true;}
    return false;
}
bool isResidual(const RomByteClosureRecord& b){return b.primary==RomClosurePrimary::Unresolved;}
bool hardConflict(const std::vector<RomByteClosureRecord>& c,std::uint16_t start,std::uint16_t end){for(std::size_t a=start;a<end&&a<c.size();++a)if(c[a].hardData)return true;return false;}
bool otherObjectConflict(const std::vector<RomObjectRecord>& objects,std::size_t id,std::uint16_t start,std::uint16_t end){for(const auto&o:objects)if(o.id!=id&&intersects(start,end,o.start,o.end))return true;return false;}
bool compatibleConsumerForExtent(const RomObjectRecord&o,const RomConsumerRecord&c){
    if(c.dynamic)return false;
    if(!intersects(o.start,o.end,c.start,c.end)&&c.start!=o.end&&c.end!=o.start)return false;
    if(o.consumerPCs.count(c.pc))return true;
    switch(o.kind){
        case RomObjectKind::ByteLookupTable:return c.kind==RomConsumerKind::Rst10ByteLookup||c.kind==RomConsumerKind::IndexedRegisterRead;
        case RomObjectKind::WordPointerTable:return c.kind==RomConsumerKind::Rst18WordLookup;
        case RomObjectKind::SequentialStream:return c.kind==RomConsumerKind::SentinelSequentialRead||c.kind==RomConsumerKind::EncodedSentinelRead||c.kind==RomConsumerKind::DelimitedStreamRead;
        case RomObjectKind::RecordTable:return c.kind==RomConsumerKind::CountedSequentialRead||c.kind==RomConsumerKind::BlockTransferRead;
        default:return c.exact||c.bounded;
    }
}
RomExtentProofKind proofFor(const RomConsumerRecord&c){
    if(c.kind==RomConsumerKind::CountedSequentialRead||c.kind==RomConsumerKind::BlockTransferRead)return RomExtentProofKind::CountedConsumer;
    if(c.kind==RomConsumerKind::SentinelSequentialRead||c.kind==RomConsumerKind::EncodedSentinelRead||c.kind==RomConsumerKind::DelimitedStreamRead)return RomExtentProofKind::SentinelConsumer;
    return RomExtentProofKind::BoundedConsumer;
}
}

std::string ResidualResearch::auditReasonText(ResidualAuditReason r){switch(r){case ResidualAuditReason::NoKnownConsumer:return"no-known-consumer";case ResidualAuditReason::PointerTargetUnconsumed:return"pointer-target-unconsumed";case ResidualAuditReason::BoundedConsumerOverlap:return"bounded-consumer-overlap";case ResidualAuditReason::DynamicOnlyRomObservation:return"dynamic-only-rom-observation";case ResidualAuditReason::DormantCodeCandidate:return"possible-dormant-code";case ResidualAuditReason::FillerRepetitionCandidate:return"filler/repetition/alignment-candidate";case ResidualAuditReason::KnownObjectExtentUnproven:return"known-object-extent-unproven";case ResidualAuditReason::ConflictingInterpretations:return"conflicting-candidate-interpretations";}return"unknown";}
std::string ResidualResearch::seedKindText(DormantCodeSeedKind k){switch(k){case DormantCodeSeedKind::StaticCodePointer:return"static-code-pointer";case DormantCodeSeedKind::PointerTableCodeUse:return"code-use-pointer-table-entry";case DormantCodeSeedKind::ExistingControlTarget:return"existing-control-target";case DormantCodeSeedKind::TraceObservedPc:return"trace-observed-pc";}return"unknown";}
std::string ResidualResearch::extentProofText(RomExtentProofKind k){switch(k){case RomExtentProofKind::BoundedConsumer:return"bounded-consumer";case RomExtentProofKind::CountedConsumer:return"counted-consumer";case RomExtentProofKind::SentinelConsumer:return"sentinel/delimited-consumer";case RomExtentProofKind::ExactSchema:return"exact-finite-schema";case RomExtentProofKind::RepeatedExactConsumers:return"repeated-exact-consumers";}return"unknown";}

std::vector<DormantCodeDiscoveryRecord> ResidualResearch::discoverDormantCode(const std::vector<std::uint8_t>& program,const std::vector<RomByteClosureRecord>& closure,const std::vector<DormantCodeSeedRecord>& seeds){
    std::vector<DormantCodeDiscoveryRecord> out;Z80Disassembler dis;
    for(const auto&s:seeds){DormantCodeDiscoveryRecord r;r.id=out.size();r.seedId=s.id;r.entry=s.address;r.seedKind=s.kind;r.staticProof=s.staticProof;r.dynamicOnly=s.dynamicOnly;r.provenancePCs=s.sourcePCs;
        if(s.address>=program.size()){r.note="seed outside loaded ROM";out.push_back(r);continue;}
        if(!s.staticProof){r.note=s.dynamicOnly?"trace-only entry is retained as dynamic candidate; it cannot create static code proof":"entry seed lacks static proof";out.push_back(r);continue;}
        std::queue<std::uint16_t> q;std::set<std::uint16_t> seen;q.push(s.address);bool invalid=false;std::size_t guard=0;
        while(!q.empty()&&guard++<4096){const auto pc=q.front();q.pop();if(seen.count(pc))continue;seen.insert(pc);if(pc>=program.size()){invalid=true;break;}if(pc<closure.size()&&closure[pc].code){r.reachesKnownCode=true;continue;}
            const auto in=dis.decode(program,pc);if(in.bytes.empty()||in.mnemonic=="DB"||static_cast<std::size_t>(pc)+in.length()>program.size()){invalid=true;break;}
            const auto end=static_cast<std::uint16_t>(static_cast<std::size_t>(pc)+in.length());if(hardConflict(closure,pc,end)){r.hardDataConflict=true;invalid=true;break;}
            r.instructionPCs.insert(pc);for(std::size_t a=pc;a<static_cast<std::size_t>(pc)+in.length();++a)r.byteAddresses.insert(static_cast<std::uint16_t>(a));
            const auto next=static_cast<std::uint32_t>(pc)+in.length();auto push=[&](int target){if(target>=0&&static_cast<std::size_t>(target)<program.size())q.push(static_cast<std::uint16_t>(target));};
            if(in.indirect){r.indirectExit=true;continue;}
            switch(in.flow){case FlowKind::Return:case FlowKind::Halt:break;case FlowKind::Jump:case FlowKind::RelativeJump:push(in.target);if(in.conditional&&next<program.size())q.push(static_cast<std::uint16_t>(next));break;case FlowKind::Call:push(in.target);if(next<program.size())q.push(static_cast<std::uint16_t>(next));break;case FlowKind::Restart:push(in.target);if(next<program.size())q.push(static_cast<std::uint16_t>(next));break;case FlowKind::Normal:if(next<program.size())q.push(static_cast<std::uint16_t>(next));break;}
        }
        if(guard>=4096){invalid=true;r.note="seed traversal exceeded conservative instruction cap";}
        if(!invalid&&!r.instructionPCs.empty()){r.accepted=true;r.note="accepted from static entry seed; every decoded byte is retained with seed provenance and no hard-data overlap";}else if(r.note.empty())r.note=r.hardDataConflict?"rejected because a seeded path overlaps hard-typed data":"seed did not establish a finite conflict-free code region";
        out.push_back(r);
    }
    return out;
}

std::vector<RomExtentRefinementRecord> ResidualResearch::refineObjectExtents(const std::vector<RomObjectRecord>& objects,const std::vector<RomConsumerRecord>& consumers,const std::vector<TableSchemaRecord>& schemas,const std::vector<RomByteClosureRecord>& closure){
    std::vector<RomExtentRefinementRecord> out;
    auto emit=[&](const RomObjectRecord&o,std::uint16_t ns,std::uint16_t ne,RomExtentProofKind kind,bool exact,bool bounded,const std::set<std::uint16_t>&pcs,const std::set<std::size_t>&schemaIds,const std::string&note){
        if(ns>=o.start&&ne<=o.end)return;
        if(ne<=ns||ne>closure.size())return;
        // Check only bytes newly added outside the existing object.  A proof that grows
        // both sides must not reject itself merely because the already-known interior is
        // hard-typed data or overlaps the object being refined.
        const std::uint16_t leftStart=ns<o.start?ns:o.start;
        const std::uint16_t leftEnd=o.start;
        const std::uint16_t rightStart=o.end;
        const std::uint16_t rightEnd=ne>o.end?ne:o.end;
        const auto conflicts=[&](std::uint16_t a,std::uint16_t b){return b>a&&(hardConflict(closure,a,b)||otherObjectConflict(objects,o.id,a,b));};
        if(conflicts(leftStart,leftEnd)||conflicts(rightStart,rightEnd))return;
        RomExtentRefinementRecord r;r.id=out.size();r.objectId=o.id;r.oldStart=o.start;r.oldEnd=o.end;r.newStart=std::min(o.start,ns);r.newEnd=std::max(o.end,ne);r.proofKind=kind;r.exactClosure=exact;r.boundedClosure=bounded;r.accepted=true;r.sourcePCs=pcs;r.schemaIds=schemaIds;r.note=note;out.push_back(r);
    };
    for(const auto&o:objects){if(o.dynamicOnly)continue;
        for(const auto&s:schemas)if(s.targetKind==SchemaTargetKind::RomObject&&s.targetId==o.id&&s.staticProof&&s.exactBounds&&(s.start<o.start||s.end>o.end)){std::set<std::size_t> ids={s.id};emit(o,s.start,s.end,RomExtentProofKind::ExactSchema,true,false,s.sourcePCs,ids,"finite type/contract analysis schema proves the enlarged ROM object extent");}
        std::map<std::pair<std::uint16_t,std::uint16_t>,std::set<std::uint16_t>> exactAgreement;
        for(const auto&c:consumers){if(!compatibleConsumerForExtent(o,c))continue;if(c.exact&&!c.dynamic)exactAgreement[{c.start,c.end}].insert(c.pc);if(c.start>=o.start&&c.end<=o.end)continue;if(!(c.exact||c.bounded))continue;std::set<std::uint16_t> pcs={c.pc};const auto k=proofFor(c);const bool exact=c.exact&&(k==RomExtentProofKind::CountedConsumer||k==RomExtentProofKind::SentinelConsumer);emit(o,c.start,c.end,k,exact,!exact,pcs,{},"consumer bound/termination proof extends this object only to its proven range");}
        for(const auto&g:exactAgreement)if(g.second.size()>=2&&(g.first.first<o.start||g.first.second>o.end))emit(o,g.first.first,g.first.second,RomExtentProofKind::RepeatedExactConsumers,true,false,g.second,{},"multiple independent exact consumers agree on the same enlarged finite range");
    }
    // Coalesce exact duplicate proposals while preserving all provenance.
    std::vector<RomExtentRefinementRecord> merged;for(const auto&r:out){bool done=false;for(auto&m:merged)if(m.objectId==r.objectId&&m.newStart==r.newStart&&m.newEnd==r.newEnd&&m.proofKind==r.proofKind){m.sourcePCs.insert(r.sourcePCs.begin(),r.sourcePCs.end());m.schemaIds.insert(r.schemaIds.begin(),r.schemaIds.end());m.exactClosure=m.exactClosure||r.exactClosure;m.boundedClosure=m.boundedClosure||r.boundedClosure;done=true;break;}if(!done){auto x=r;x.id=merged.size();merged.push_back(x);}}return merged;
}

std::vector<ResidualAuditRecord> ResidualResearch::auditResidualSpans(const std::vector<RomByteClosureRecord>& closure,const std::vector<RomObjectRecord>& objects,const std::vector<RomConsumerRecord>& consumers,const std::vector<DormantCodeSeedRecord>& seeds,const std::vector<std::uint8_t>& program){
    std::vector<ResidualAuditRecord> out;std::size_t i=0;while(i<closure.size()){if(!isResidual(closure[i])){++i;continue;}std::size_t j=i+1;while(j<closure.size()&&isResidual(closure[j]))++j;ResidualAuditRecord r;r.id=out.size();r.start=static_cast<std::uint16_t>(i);r.end=static_cast<std::uint16_t>(j);r.length=j-i;
        for(const auto&o:objects)if(touchesOrNear(r.start,r.end,o.start,o.end)){r.nearbyObjectIds.insert(o.id);if(o.end==r.start||o.start==r.end)r.reasons.insert(ResidualAuditReason::KnownObjectExtentUnproven);}
        std::size_t bounded=0,dynamic=0,overlappingConsumers=0;for(const auto&c:consumers)if(touchesOrNear(r.start,r.end,c.start,c.end)){r.nearbyConsumerPCs.insert(c.pc);if(intersects(r.start,r.end,c.start,c.end)){++overlappingConsumers;if(c.bounded&&!c.dynamic)++bounded;if(c.dynamic)++dynamic;}}
        if(bounded){r.reasons.insert(ResidualAuditReason::BoundedConsumerOverlap);r.staticEvidence=true;}if(dynamic){r.reasons.insert(ResidualAuditReason::DynamicOnlyRomObservation);r.dynamicEvidence=true;}
        for(const auto&s:seeds)if(s.address>=r.start&&s.address<r.end){r.dormantSeedIds.insert(s.id);r.reasons.insert(ResidualAuditReason::DormantCodeCandidate);r.staticEvidence=r.staticEvidence||s.staticProof;r.dynamicEvidence=r.dynamicEvidence||s.dynamicOnly;}
        bool pointerInside=false;for(std::size_t a=i;a<j;++a)if(closure[a].pointerTarget){pointerInside=true;break;}if(pointerInside){r.reasons.insert(ResidualAuditReason::PointerTargetUnconsumed);r.staticEvidence=true;}
        if(repeatedPattern(program,i,j)){r.repetitionCandidate=true;r.reasons.insert(ResidualAuditReason::FillerRepetitionCandidate);}
        if(r.nearbyObjectIds.size()>1||(closure[i].candidate&&pointerInside))r.reasons.insert(ResidualAuditReason::ConflictingInterpretations);
        if(overlappingConsumers==0&&!pointerInside&&r.dormantSeedIds.empty())r.reasons.insert(ResidualAuditReason::NoKnownConsumer);
        if(r.reasons.empty())r.reasons.insert(ResidualAuditReason::NoKnownConsumer);
        std::ostringstream n;n<<"unresolved bytes retain audit-only classifications; none of these reasons closes the span";if(r.repetitionCandidate)n<<"; repetition is heuristic only";r.note=n.str();out.push_back(r);i=j;}
    return out;
}

std::vector<ResidualPriorityV2Record> ResidualResearch::prioritizeV2(const std::vector<ResidualAuditRecord>& audit,const std::vector<RomByteClosureRecord>& closure,const std::vector<RomConsumerRecord>& consumers,std::size_t maxSpans){
    std::vector<ResidualPriorityV2Record> out;for(const auto&a:audit){ResidualPriorityV2Record r;r.auditId=a.id;r.start=a.start;r.end=a.end;r.length=a.length;r.codeSeedEvidence=a.dormantSeedIds.size();r.objectBoundaryProximity=a.nearbyObjectIds.size();r.dynamicObservation=a.dynamicEvidence?1:0;r.conflictPenalty=a.reasons.count(ResidualAuditReason::ConflictingInterpretations)?1:0;
        const std::size_t lo=a.start>8?a.start-8:0,hi=std::min<std::size_t>(closure.size(),static_cast<std::size_t>(a.end)+8);for(std::size_t x=lo;x<hi;++x)if(closure[x].pointerTarget)++r.pointerProximity;
        std::map<std::uint16_t,std::size_t> perPc;for(const auto&c:consumers)if(touchesOrNear(a.start,a.end,c.start,c.end,8))++perPc[c.pc];for(const auto&p:perPc)if(p.second>1)++r.repeatedConsumers;r.routineRelevance=a.nearbyConsumerPCs.size();
        r.score=static_cast<int>(100*r.codeSeedEvidence+20*r.pointerProximity+12*r.objectBoundaryProximity+18*r.repeatedConsumers+4*r.routineRelevance+3*r.dynamicObservation-35*r.conflictPenalty);if(a.repetitionCandidate)r.score-=8;
        std::ostringstream s;s<<"research-order score only: seed="<<r.codeSeedEvidence<<" pointer="<<r.pointerProximity<<" object="<<r.objectBoundaryProximity<<" repeated="<<r.repeatedConsumers<<" routine="<<r.routineRelevance<<" dynamic="<<r.dynamicObservation<<" conflict="<<r.conflictPenalty;r.reason=s.str();out.push_back(r);}
    std::stable_sort(out.begin(),out.end(),[](const auto&a,const auto&b){if(a.score!=b.score)return a.score>b.score;if(a.length!=b.length)return a.length>b.length;return a.start<b.start;});if(out.size()>maxSpans)out.resize(maxSpans);return out;
}

ResidualResearchStats ResidualResearch::stats(const std::vector<ResidualAuditRecord>& audit,const std::vector<DormantCodeSeedRecord>& seeds,const std::vector<DormantCodeDiscoveryRecord>& discoveries,const std::vector<RomExtentRefinementRecord>& extents,const std::vector<ResidualPriorityV2Record>& priority){ResidualResearchStats s;s.auditSpans=audit.size();for(const auto&a:audit){s.auditedUnresolvedBytes+=a.length;if(a.reasons.count(ResidualAuditReason::NoKnownConsumer))++s.noKnownConsumerSpans;}s.dormantSeeds=seeds.size();for(const auto&d:discoveries){if(d.accepted){++s.acceptedDormantDiscoveries;s.dormantCodeBytes+=d.byteAddresses.size();}if(d.hardDataConflict)++s.rejectedHardDataOverlaps;}for(const auto&e:extents)if(e.accepted){++s.extentRefinements;if(e.exactClosure)++s.exactExtentRefinements;if(e.boundedClosure)++s.boundedExtentRefinements;}s.priorityRecords=priority.size();return s;}

} // namespace pacripper
