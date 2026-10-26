// PacRipper residual-extent analysis residual extent / exhaustive unused-region closure
// Created by Jacob Hodgkins

#include "Decompiler.h"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <map>
#include <sstream>

namespace pacripper {
namespace {
std::string h24(std::uint16_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(4)<<std::setfill('0')<<(unsigned)v;return o.str();}
template<class T>std::string ids24(const std::set<T>&s,const char*p=""){std::ostringstream o;o<<"{";std::size_t n=0;for(auto v:s){if(n++)o<<",";o<<p<<v;}o<<"}";return o.str();}
std::string pcs24(const std::set<std::uint16_t>&s){std::ostringstream o;o<<"{";std::size_t n=0;for(auto v:s){if(n++)o<<",";o<<"$"<<h24(v);}o<<"}";return o.str();}
bool staticIndependent24(const Analyzer* a,std::uint16_t pc){return a&&a->hasStaticInstructionProof(pc)&&!a->isTraceDiscoveredInstruction(pc);}
std::set<std::uint16_t> operandHexWords24(const std::string& text){
    std::set<std::uint16_t> out;
    for(std::size_t p=0;p+5<=text.size();++p){
        if(text[p]!='$')continue;
        unsigned v=0;bool ok=true;
        for(std::size_t i=1;i<=4;++i){const char c=text[p+i];unsigned d=0;if(c>='0'&&c<='9')d=c-'0';else if(c>='A'&&c<='F')d=10+c-'A';else if(c>='a'&&c<='f')d=10+c-'a';else{ok=false;break;}v=(v<<4)|d;}
        if(ok&&(p+5==text.size()||!std::isxdigit(static_cast<unsigned char>(text[p+5]))))out.insert(static_cast<std::uint16_t>(v));
    }
    return out;
}
std::set<std::uint16_t> unresolvedInWindow24(const std::vector<RomByteClosureRecord>& baseline,std::uint16_t start,std::uint16_t end){
    std::set<std::uint16_t> out;for(std::uint32_t a=start;a<end&&a<baseline.size();++a)if(baseline[a].primary==RomClosurePrimary::Unresolved)out.insert(static_cast<std::uint16_t>(a));return out;
}
bool setOverlaps24(const std::set<std::uint16_t>& s,std::uint16_t start,std::uint16_t end){return ResidualExtentAnalysis::addressSetIntersects(s,start,end);}
}

void Decompiler::buildResidualExtent(){
    residualExtentResidualAudit_.clear();residualExtentExtentProofs_.clear();residualExtentNegativeReferenceProofs_.clear();residualExtentUnusedRegions_.clear();residualExtentClosureProvenance_.clear();residualExtentFinalResidual_.clear();residualExtentClosureBytes_.clear();stats_.residualExtent={};
    if(!analyzer_)return;
    const auto& program=analyzer_->program();
    const auto& baseline=!intermissionClosureBytes_.empty()?intermissionClosureBytes_:mazeTopologyClosureBytes_;
    residualExtentClosureBytes_=baseline;

    // Rebuild the residual from the verified intermission analysis byte map; no inherited span
    // list is trusted as the canonical current shape.
    std::vector<std::pair<std::uint16_t,std::uint16_t>> spans;
    for(std::size_t i=0;i<baseline.size();){
        if(baseline[i].primary!=RomClosurePrimary::Unresolved){++i;continue;}
        const std::size_t start=i;while(i<baseline.size()&&baseline[i].primary==RomClosurePrimary::Unresolved)++i;
        spans.push_back({static_cast<std::uint16_t>(start),static_cast<std::uint16_t>(i)});
    }

    // Final caller-complete read domains. context-sensitive root analysis inventories the rooted read
    // universe; Passes 20/21/22/23 replace only the blocker PCs they refine.
    std::map<std::uint16_t,AddressLatticeValue> finalReadDomains;
    std::map<std::uint16_t,AddressLatticeValue> checksumDomains;
    std::set<std::uint16_t> remainingReadBlockers;
    // Do not reconstruct the context-sensitive root analysis blocker set from every rejected address
    // proof.  context-sensitive root analysis's negative-evidence records are the canonical
    // lineage: they contain only the inherited/newly-rooted PCs that actually
    // remained blockers after the context-sensitive root analysis fixed point.  This distinction is
    // essential because many rejected proofs are intentionally non-blocking.
    for(const auto&n:rootContextNegativeReferenceEvidence_){
        remainingReadBlockers.insert(n.remainingInheritedBlockerPCs.begin(),n.remainingInheritedBlockerPCs.end());
        remainingReadBlockers.insert(n.remainingNewlyRootedBlockerPCs.begin(),n.remainingNewlyRootedBlockerPCs.end());
    }
    for(const auto&p:rootContextAddressProofs_){
        if(p.accepted&&p.callerComplete&&!p.contextOverflow&&p.aggregateAddress.staticProof&&!p.aggregateAddress.dynamicOnly&&!p.aggregateAddress.hasUnknownAlternative&&p.domainClass!=RootContextDomainClass::Unresolved)
            finalReadDomains[p.pc]=p.aggregateAddress;
    }
    for(const auto&p:memoryAliasAddressProofs_)if(p.accepted){remainingReadBlockers.erase(p.pc);if(p.kind==MemoryAliasProofKind::SelfTestChecksum)checksumDomains[p.pc]=p.address;else finalReadDomains[p.pc]=p.address;}
    for(const auto&p:commandStreamAddressProofs_)if(p.accepted){remainingReadBlockers.erase(p.pc);finalReadDomains[p.pc]=p.address;}
    for(const auto&p:mazeTopologyAddressProofs_)if(p.accepted){remainingReadBlockers.erase(p.pc);finalReadDomains[p.pc]=p.address;}
    for(const auto&p:intermissionAddressProofs_)if(p.accepted){remainingReadBlockers.erase(p.pc);finalReadDomains[p.pc]=p.address;}

    // Correction/reconciliation: $2C5E indexes its RST-$18 pointer table with
    // the queued B parameter before any low/high-B branch.  The task-$1C
    // producer at $0587 does not currently have an exhaustive static value
    // domain for that parameter.  Therefore every sparse pointer domain owned
    // by this consumer is globally incomplete for *negative* ROM-reference
    // reasoning: omitted selector values cannot be inverted into absence.
    std::set<std::size_t> globallyIncompletePointerDomainIds;
    for(const auto&pd:pointerTableDomains_){
        if(!pd.staticProof||pd.indices.empty())continue;
        const auto di=std::find_if(romDecoders_.begin(),romDecoders_.end(),[&](const RomDecoderRecord&d){return d.id==pd.decoderId;});
        if(di!=romDecoders_.end()&&di->routine==0x2C5E)globallyIncompletePointerDomainIds.insert(pd.id);
    }

    const bool callerComplete=stats_.rootContext.callerInventoryComplete&&stats_.rootContext.contextOverflowPCs==0&&stats_.rootContext.guardTrips==0;
    const bool indirectControlComplete=stats_.rootContext.unresolvedIndirectControlPCs==0;
    const bool allConsumersBounded=callerComplete&&indirectControlComplete&&remainingReadBlockers.empty()&&stats_.intermission.remainingBlockers==0;

    // Residual inventory v2: attach direct/static mechanisms plus the semantic
    // object neighborhood, but do not treat mere proximity as ownership.
    for(const auto&sp:spans){
        ResidualExtentResidualAuditRecord r;r.id=residualExtentResidualAudit_.size();r.start=sp.first;r.end=sp.second;r.length=static_cast<std::size_t>(r.end-r.start);
        r.leftRomBoundary=r.start==0;r.rightRomBoundary=r.end==program.size();
        if(r.start>0)r.leftBoundaryProven=baseline[r.start-1].primary!=RomClosurePrimary::Unresolved;
        if(r.end<baseline.size())r.rightBoundaryProven=baseline[r.end].primary!=RomClosurePrimary::Unresolved;
        r.guard330d330e=ResidualExtentAnalysis::intersects(r.start,r.end,0x330D,0x330F);
        r.guard3ffe3fff=ResidualExtentAnalysis::intersects(r.start,r.end,0x3FFE,0x4000);
        for(const auto&old:mazeTopologyResidualClassification_)if(ResidualExtentAnalysis::intersects(r.start,r.end,old.start,old.end)){r.inheritedKind=old.kind;break;}

        for(const auto&kv:analyzer_->instructions()){
            const auto&in=kv.second;if(!staticIndependent24(analyzer_,in.address))continue;
            for(const auto&m:in.memoryRefs)if(m.address>=r.start&&m.address<r.end)r.directMemoryRefPCs.insert(in.address);
            if(in.target>=0&&static_cast<unsigned>(in.target)>=r.start&&static_cast<unsigned>(in.target)<r.end)r.controlTargetPCs.insert(in.address);
            for(auto v:operandHexWords24(in.operands))if(v>=r.start&&v<r.end)r.immediateAddressPCs.insert(in.address);
        }
        for(const auto&kv:finalReadDomains)if(ResidualReferenceAnalysis::addressValueIntersects(kv.second,r.start,r.end))r.finiteIndirectPCs.insert(kv.first);
        for(const auto&kv:checksumDomains)if(ResidualReferenceAnalysis::addressValueIntersects(kv.second,r.start,r.end))r.checksumSelfTestPCs.insert(kv.first);
        r.unresolvedReadPCs=remainingReadBlockers;

        for(const auto&s:systemRomSemantics_)if(s.staticProof&&ResidualExtentAnalysis::intersects(r.start,r.end,s.start,s.end))r.systemSemanticIds.insert(s.id);
        for(const auto&s:streamSemantics_)if(s.accepted&&s.staticProof&&setOverlaps24(s.coveredAddresses,r.start,r.end))r.streamIds.insert(s.id);
        for(const auto&f:fixedRecordSemantics_)if(f.staticProof&&setOverlaps24(f.coveredAddresses,r.start,r.end))r.fixedRecordIds.insert(f.id);
        for(const auto&b:boundedBlockSemantics_)if(b.staticProof&&setOverlaps24(b.coveredAddresses,r.start,r.end))r.boundedBlockIds.insert(b.id);
        for(const auto&o:residualReferenceSemanticOverlaps_)if(ResidualExtentAnalysis::intersects(r.start,r.end,o.start,o.end))r.overlapIds.insert(o.id);
        for(std::size_t i=0;i<romPointerLinks_.size();++i){const auto&l=romPointerLinks_[i];if((l.target>=r.start&&l.target<r.end)||(l.pointeeExtentProven&&ResidualExtentAnalysis::intersects(r.start,r.end,l.pointeeStart,l.pointeeEnd)))r.pointerLinkIds.insert(i);}
        for(const auto&a:highRomResidualAudit_)if(ResidualExtentAnalysis::intersects(r.start,r.end,a.start,a.end)){r.decoderIds.insert(a.nearbyDecoderIds.begin(),a.nearbyDecoderIds.end());r.pointerDomainIds.insert(a.nearbyTableDomainIds.begin(),a.nearbyTableDomainIds.end());}

        bool provenPointerOverlap=false;for(auto id:r.pointerLinkIds){const auto&l=romPointerLinks_[id];if(l.pointeeExtentProven&&ResidualExtentAnalysis::intersects(r.start,r.end,l.pointeeStart,l.pointeeEnd))provenPointerOverlap=true;}
        r.allConsumersBounded=allConsumersBounded;
        r.positiveSemanticReference=!r.directMemoryRefPCs.empty()||!r.immediateAddressPCs.empty()||!r.controlTargetPCs.empty()||!r.finiteIndirectPCs.empty()||!r.systemSemanticIds.empty()||!r.streamIds.empty()||!r.fixedRecordIds.empty()||!r.boundedBlockIds.empty()||provenPointerOverlap;
        r.negativeClosureEligible=r.allConsumersBounded&&!r.positiveSemanticReference&&!r.guard3ffe3fff&&globallyIncompletePointerDomainIds.empty();
        std::ostringstream note;note<<"residual-extent analysis rebuilt this span from the intermission analysis byte map. Final rooted-read blockers="<<r.unresolvedReadPCs.size()<<", finite semantic hits="<<r.finiteIndirectPCs.size()<<", direct/literal/control="<<r.directMemoryRefPCs.size()<<"/"<<r.immediateAddressPCs.size()<<"/"<<r.controlTargetPCs.size()<<". ";
        if(r.guard330d330e)note<<"Named $330D-$330E all-consumer guard: intermission analysis retry exclusion is not reused as global absence. ";
        if(r.guard3ffe3fff)note<<"Named $3FFE-$3FFF final-system-tail guard remains ineligible for negative closure. ";
        note<<"Checksum/self-test domains are inventoried separately and are not semantic ownership.";r.note=note.str();
        residualExtentResidualAudit_.push_back(r);
    }

    // Extent proofs. These records prove what the established decoders
    // actually own; residual bytes inside the research windows remain merely
    // excluded until the independent all-consumer negative proof also succeeds.
    //
    // Reconciliation rule: the $2C5E selector source is not exhaustively
    // bounded.  Because RST $18 consumes B *before* the routine branches, the
    // pointer-entry address can span all 256 byte-selector values.  Record that
    // full potential table envelope, but do not promote omitted entries or
    // their targets as accepted objects and do not use them as negative proof.
    for(const auto&pd:pointerTableDomains_){
        if(!pd.staticProof||pd.indices.empty())continue;
        const auto di=std::find_if(romDecoders_.begin(),romDecoders_.end(),[&](const RomDecoderRecord&d){return d.id==pd.decoderId;});
        if(di==romDecoders_.end()||di->routine!=0x2C5E)continue;
        ResidualExtentExtentProofRecord e;e.id=residualExtentExtentProofs_.size();e.kind=ResidualExtentExtentKind::SparsePointerDomain;e.name="RST18 incomplete byte-selector pointer-table domain";e.start=pd.base;
        const std::uint32_t end32=static_cast<std::uint32_t>(pd.base)+pd.stride*256u;e.end=static_cast<std::uint16_t>(std::min<std::uint32_t>(end32,program.size()));
        e.sourceObjectIds.insert(pd.id);e.consumerPCs=di->readPCs;e.proofPCs=pd.proofPCs;e.proofPCs.insert(di->sourcePCs.begin(),di->sourcePCs.end());
        for(auto a:pd.entryAddresses){e.acceptedAddresses.insert(a);if(static_cast<std::size_t>(a)+1<program.size())e.acceptedAddresses.insert(static_cast<std::uint16_t>(a+1));const std::uint16_t target=static_cast<std::uint16_t>(program[a]|(static_cast<std::uint16_t>(program[a+1])<<8));e.acceptedRoots.insert(target);}
        e.residualAddresses=unresolvedInWindow24(baseline,e.start,e.end);e.sourceDomainComplete=false;e.nestedExtentComplete=false;e.accepted=false;e.closesBytes=false;e.note="Known selector observations remain positive evidence only. The queued B source is not exhaustively bounded, so all 256 RST-$18 pointer-entry positions remain potential and omitted selector values cannot support an unused-ROM proof.";residualExtentExtentProofs_.push_back(e);

    }

    for(const auto&f:fixedRecordSemantics_){
        if(!f.staticProof||f.coveredAddresses.empty())continue;
        ResidualExtentExtentProofRecord e;e.id=residualExtentExtentProofs_.size();e.kind=ResidualExtentExtentKind::ExactRecordDomain;e.name="HighRom fixed-record field union @ $"+h24(f.base);e.start=*f.coveredAddresses.begin();e.end=static_cast<std::uint16_t>(*f.coveredAddresses.rbegin()+1);e.acceptedAddresses=f.coveredAddresses;e.consumerPCs=f.readPCs;e.proofPCs=f.proofPCs;e.sourceObjectIds.insert(f.id);e.residualAddresses=unresolvedInWindow24(baseline,e.start,e.end);e.sourceDomainComplete=f.exact||f.bounded;e.nestedExtentComplete=true;e.accepted=e.sourceDomainComplete;e.closesBytes=false;e.note="Record indices, stride and field offsets are inherited source-proven facts; gaps inside the bounding envelope are not silently promoted to record fields.";residualExtentExtentProofs_.push_back(e);
    }

    for(const auto&s0:streamSemantics_){
        const auto di=std::find_if(romDecoders_.begin(),romDecoders_.end(),[&](const RomDecoderRecord&d){return d.id==s0.decoderId;});if(di==romDecoders_.end()||di->routine!=0x2419||!s0.accepted||!s0.staticProof)continue;
        ResidualExtentExtentProofRecord e;e.id=residualExtentExtentProofs_.size();e.kind=ResidualExtentExtentKind::SentinelStreamDomain;e.name="Signed-pair zero-sentinel stream";e.start=s0.start;e.end=s0.end;e.acceptedAddresses=s0.coveredAddresses;e.acceptedRoots.insert(s0.start);e.consumerPCs=s0.readPCs;e.proofPCs=s0.proofPCs;e.sourceObjectIds.insert(s0.id);e.residualAddresses=unresolvedInWindow24(baseline,e.start,e.end);e.sourceDomainComplete=true;e.nestedExtentComplete=s0.terminated;e.accepted=e.nestedExtentComplete;e.closesBytes=false;e.note="The decoder walks signed pairs to the first zero terminator; bytes after the accepted terminator remain outside this object.";residualExtentExtentProofs_.push_back(e);
    }

    if(!commandStreamCommandStreams_.empty()){
        ResidualExtentExtentProofRecord e;e.id=residualExtentExtentProofs_.size();e.kind=ResidualExtentExtentKind::CommandStreamGraph;e.name="CommandStream command-stream rooted graph";e.start=0xFFFF;e.end=0;e.sourceDomainComplete=true;e.nestedExtentComplete=true;
        for(const auto&s:commandStreamCommandStreams_){e.sourceObjectIds.insert(s.id);e.acceptedRoots.insert(s.root);e.proofPCs.insert(s.proofPCs.begin(),s.proofPCs.end());e.acceptedAddresses.insert(s.tokenAddresses.begin(),s.tokenAddresses.end());e.acceptedAddresses.insert(s.f0PayloadAddresses.begin(),s.f0PayloadAddresses.end());e.acceptedAddresses.insert(s.f1PayloadAddresses.begin(),s.f1PayloadAddresses.end());e.acceptedAddresses.insert(s.f2PayloadAddresses.begin(),s.f2PayloadAddresses.end());e.acceptedAddresses.insert(s.f3PayloadAddresses.begin(),s.f3PayloadAddresses.end());e.acceptedAddresses.insert(s.f4PayloadAddresses.begin(),s.f4PayloadAddresses.end());if(!s.complete)e.nestedExtentComplete=false;}
        if(!e.acceptedAddresses.empty()){e.start=*e.acceptedAddresses.begin();e.end=static_cast<std::uint16_t>(*e.acceptedAddresses.rbegin()+1);e.residualAddresses=unresolvedInWindow24(baseline,e.start,e.end);}else{e.start=0;e.end=0;e.sourceDomainComplete=false;}
        e.accepted=e.sourceDomainComplete&&e.nestedExtentComplete;e.closesBytes=false;e.note="Only the four source-rooted command objects and recursively proven replacement targets belong to the accepted graph; $7082/$8269 remain excluded and unrelated command-like bytes are not promoted.";residualExtentExtentProofs_.push_back(e);
    }

    {
        ResidualExtentExtentProofRecord e;e.id=residualExtentExtentProofs_.size();e.kind=ResidualExtentExtentKind::SystemTailGuard;e.name="IM2 system-tail exact extent and final guard";e.start=0x3FFA;e.end=0x4000;e.sourceDomainComplete=true;e.nestedExtentComplete=true;
        for(const auto&s:systemRomSemantics_)if(s.staticProof&&ResidualExtentAnalysis::intersects(e.start,e.end,s.start,s.end)){e.sourceObjectIds.insert(s.id);e.proofPCs.insert(s.proofPCs.begin(),s.proofPCs.end());for(std::uint16_t a=s.start;a<s.end;++a)e.acceptedAddresses.insert(a);}
        e.residualAddresses=unresolvedInWindow24(baseline,e.start,e.end);e.accepted=!e.acceptedAddresses.empty();e.closesBytes=false;e.note="Exact IM2 words explain $3FFA-$3FFD only. $3FFE-$3FFF are deliberately retained as genuine unresolved bytes; neighboring vector semantics, checksum participation and trace silence do not extend the object.";residualExtentExtentProofs_.push_back(e);
    }

    // Exhaustive negative-reference proof for every current span. The final
    // system-tail guard is deliberately excluded even when ordinary reference
    // classes are absent, matching the residual-extent analysis acceptance contract.
    for(const auto&a:residualExtentResidualAudit_){
        ResidualExtentNegativeReferenceRecord n;n.id=residualExtentNegativeReferenceProofs_.size();n.residualAuditId=a.id;n.start=a.start;n.end=a.end;n.length=a.length;n.directMemoryRefPCs=a.directMemoryRefPCs;n.immediateAddressPCs=a.immediateAddressPCs;n.controlTargetPCs=a.controlTargetPCs;n.finiteIndirectPCs=a.finiteIndirectPCs;n.checksumSelfTestPCs=a.checksumSelfTestPCs;n.systemSemanticIds=a.systemSemanticIds;n.unresolvedReadPCs=a.unresolvedReadPCs;
        for(const auto&kv:finalReadDomains)n.boundedReadPCs.insert(kv.first);
        for(const auto&kv:checksumDomains)n.boundedReadPCs.insert(kv.first);
        for(const auto&kv:analyzer_->romDataUsage())if(kv.first>=n.start&&kv.first<n.end){n.dynamicReadEvents+=kv.second.readEvents;n.dynamicReadPCs.insert(kv.second.sourcePCs.begin(),kv.second.sourcePCs.end());}
        n.callerInventoryComplete=callerComplete;n.indirectControlInventoryComplete=indirectControlComplete;n.allReadAlternativesBounded=allConsumersBounded;n.leftBoundaryProven=a.leftBoundaryProven;n.rightBoundaryProven=a.rightBoundaryProven;n.leftRomBoundary=a.leftRomBoundary;n.rightRomBoundary=a.rightRomBoundary;
        n.directReferenceAbsent=n.directMemoryRefPCs.empty()&&n.immediateAddressPCs.empty();n.finiteIndirectReferenceAbsent=n.finiteIndirectPCs.empty();n.controlReferenceAbsent=n.controlTargetPCs.empty();n.systemSemanticAbsent=n.systemSemanticIds.empty();
        n.incompletePointerDomainIds=globallyIncompletePointerDomainIds;
        n.incompletePointerDomainPotentialReference=!n.incompletePointerDomainIds.empty();
        n.exhaustiveModeledStaticAbsence=n.callerInventoryComplete&&n.indirectControlInventoryComplete&&n.allReadAlternativesBounded&&n.directReferenceAbsent&&n.finiteIndirectReferenceAbsent&&n.controlReferenceAbsent&&n.systemSemanticAbsent&&n.unresolvedReadPCs.empty()&&!n.incompletePointerDomainPotentialReference;
        n.guardExcluded=a.guard3ffe3fff;n.supportsUnusedClassification=ResidualExtentAnalysis::qualifiesUnused(n);
        std::ostringstream note;note<<"All independently static direct memory/literal/control references were rescanned from source-proven instructions; context-sensitive root analysis rooted caller inventory is "<<(n.callerInventoryComplete?"complete":"incomplete")<<" and final read blockers="<<n.unresolvedReadPCs.size()<<". ";
        if(n.incompletePointerDomainPotentialReference)note<<"Incomplete sparse pointer-selector domain(s)="<<ids24(n.incompletePointerDomainIds)<<" may select bytes in this span, so omitted selectors are not negative evidence. ";
        if(!n.checksumSelfTestPCs.empty())note<<"Checksum/self-test PCs="<<n.checksumSelfTestPCs.size()<<" are recorded separately and do not establish semantic ownership. ";
        if(n.dynamicReadEvents==0)note<<"No dynamic contradiction is present; dynamic absence is not used as static proof. ";
        if(n.guardExcluded)note<<"The $3FFE-$3FFF explicit guard vetoes unused classification despite ordinary negative evidence. ";
        n.note=note.str();residualExtentNegativeReferenceProofs_.push_back(n);
        if(n.supportsUnusedClassification){ResidualExtentUnusedRegionRecord u;u.id=residualExtentUnusedRegions_.size();u.negativeProofId=n.id;u.start=n.start;u.end=n.end;u.accepted=true;u.note="Exhaustive source-rooted all-consumer negative-reference proof; classified proven unused, not merely unobserved.";residualExtentUnusedRegions_.push_back(u);}
    }

    std::map<std::uint16_t,ResidualExtentClosureProvenanceRecord> prov;
    for(const auto&u:residualExtentUnusedRegions_)if(u.accepted){const auto&n=residualExtentNegativeReferenceProofs_.at(u.negativeProofId);for(std::uint32_t aa=u.start;aa<u.end&&aa<residualExtentClosureBytes_.size();++aa){const auto a=static_cast<std::uint16_t>(aa);if(baseline[a].primary!=RomClosurePrimary::Unresolved)continue;auto&b=residualExtentClosureBytes_[a];b.provenUnused=true;b.primary=RomClosure::classify(b);auto&v=prov[a];v.address=a;v.provenUnused=true;v.residualAuditIds.insert(n.residualAuditId);v.negativeProofIds.insert(n.id);for(const auto&e:residualExtentExtentProofs_)if(e.accepted&&e.residualAddresses.count(a)){v.extentProofIds.insert(e.id);v.proofPCs.insert(e.proofPCs.begin(),e.proofPCs.end());}v.note="residual-extent analysis exhaustive static all-consumer absence; byte retained in ROM image but proven unreachable as semantic ROM data/code under the complete rooted model.";}}
    for(auto&kv:prov)residualExtentClosureProvenance_.push_back(kv.second);

    // Final residual map and exact statistics.
    auto&st=stats_.residualExtent;st.residualAuditRecords=residualExtentResidualAudit_.size();for(const auto&r:residualExtentResidualAudit_)st.auditedResidualBytes+=r.length;st.extentProofs=residualExtentExtentProofs_.size();for(const auto&e:residualExtentExtentProofs_)if(e.accepted)++st.acceptedExtentProofs;st.negativeReferenceProofs=residualExtentNegativeReferenceProofs_.size();for(const auto&n:residualExtentNegativeReferenceProofs_)if(n.exhaustiveModeledStaticAbsence)++st.exhaustiveNegativeProofs;st.unusedRegions=residualExtentUnusedRegions_.size();st.closureProvenanceRecords=residualExtentClosureProvenance_.size();st.allConsumerInventoryComplete=allConsumersBounded;
    bool in=false;std::size_t fs=0;for(std::size_t i=0;i<residualExtentClosureBytes_.size();++i){const bool u=residualExtentClosureBytes_[i].primary==RomClosurePrimary::Unresolved;if(u){++st.unresolvedAfterResidualExtent;if(!in){fs=i;in=true;}}else if(in){ResidualExtentFinalResidualRecord r;r.id=residualExtentFinalResidual_.size();r.start=static_cast<std::uint16_t>(fs);r.end=static_cast<std::uint16_t>(i);r.length=i-fs;r.reason=(r.start==0x3FFE&&r.end==0x4000)?"residual-extent analysis final-system-tail guard: no genuine static/system semantic extent proven":"static proof still incomplete";residualExtentFinalResidual_.push_back(r);in=false;}if(i<baseline.size()&&baseline[i].primary==RomClosurePrimary::Unresolved&&residualExtentClosureBytes_[i].primary==RomClosurePrimary::ProvenUnused)++st.newlyUnusedExplainedBytes;}
    if(in){ResidualExtentFinalResidualRecord r;r.id=residualExtentFinalResidual_.size();r.start=static_cast<std::uint16_t>(fs);r.end=static_cast<std::uint16_t>(residualExtentClosureBytes_.size());r.length=residualExtentClosureBytes_.size()-fs;r.reason=(r.start==0x3FFE&&r.end==0x4000)?"residual-extent analysis final-system-tail guard: no genuine static/system semantic extent proven":"static proof still incomplete";residualExtentFinalResidual_.push_back(r);}
    st.residualSpansAfterResidualExtent=residualExtentFinalResidual_.size();st.newlyExplainedBytes=st.newlyUnusedExplainedBytes;
    for(std::uint16_t a=0x330D;a<0x330F&&a<residualExtentClosureBytes_.size();++a)if(baseline[a].primary==RomClosurePrimary::Unresolved&&residualExtentClosureBytes_[a].primary!=RomClosurePrimary::Unresolved)++st.guard330d330eClosedBytes;
    for(std::uint16_t a=0x3FFE;a<0x4000&&a<residualExtentClosureBytes_.size();++a)if(residualExtentClosureBytes_[a].primary==RomClosurePrimary::Unresolved)++st.guard3ffe3fffUnresolvedBytes;
}

std::vector<std::string> Decompiler::residualExtentResidualAuditLines() const{
    std::vector<std::string>o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper residual-extent analysis residual inventory v2");o.push_back("audits="+std::to_string(stats_.residualExtent.residualAuditRecords)+" bytes="+std::to_string(stats_.residualExtent.auditedResidualBytes)+" all-consumers="+(stats_.residualExtent.allConsumerInventoryComplete?"complete":"incomplete"));
    for(const auto&r:residualExtentResidualAudit_)o.push_back("residual24#"+std::to_string(r.id)+" $"+h24(r.start)+"-$"+h24(static_cast<std::uint16_t>(r.end-1))+" len="+std::to_string(r.length)+" inherited="+MazeTopologyAnalysis::residualKindText(r.inheritedKind)+" direct="+pcs24(r.directMemoryRefPCs)+" literal="+pcs24(r.immediateAddressPCs)+" control="+pcs24(r.controlTargetPCs)+" finite="+pcs24(r.finiteIndirectPCs)+" decoder="+ids24(r.decoderIds,"decoder#")+" pointer-domains="+ids24(r.pointerDomainIds,"domain#")+" ptr-links="+ids24(r.pointerLinkIds,"link#")+" blockers="+pcs24(r.unresolvedReadPCs)+" eligible="+(r.negativeClosureEligible?"yes":"no")+" :: "+r.note);
    return o;
}
std::vector<std::string> Decompiler::residualExtentExtentProofLines() const{
    std::vector<std::string>o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper residual-extent analysis object/decoder extent proofs");o.push_back("accepted="+std::to_string(stats_.residualExtent.acceptedExtentProofs)+"/"+std::to_string(stats_.residualExtent.extentProofs));for(const auto&e:residualExtentExtentProofs_)o.push_back("extent#"+std::to_string(e.id)+" kind="+ResidualExtentAnalysis::extentKindText(e.kind)+" name="+e.name+" window=$"+h24(e.start)+"-$"+(e.end>e.start?h24(static_cast<std::uint16_t>(e.end-1)):h24(e.end))+" accepted-addresses="+std::to_string(e.acceptedAddresses.size())+" roots="+pcs24(e.acceptedRoots)+" excluded-roots="+pcs24(e.excludedRoots)+" residual-in-window="+std::to_string(e.residualAddresses.size())+" domain="+(e.sourceDomainComplete?"complete":"incomplete")+" nested="+(e.nestedExtentComplete?"complete":"incomplete")+" accepted="+(e.accepted?"yes":"no")+" :: "+e.note);return o;
}
std::vector<std::string> Decompiler::residualExtentNegativeReferenceLines() const{
    std::vector<std::string>o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper residual-extent analysis exhaustive all-consumer negative-reference proofs");o.push_back("exhaustive="+std::to_string(stats_.residualExtent.exhaustiveNegativeProofs)+"/"+std::to_string(stats_.residualExtent.negativeReferenceProofs)+" unused-regions="+std::to_string(stats_.residualExtent.unusedRegions));for(const auto&n:residualExtentNegativeReferenceProofs_)o.push_back("negative24#"+std::to_string(n.id)+" $"+h24(n.start)+"-$"+h24(static_cast<std::uint16_t>(n.end-1))+" direct="+pcs24(n.directMemoryRefPCs)+" literal="+pcs24(n.immediateAddressPCs)+" control="+pcs24(n.controlTargetPCs)+" finite="+pcs24(n.finiteIndirectPCs)+" blockers="+pcs24(n.unresolvedReadPCs)+" incomplete-pointer-domains="+ids24(n.incompletePointerDomainIds)+" incomplete-pointer-potential="+(n.incompletePointerDomainPotentialReference?"yes":"no")+" exhaustive="+(n.exhaustiveModeledStaticAbsence?"yes":"no")+" guard="+(n.guardExcluded?"yes":"no")+" unused="+(n.supportsUnusedClassification?"yes":"no")+" :: "+n.note);return o;
}
std::vector<std::string> Decompiler::residualExtentClosureLines() const{
    std::vector<std::string>o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper residual-extent analysis proven-unused closure");o.push_back("new-unused="+std::to_string(stats_.residualExtent.newlyUnusedExplainedBytes)+" residual="+std::to_string(stats_.residualExtent.unresolvedAfterResidualExtent)+" spans="+std::to_string(stats_.residualExtent.residualSpansAfterResidualExtent)+" $330D-$330E-closed="+std::to_string(stats_.residualExtent.guard330d330eClosedBytes)+" $3FFE-$3FFF-unresolved="+std::to_string(stats_.residualExtent.guard3ffe3fffUnresolvedBytes));for(const auto&r:residualExtentFinalResidual_)o.push_back("final-residual#"+std::to_string(r.id)+" $"+h24(r.start)+"-$"+h24(static_cast<std::uint16_t>(r.end-1))+" len="+std::to_string(r.length)+" :: "+r.reason);for(const auto&p:residualExtentClosureProvenance_)o.push_back("$"+h24(p.address)+" unused="+(p.provenUnused?"yes":"no")+" residual="+ids24(p.residualAuditIds,"residual24#")+" negative="+ids24(p.negativeProofIds,"negative24#")+" extents="+ids24(p.extentProofIds,"extent#")+" :: "+p.note);return o;
}

} // namespace pacripper
