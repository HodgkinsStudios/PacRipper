// PacRipper context-sensitive root analysis context-sensitive system-root address flow + residual consumer closure
// Created by Jacob Hodgkins

#include "Decompiler.h"

#include <iomanip>
#include <map>
#include <set>
#include <sstream>

namespace pacripper {
namespace {
std::string h19(std::uint16_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(4)<<std::setfill('0')<<(unsigned)v;return o.str();}
std::string pcs19(const std::set<std::uint16_t>&s){std::ostringstream o;o<<"{";std::size_t n=0;for(auto v:s){if(n++)o<<",";o<<"$"<<h19(v);}o<<"}";return o.str();}
std::string ids19(const std::set<std::size_t>&s,const char*p=""){std::ostringstream o;o<<"{";std::size_t n=0;for(auto v:s){if(n++)o<<",";o<<p<<v;}o<<"}";return o.str();}
std::string domain19(const AddressLatticeValue&v){std::set<std::uint16_t>d;if(!RootContextAnalysis::completeFiniteDomain(v,d))return "unknown";std::ostringstream o;o<<"{";std::size_t n=0;for(auto a:d){if(n++)o<<",";o<<"$"<<h19(a);}o<<"}";return o.str();}
bool intersects19(const AddressLatticeValue&v,std::uint16_t start,std::uint16_t end){
    std::set<std::uint16_t>d;if(!RootContextAnalysis::completeFiniteDomain(v,d))return false;
    for(auto a:d)if(a>=start&&a<end)return true;
    return false;
}
}

void Decompiler::buildRootContext(){
    rootContextAddressContexts_.clear();rootContextAddressProofs_.clear();rootContextNegativeReferenceEvidence_.clear();
    rootContextUnusedRomRegions_.clear();rootContextClosureProvenance_.clear();rootContextClosureBytes_.clear();stats_.rootContext={};
    if(!analyzer_)return;
    const auto& baseline=!systemRootClosureBytes_.empty()?systemRootClosureBytes_:residualReferenceClosureBytes_;
    rootContextClosureBytes_=baseline;

    const auto result=RootContextAnalysis::analyze(*analyzer_,systemRootReachability_,systemRootInlineData_,systemRootNegativeReferenceEvidence_,32,512,8);
    rootContextAddressContexts_=result.contextRecords;rootContextAddressProofs_=result.addressProofs;
    memoryAliasWriterContexts_=result.writerContextRecords;memoryAliasWriterProofs_=result.writerAddressProofs;

    // Preserve system-root reachability analysis span identities and overlay caller-complete context-sensitive root analysis facts.
    std::map<std::size_t,const NegativeReferenceRecord*> residualReferenceById;
    for(const auto&n:negativeReferenceEvidence_)residualReferenceById[n.id]=&n;
    for(const auto&old:systemRootNegativeReferenceEvidence_){
        RootContextNegativeReferenceRecord n;n.id=rootContextNegativeReferenceEvidence_.size();n.systemRootNegativeReferenceId=old.id;
        n.start=old.start;n.end=old.end;n.length=old.length;n.inheritedPositiveReference=old.inheritedPositiveReference;
        n.dynamicReadEvents=old.dynamicReadEvents;n.callerInventoryComplete=result.callerInventoryComplete;
        n.remainingInheritedBlockerPCs=result.remainingInheritedBlockerPCs;
        n.remainingNewlyRootedBlockerPCs=result.remainingNewlyRootedBlockerPCs;
        for(const auto&p:rootContextAddressProofs_){
            if(!p.accepted)continue;
            if(intersects19(p.aggregateAddress,n.start,n.end)){n.finitePositiveHitPCs.insert(p.pc);n.finitePositiveProofIds.insert(p.id);}
        }
        const bool noPositive=!n.inheritedPositiveReference&&n.finitePositiveHitPCs.empty();
        n.exhaustiveModeledStaticAbsence=n.callerInventoryComplete&&noPositive&&n.remainingInheritedBlockerPCs.empty()&&n.remainingNewlyRootedBlockerPCs.empty();
        bool left=false,right=false;auto pi=residualReferenceById.find(old.residualReferenceNegativeReferenceId);if(pi!=residualReferenceById.end()){left=pi->second->leftBoundaryProven;right=pi->second->rightBoundaryProven;}
        n.supportsUnusedClassification=RootContextAnalysis::supportsUnused(n,left,right);
        std::ostringstream note;note<<"context-sensitive root analysis context-sensitive overlay: caller-complete="<<(n.callerInventoryComplete?"yes":"no")
            <<", inherited blockers="<<n.remainingInheritedBlockerPCs.size()<<", newly rooted blockers="<<n.remainingNewlyRootedBlockerPCs.size()
            <<", finite positive hits="<<n.finitePositiveHitPCs.size()<<". Dynamic evidence remains corroborative only.";n.note=note.str();
        rootContextNegativeReferenceEvidence_.push_back(n);
        if(n.supportsUnusedClassification){UnusedRomRegionRecord u;u.id=rootContextUnusedRomRegions_.size();u.negativeReferenceId=n.id;u.start=n.start;u.end=n.end;u.accepted=true;u.note="context-sensitive root analysis exhaustive caller-complete negative reference proof with proven boundaries";rootContextUnusedRomRegions_.push_back(u);}
    }

    // Only accepted finite-ROM caller-complete domains can add closure. Mixed or
    // non-ROM domains remain evidence records but never close a byte here.
    std::map<std::uint16_t,RootContextClosureProvenanceRecord> prov;
    for(const auto&p:rootContextAddressProofs_){
        if(!p.accepted||p.domainClass!=RootContextDomainClass::FiniteRom)continue;
        std::set<std::uint16_t>domain;if(!RootContextAnalysis::completeFiniteDomain(p.aggregateAddress,domain))continue;
        const bool exact=domain.size()==1;
        for(auto a:domain){
            if(a>=rootContextClosureBytes_.size()||baseline[a].primary!=RomClosurePrimary::Unresolved)continue;
            auto&b=rootContextClosureBytes_[a];if(exact)b.staticExactDataUse=true;else b.boundedConsumer=true;b.consumerPCs.insert(p.pc);b.primary=RomClosure::classify(b);
            auto&v=prov[a];v.address=a;v.exact=v.exact||exact;v.bounded=v.bounded||!exact;v.addressProofIds.insert(p.id);v.contextRecordIds.insert(p.contextRecordIds.begin(),p.contextRecordIds.end());v.sourcePCs.insert(p.pc);v.sourcePCs.insert(p.proofPCs.begin(),p.proofPCs.end());v.callSites.insert(p.callSites.begin(),p.callSites.end());if(!v.note.empty())v.note+="; ";v.note+=exact?"exact caller-complete finite ROM address":"bounded caller-complete finite ROM address union";
        }
    }
    for(auto&kv:prov)rootContextClosureProvenance_.push_back(kv.second);

    std::size_t unresolved=0,spans=0,newExact=0,newBounded=0;bool in=false;
    for(std::size_t i=0;i<rootContextClosureBytes_.size();++i){const bool u=rootContextClosureBytes_[i].primary==RomClosurePrimary::Unresolved;if(u){++unresolved;if(!in){++spans;in=true;}}else in=false;if(i<baseline.size()&&baseline[i].primary==RomClosurePrimary::Unresolved&&!u){if(rootContextClosureBytes_[i].staticExactDataUse)++newExact;else ++newBounded;}}
    auto&st=stats_.rootContext;st.rootedContextStates=result.rootedContextStates;st.maxObservedCallDepth=result.maxObservedCallDepth;st.stateMergeUpdates=result.stateMergeUpdates;st.valueWidenEvents=result.valueWidenEvents;st.contextOverflowEvents=result.contextOverflowEvents;st.contextOverflowPCs=result.contextOverflowPCs.size();st.unresolvedIndirectControlPCs=result.unresolvedIndirectControlPCs.size();st.guardTrips=result.guardTrips;st.callerInventoryComplete=result.callerInventoryComplete;st.addressContextRecords=rootContextAddressContexts_.size();st.addressProofs=rootContextAddressProofs_.size();
    for(const auto&p:rootContextAddressProofs_){if(p.accepted)++st.acceptedAddressProofs;if(p.sourceInvariant)++st.sourceInvariantProofs;switch(p.domainClass){case RootContextDomainClass::FiniteRom:++st.finiteRomProofs;break;case RootContextDomainClass::FiniteNonRom:++st.finiteNonRomProofs;break;case RootContextDomainClass::Mixed:++st.mixedProofs;break;case RootContextDomainClass::Unresolved:++st.unresolvedProofs;break;}}
    st.inheritedBlockers=result.inheritedBlockerPCs.size();st.refinedInheritedBlockers=result.refinedInheritedBlockerPCs.size();st.remainingInheritedBlockers=result.remainingInheritedBlockerPCs.size();st.newlyRootedBlockers=result.newlyRootedBlockerPCs.size();st.refinedNewlyRootedBlockers=result.refinedNewlyRootedBlockerPCs.size();st.remainingNewlyRootedBlockers=result.remainingNewlyRootedBlockerPCs.size();st.totalRemainingBlockers=st.remainingInheritedBlockers+st.remainingNewlyRootedBlockers;st.negativeReferenceRecords=rootContextNegativeReferenceEvidence_.size();for(const auto&n:rootContextNegativeReferenceEvidence_)if(n.exhaustiveModeledStaticAbsence)++st.exhaustiveNegativeReferenceRecords;st.unusedRomRegions=rootContextUnusedRomRegions_.size();st.closureProvenanceRecords=rootContextClosureProvenance_.size();st.newlyExactExplainedBytes=newExact;st.newlyBoundedExplainedBytes=newBounded;st.newlyExplainedBytes=newExact+newBounded;st.unresolvedAfterRootContext=unresolved;st.residualSpansAfterRootContext=spans;
}

std::vector<std::string> Decompiler::rootContextAddressContextLines() const{std::vector<std::string>o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper context-sensitive root analysis caller-context address flow");o.push_back("contexts="+std::to_string(stats_.rootContext.rootedContextStates)+" records="+std::to_string(stats_.rootContext.addressContextRecords)+" max-depth="+std::to_string(stats_.rootContext.maxObservedCallDepth)+" widen="+std::to_string(stats_.rootContext.valueWidenEvents)+" guard-trips="+std::to_string(stats_.rootContext.guardTrips)+" caller-inventory="+(stats_.rootContext.callerInventoryComplete?"complete":"incomplete"));for(const auto&r:rootContextAddressContexts_)o.push_back("ctx#"+std::to_string(r.id)+" pc=$"+h19(r.pc)+" "+r.operand+" calls="+pcs19(r.callSites)+" proof="+pcs19(r.proofPCs)+" :: "+r.note);return o;}
std::vector<std::string> Decompiler::rootContextAddressProofLines() const{std::vector<std::string>o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper context-sensitive root analysis caller-complete address proofs");o.push_back("proofs="+std::to_string(stats_.rootContext.addressProofs)+" accepted="+std::to_string(stats_.rootContext.acceptedAddressProofs)+" source-invariants="+std::to_string(stats_.rootContext.sourceInvariantProofs)+" inherited-refined="+std::to_string(stats_.rootContext.refinedInheritedBlockers)+" new-root-refined="+std::to_string(stats_.rootContext.refinedNewlyRootedBlockers)+" remaining="+std::to_string(stats_.rootContext.totalRemainingBlockers));for(const auto&p:rootContextAddressProofs_)o.push_back("proof#"+std::to_string(p.id)+" pc=$"+h19(p.pc)+" class="+RootContextAnalysis::domainClassText(p.domainClass)+" domain="+domain19(p.aggregateAddress)+" accepted="+(p.accepted?"yes":"no")+" source-invariant="+(p.sourceInvariant?"yes":"no")+" contexts="+ids19(p.contextRecordIds,"ctx#")+" calls="+pcs19(p.callSites)+" proof="+pcs19(p.proofPCs)+" :: "+p.note);return o;}
std::vector<std::string> Decompiler::rootContextNegativeRomEvidenceLines() const{std::vector<std::string>o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper context-sensitive root analysis negative ROM evidence");for(const auto&n:rootContextNegativeReferenceEvidence_)o.push_back("negative19#"+std::to_string(n.id)+" $"+h19(n.start)+"-$"+h19(static_cast<std::uint16_t>(n.end-1))+" inherited="+std::to_string(n.remainingInheritedBlockerPCs.size())+" new-root="+std::to_string(n.remainingNewlyRootedBlockerPCs.size())+" hits="+pcs19(n.finitePositiveHitPCs)+" exhaustive="+(n.exhaustiveModeledStaticAbsence?"yes":"no")+" unused="+(n.supportsUnusedClassification?"yes":"no")+" :: "+n.note);return o;}
std::vector<std::string> Decompiler::rootContextClosureLines() const{std::vector<std::string>o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper context-sensitive root analysis residual consumer closure");o.push_back("new="+std::to_string(stats_.rootContext.newlyExplainedBytes)+" exact="+std::to_string(stats_.rootContext.newlyExactExplainedBytes)+" bounded="+std::to_string(stats_.rootContext.newlyBoundedExplainedBytes)+" residual="+std::to_string(stats_.rootContext.unresolvedAfterRootContext)+" spans="+std::to_string(stats_.rootContext.residualSpansAfterRootContext));for(const auto&p:rootContextClosureProvenance_)o.push_back("$"+h19(p.address)+" exact="+(p.exact?"yes":"no")+" bounded="+(p.bounded?"yes":"no")+" proofs="+ids19(p.addressProofIds,"proof#")+" contexts="+ids19(p.contextRecordIds,"ctx#")+" calls="+pcs19(p.callSites)+" source="+pcs19(p.sourcePCs)+" :: "+p.note);return o;}

} // namespace pacripper
