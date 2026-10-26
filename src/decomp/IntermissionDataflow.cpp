// PacRipper intermission analysis integration / lifecycle closure
// Created by Jacob Hodgkins

#include "Decompiler.h"

#include <iomanip>
#include <map>
#include <set>
#include <sstream>

namespace pacripper {
namespace {
std::string h23(std::uint16_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(4)<<std::setfill('0')<<(unsigned)v;return o.str();}
template<class T>std::string ids23(const std::set<T>&s,const char*p=""){std::ostringstream o;o<<"{";std::size_t n=0;for(auto v:s){if(n++)o<<",";o<<p<<v;}o<<"}";return o.str();}
std::string pcs23(const std::set<std::uint16_t>&s){std::ostringstream o;o<<"{";std::size_t n=0;for(auto v:s){if(n++)o<<",";o<<"$"<<h23(v);}o<<"}";return o.str();}
std::string vals23(const std::set<std::uint8_t>&s){std::ostringstream o;o<<"{";std::size_t n=0;for(auto v:s){if(n++)o<<",";o<<"$"<<std::uppercase<<std::hex<<std::setw(2)<<std::setfill('0')<<(unsigned)v;}o<<"}";return o.str();}
}

void Decompiler::buildIntermission(){
    intermissionDispatchProofs_.clear();intermissionWriterProofs_.clear();intermissionLifecycleProofs_.clear();intermissionAddressProofs_.clear();intermissionClosureProvenance_.clear();intermissionClosureBytes_.clear();stats_.intermission={};
    if(!analyzer_)return;
    const auto&baseline=!mazeTopologyClosureBytes_.empty()?mazeTopologyClosureBytes_:commandStreamClosureBytes_;intermissionClosureBytes_=baseline;
    const auto result=IntermissionAnalysis::analyze(*analyzer_,hardwareAccesses_,mazeTopologyRetryLoopProofs_,mazeTopologyAddressProofs_);
    intermissionDispatchProofs_=result.dispatchProofs;intermissionWriterProofs_=result.writerProofs;intermissionLifecycleProofs_=result.lifecycleProofs;intermissionAddressProofs_=result.addressProofs;

    std::map<std::uint16_t,IntermissionClosureProvenanceRecord>prov;
    for(const auto&p:intermissionAddressProofs_){
        if(!IntermissionAnalysis::semanticRomClosureEligible(p))continue;
        std::set<std::uint16_t>d;if(!RootContextAnalysis::completeFiniteDomain(p.address,d))continue;const bool exact=d.size()==1;
        for(auto a:d){
            if(a>=intermissionClosureBytes_.size()||a>=baseline.size()||baseline[a].primary!=RomClosurePrimary::Unresolved)continue;
            auto&b=intermissionClosureBytes_[a];if(exact)b.staticExactDataUse=true;else b.boundedConsumer=true;b.consumerPCs.insert(p.pc);b.primary=RomClosure::classify(b);
            auto&v=prov[a];v.address=a;v.exact=v.exact||exact;v.bounded=v.bounded||!exact;v.addressProofIds.insert(p.id);v.lifecycleProofIds.insert(p.lifecycleProofIds.begin(),p.lifecycleProofIds.end());v.sourcePCs.insert(p.pc);v.sourcePCs.insert(p.proofPCs.begin(),p.proofPCs.end());v.note=exact?"exact intermission analysis lifecycle-backed ROM address":"bounded intermission analysis lifecycle-backed ROM address";
        }
    }
    for(auto&kv:prov)intermissionClosureProvenance_.push_back(kv.second);

    auto&st=stats_.intermission;st.dispatchProofs=intermissionDispatchProofs_.size();for(const auto&r:intermissionDispatchProofs_)if(r.complete)++st.completeDispatchProofs;
    st.writerProofs=intermissionWriterProofs_.size();for(const auto&r:intermissionWriterProofs_){if(r.lifecycleReachable)++st.lifecycleReachableWriterProofs;if(r.touchesCriticalCorridor)++st.criticalCorridorWriterProofs;if(r.lifecycleReachable&&r.touchesCriticalCorridor&&r.canWriteBlockingValue)++st.blockingCriticalWriterProofs;}
    st.lifecycleProofs=intermissionLifecycleProofs_.size();for(const auto&r:intermissionLifecycleProofs_)if(r.accepted)++st.acceptedLifecycleProofs;
    st.addressProofs=intermissionAddressProofs_.size();for(const auto&r:intermissionAddressProofs_)if(r.accepted)++st.acceptedAddressProofs;
    st.inheritedBlockers=result.inheritedBlockerPCs.size();st.refinedInheritedBlockers=result.refinedInheritedBlockerPCs.size();st.remainingBlockers=result.remainingBlockerPCs.size();st.closureProvenanceRecords=intermissionClosureProvenance_.size();
    bool in=false;for(std::size_t i=0;i<intermissionClosureBytes_.size();++i){const bool u=intermissionClosureBytes_[i].primary==RomClosurePrimary::Unresolved;if(u){++st.unresolvedAfterIntermission;if(!in){++st.residualSpansAfterIntermission;in=true;}}else in=false;if(i<baseline.size()&&baseline[i].primary==RomClosurePrimary::Unresolved&&!u){if(intermissionClosureBytes_[i].staticExactDataUse)++st.newlyExactExplainedBytes;else ++st.newlyBoundedExplainedBytes;}}st.newlyExplainedBytes=st.newlyExactExplainedBytes+st.newlyBoundedExplainedBytes;
}

std::vector<std::string> Decompiler::intermissionDispatchProofLines() const{std::vector<std::string>o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper intermission analysis intermission dispatch proofs");o.push_back("complete="+std::to_string(stats_.intermission.completeDispatchProofs)+"/"+std::to_string(stats_.intermission.dispatchProofs));for(const auto&r:intermissionDispatchProofs_)o.push_back("dispatch#"+std::to_string(r.id)+" kind="+IntermissionAnalysis::dispatchKindText(r.kind)+" pc=$"+h23(r.dispatchPC)+" table=$"+h23(r.tableStart)+" entries="+std::to_string(r.entryCount)+" shape="+(r.sourceShapeProven?"yes":"no")+" complete="+(r.complete?"yes":"no")+" :: "+r.note);return o;}
std::vector<std::string> Decompiler::intermissionWriterProofLines() const{std::vector<std::string>o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper intermission analysis video-writer lifecycle audit");o.push_back("writers="+std::to_string(stats_.intermission.writerProofs)+" lifecycle="+std::to_string(stats_.intermission.lifecycleReachableWriterProofs)+" critical="+std::to_string(stats_.intermission.criticalCorridorWriterProofs)+" blocking-critical="+std::to_string(stats_.intermission.blockingCriticalWriterProofs));for(const auto&r:intermissionWriterProofs_)o.push_back("writer#"+std::to_string(r.id)+" kind="+IntermissionAnalysis::writerKindText(r.kind)+" name="+r.name+" pcs="+pcs23(r.writerPCs)+" targets="+pcs23(r.targetAddresses)+" values="+vals23(r.writtenValues)+" lifecycle="+(r.lifecycleReachable?"yes":"no")+" critical="+(r.touchesCriticalCorridor?"yes":"no")+" blocking="+(r.canWriteBlockingValue?"yes":"no")+" shape="+(r.sourceShapeProven?"yes":"no")+" :: "+r.note);return o;}
std::vector<std::string> Decompiler::intermissionLifecycleProofLines() const{std::vector<std::string>o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper intermission analysis $291E topology lifecycle proof");o.push_back("accepted="+std::to_string(stats_.intermission.acceptedLifecycleProofs)+"/"+std::to_string(stats_.intermission.lifecycleProofs)+" blockers="+std::to_string(stats_.intermission.remainingBlockers));for(const auto&r:intermissionLifecycleProofs_)o.push_back("lifecycle#"+std::to_string(r.id)+" setup="+(r.setupQueueShapeProven?"yes":"no")+" clear-before="+(r.playfieldClearBeforeIntermissionProven?"yes":"no")+" init="+(r.ghostInitializerProven?"yes":"no")+" coord-map="+(r.coordinateMappingProven?"yes":"no")+" gate="+(r.interiorGateProven?"yes":"no")+" dispatch="+(r.stateDispatchComplete?"yes":"no")+" timer="+(r.delayedTransitionsComplete?"yes":"no")+" queue-drain="+(r.taskQueueDrainProven?"yes":"no")+" writers="+(r.relevantWriterInventoryComplete?"yes":"no")+" corridor-init="+(r.criticalCorridorInitializedPassable?"yes":"no")+" corridor-preserved="+(r.criticalCorridorPreservedPassable?"yes":"no")+" maze="+(r.canonicalMazeRetryExitInherited?"yes":"no")+" intermission="+(r.intermissionRetryExitProven?"yes":"no")+" all-topologies="+(r.allTopologyStatesComplete?"yes":"no")+" accepted="+(r.accepted?"yes":"no")+" missing={"+r.missingStaticFact+"} :: "+r.note);return o;}
std::vector<std::string> Decompiler::intermissionAddressProofLines() const{std::vector<std::string>o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper intermission analysis accepted retry-loop address proofs");o.push_back("accepted="+std::to_string(stats_.intermission.acceptedAddressProofs)+"/"+std::to_string(stats_.intermission.addressProofs)+" refined="+std::to_string(stats_.intermission.refinedInheritedBlockers)+" remaining="+std::to_string(stats_.intermission.remainingBlockers));for(const auto&r:intermissionAddressProofs_)o.push_back("proof#"+std::to_string(r.id)+" pc=$"+h23(r.pc)+" operand="+r.operand+" class="+RootContextAnalysis::domainClassText(r.domainClass)+" domain="+pcs23(r.finiteDomain)+" accepted="+(r.accepted?"yes":"no")+" lifecycle="+ids23(r.lifecycleProofIds,"lifecycle#")+" :: "+r.note);return o;}
std::vector<std::string> Decompiler::intermissionClosureLines() const{std::vector<std::string>o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper intermission analysis lifecycle/retry-loop closure");o.push_back("new="+std::to_string(stats_.intermission.newlyExplainedBytes)+" exact="+std::to_string(stats_.intermission.newlyExactExplainedBytes)+" bounded="+std::to_string(stats_.intermission.newlyBoundedExplainedBytes)+" residual="+std::to_string(stats_.intermission.unresolvedAfterIntermission)+" spans="+std::to_string(stats_.intermission.residualSpansAfterIntermission));for(const auto&p:intermissionClosureProvenance_)o.push_back("$"+h23(p.address)+" exact="+(p.exact?"yes":"no")+" bounded="+(p.bounded?"yes":"no")+" proofs="+ids23(p.addressProofIds,"proof#")+" lifecycle="+ids23(p.lifecycleProofIds,"lifecycle#")+" source="+pcs23(p.sourcePCs)+" :: "+p.note);return o;}

} // namespace pacripper
