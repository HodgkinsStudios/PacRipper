// PacRipper memory-alias analysis writer-alias / pointer-lifecycle dataflow integration
// Created by Jacob Hodgkins

#include "Decompiler.h"

#include <iomanip>
#include <map>
#include <set>
#include <sstream>

namespace pacripper {
namespace {
std::string h20(std::uint16_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(4)<<std::setfill('0')<<(unsigned)v;return o.str();}
std::string pcs20(const std::set<std::uint16_t>&s){std::ostringstream o;o<<"{";std::size_t n=0;for(auto v:s){if(n++)o<<",";o<<"$"<<h20(v);}o<<"}";return o.str();}
std::string ids20(const std::set<std::size_t>&s,const char*p=""){std::ostringstream o;o<<"{";std::size_t n=0;for(auto v:s){if(n++)o<<",";o<<p<<v;}o<<"}";return o.str();}
std::string domain20(const AddressLatticeValue&v){std::set<std::uint16_t>d;if(!RootContextAnalysis::completeFiniteDomain(v,d))return"unknown";std::ostringstream o;if(d.size()>64){o<<"{count="<<d.size()<<",min=$"<<h20(*d.begin())<<",max=$"<<h20(*d.rbegin())<<"}";return o.str();}o<<"{";std::size_t n=0;for(auto a:d){if(n++)o<<",";o<<"$"<<h20(a);}o<<"}";return o.str();}
}

void Decompiler::buildMemoryAlias(){
    memoryAliasWriterAliases_.clear();memoryAliasAddressProofs_.clear();memoryAliasClosureProvenance_.clear();memoryAliasClosureBytes_.clear();stats_.memoryAlias={};
    if(!analyzer_)return;
    const auto&baseline=!rootContextClosureBytes_.empty()?rootContextClosureBytes_:systemRootClosureBytes_;memoryAliasClosureBytes_=baseline;
    const auto result=MemoryAliasAnalysis::analyze(*analyzer_,systemRootReachability_,rootContextAddressContexts_,memoryAliasWriterContexts_,memoryAliasWriterProofs_,stats_.rootContext.callerInventoryComplete,stats_.rootContext.contextOverflowEvents,stats_.rootContext.guardTrips,stats_.rootContext.unresolvedIndirectControlPCs);
    memoryAliasWriterAliases_=result.writerAliases;memoryAliasAddressProofs_=result.addressProofs;

    std::map<std::uint16_t,MemoryAliasClosureProvenanceRecord> prov;
    for(const auto&p:memoryAliasAddressProofs_){
        // Self-test/checksum reads are evidence about hardware diagnostics, not
        // semantic program-data meaning.  Keep that distinction explicit even
        // if a future self-test proof happens to intersect the ROM address map.
        if(!MemoryAliasAnalysis::semanticRomClosureEligible(p))continue;
        std::set<std::uint16_t>d;
        if(!RootContextAnalysis::completeFiniteDomain(p.address,d))continue;
        const bool exact=d.size()==1;
        for(auto a:d){if(a>=memoryAliasClosureBytes_.size()||baseline[a].primary!=RomClosurePrimary::Unresolved)continue;auto&b=memoryAliasClosureBytes_[a];if(exact)b.staticExactDataUse=true;else b.boundedConsumer=true;b.consumerPCs.insert(p.pc);b.primary=RomClosure::classify(b);auto&v=prov[a];v.address=a;v.exact=v.exact||exact;v.bounded=v.bounded||!exact;v.addressProofIds.insert(p.id);v.writerAliasRecordIds.insert(p.writerAliasRecordIds.begin(),p.writerAliasRecordIds.end());v.sourcePCs.insert(p.pc);v.sourcePCs.insert(p.proofPCs.begin(),p.proofPCs.end());if(!v.note.empty())v.note+="; ";v.note+=exact?"exact memory-alias analysis finite ROM lifecycle address":"bounded memory-alias analysis finite ROM lifecycle address";}
    }
    for(auto&kv:prov)memoryAliasClosureProvenance_.push_back(kv.second);

    auto&st=stats_.memoryAlias;st.writerContextRecords=memoryAliasWriterContexts_.size();st.writerProofs=memoryAliasWriterProofs_.size();for(const auto&p:memoryAliasWriterProofs_){if(p.accepted)++st.acceptedWriterProofs;else ++st.unresolvedWriterProofs;}st.writerAliasInventories=memoryAliasWriterAliases_.size();for(const auto&r:memoryAliasWriterAliases_)if(r.complete)++st.completeWriterAliasInventories;st.writerCallerInventoryComplete=result.writerCallerInventoryComplete;st.writerContextOverflowEvents=result.writerContextOverflowEvents;st.writerGuardTrips=result.writerGuardTrips;st.writerUnresolvedIndirectControlPCs=result.writerUnresolvedIndirectControlPCs;st.addressProofs=memoryAliasAddressProofs_.size();for(const auto&p:memoryAliasAddressProofs_)if(p.accepted)++st.acceptedAddressProofs;st.inheritedBlockers=result.inheritedBlockerPCs.size();st.refinedInheritedBlockers=result.refinedInheritedBlockerPCs.size();st.remainingInheritedBlockers=result.remainingInheritedBlockerPCs.size();st.newlyRootedBlockers=result.newlyRootedBlockerPCs.size();st.refinedNewlyRootedBlockers=result.refinedNewlyRootedBlockerPCs.size();st.remainingNewlyRootedBlockers=result.remainingNewlyRootedBlockerPCs.size();st.totalRemainingBlockers=st.remainingInheritedBlockers+st.remainingNewlyRootedBlockers;st.closureProvenanceRecords=memoryAliasClosureProvenance_.size();
    bool in=false;for(std::size_t i=0;i<memoryAliasClosureBytes_.size();++i){const bool u=memoryAliasClosureBytes_[i].primary==RomClosurePrimary::Unresolved;if(u){++st.unresolvedAfterMemoryAlias;if(!in){++st.residualSpansAfterMemoryAlias;in=true;}}else in=false;if(i<baseline.size()&&baseline[i].primary==RomClosurePrimary::Unresolved&&!u){if(memoryAliasClosureBytes_[i].staticExactDataUse)++st.newlyExactExplainedBytes;else ++st.newlyBoundedExplainedBytes;}}st.newlyExplainedBytes=st.newlyExactExplainedBytes+st.newlyBoundedExplainedBytes;
}

std::vector<std::string> Decompiler::memoryAliasWriterProofLines() const{std::vector<std::string>o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper memory-alias analysis context-sensitive writer address proofs");for(const auto&p:memoryAliasWriterProofs_)if(!p.accepted)o.push_back("wproof#"+std::to_string(p.id)+" pc=$"+h20(p.pc)+" "+p.operand+" class="+RootContextAnalysis::domainClassText(p.domainClass)+" domain="+domain20(p.aggregateAddress)+" source-invariant="+(p.sourceInvariant?"yes":"no")+" contexts="+ids20(p.contextRecordIds,"wctx#")+" calls="+pcs20(p.callSites)+" proof="+pcs20(p.proofPCs)+" :: "+p.note);return o;}
std::vector<std::string> Decompiler::memoryAliasWriterAliasLines() const{std::vector<std::string>o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper memory-alias analysis writer / alias inventories");o.push_back("writer-proofs="+std::to_string(stats_.memoryAlias.writerProofs)+" accepted="+std::to_string(stats_.memoryAlias.acceptedWriterProofs)+" unresolved="+std::to_string(stats_.memoryAlias.unresolvedWriterProofs)+" inventories="+std::to_string(stats_.memoryAlias.writerAliasInventories)+" complete="+std::to_string(stats_.memoryAlias.completeWriterAliasInventories)+" caller-inventory="+(stats_.memoryAlias.writerCallerInventoryComplete?"complete":"incomplete"));for(const auto&r:memoryAliasWriterAliases_)o.push_back("alias#"+std::to_string(r.id)+" [$"+h20(r.start)+",$"+h20(static_cast<std::uint16_t>(r.end-1))+"] complete="+(r.complete?"yes":"no")+" direct="+pcs20(r.directWriterPCs)+" indirect="+pcs20(r.indirectWriterPCs)+" unknown-alias="+pcs20(r.unknownAliasWriterPCs)+" writer-proofs="+ids20(r.indirectWriterProofIds,"wproof#")+" :: "+r.note);return o;}
std::vector<std::string> Decompiler::memoryAliasAddressProofLines() const{std::vector<std::string>o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper memory-alias analysis memory-state / pointer lifecycle proofs");o.push_back("proofs="+std::to_string(stats_.memoryAlias.addressProofs)+" accepted="+std::to_string(stats_.memoryAlias.acceptedAddressProofs)+" inherited-refined="+std::to_string(stats_.memoryAlias.refinedInheritedBlockers)+" new-root-refined="+std::to_string(stats_.memoryAlias.refinedNewlyRootedBlockers)+" remaining="+std::to_string(stats_.memoryAlias.totalRemainingBlockers));for(const auto&p:memoryAliasAddressProofs_)o.push_back("proof#"+std::to_string(p.id)+" pc=$"+h20(p.pc)+" kind="+MemoryAliasAnalysis::proofKindText(p.kind)+" class="+RootContextAnalysis::domainClassText(p.domainClass)+" domain="+domain20(p.address)+" accepted="+(p.accepted?"yes":"no")+" writers="+ids20(p.writerAliasRecordIds,"alias#")+" proof="+pcs20(p.proofPCs)+" :: "+p.note);return o;}
std::vector<std::string> Decompiler::memoryAliasClosureLines() const{std::vector<std::string>o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper memory-alias analysis residual consumer closure");o.push_back("new="+std::to_string(stats_.memoryAlias.newlyExplainedBytes)+" exact="+std::to_string(stats_.memoryAlias.newlyExactExplainedBytes)+" bounded="+std::to_string(stats_.memoryAlias.newlyBoundedExplainedBytes)+" residual="+std::to_string(stats_.memoryAlias.unresolvedAfterMemoryAlias)+" spans="+std::to_string(stats_.memoryAlias.residualSpansAfterMemoryAlias));for(const auto&p:memoryAliasClosureProvenance_)o.push_back("$"+h20(p.address)+" exact="+(p.exact?"yes":"no")+" bounded="+(p.bounded?"yes":"no")+" proofs="+ids20(p.addressProofIds,"proof#")+" writers="+ids20(p.writerAliasRecordIds,"alias#")+" source="+pcs20(p.sourcePCs)+" :: "+p.note);return o;}

} // namespace pacripper
