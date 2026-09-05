// PacRipper indirect-address analysis bounded indirect ROM consumer/address-range proof
// Created by Jacob Hodgkins

#include "Decompiler.h"

#include <algorithm>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>

namespace pacripper {
namespace {
std::string indirectHex16(std::uint16_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(4)<<std::setfill('0')<<(unsigned)v;return o.str();}
std::string indirectPcSet(const std::set<std::uint16_t>&s){std::ostringstream o;o<<"{";std::size_t n=0;for(auto v:s){if(n++)o<<",";o<<"$"<<indirectHex16(v);}o<<"}";return o.str();}
std::string indirectIdSet(const std::set<std::size_t>&s,const std::string&p=""){std::ostringstream o;o<<"{";std::size_t n=0;for(auto v:s){if(n++)o<<",";o<<p<<v;}o<<"}";return o.str();}
std::string indirectValuesText(const AddressLatticeValue&v){if(v.values.empty())return"{}";std::ostringstream o;o<<"{";std::size_t n=0;for(auto x:v.values){if(n++)o<<",";if(n>24){o<<"...";break;}o<<"$"<<indirectHex16(x);}o<<"}";return o.str();}
AddressFlowEdgeKind convertEdge15(CfgEdgeKind k){switch(k){case CfgEdgeKind::BranchTaken:return AddressFlowEdgeKind::BranchTaken;case CfgEdgeKind::BranchNotTaken:return AddressFlowEdgeKind::BranchNotTaken;case CfgEdgeKind::Call:return AddressFlowEdgeKind::Call;case CfgEdgeKind::Restart:return AddressFlowEdgeKind::Restart;case CfgEdgeKind::Dispatch:return AddressFlowEdgeKind::Dispatch;case CfgEdgeKind::Return:return AddressFlowEdgeKind::Return;case CfgEdgeKind::Indirect:case CfgEdgeKind::DynamicIndirect:case CfgEdgeKind::DynamicReturn:return AddressFlowEdgeKind::Indirect;case CfgEdgeKind::Fallthrough:return AddressFlowEdgeKind::Structural;}return AddressFlowEdgeKind::Structural;}
}

void Decompiler::buildIndirectAddress(){
    indirectMemoryAccesses_.clear();indirectRomConsumerProofs_.clear();indirectAddressClosureProvenance_.clear();indirectAddressClosureBytes_.clear();indirectAddressResidualAudit_.clear();indirectAddressResidualPriorityV2_.clear();stats_.indirectAddress={};if(!analyzer_)return;

    std::vector<AddressBlockInput> addressBlocks;addressBlocks.reserve(blocks_.size());std::map<std::uint16_t,std::set<std::uint16_t>> owners;
    for(const auto&bk:blocks_){AddressBlockInput b;b.start=bk.first;b.instructions=bk.second.instructions;for(const auto&e:bk.second.outgoing){AddressFlowEdgeInput x;x.to=e.to;x.kind=convertEdge15(e.kind);b.outgoing.push_back(x);}addressBlocks.push_back(b);for(auto pc:bk.second.instructions)owners[pc]=bk.second.functionOwners;}
    std::set<std::uint16_t> roots;for(const auto&fk:functions_)if(fk.second.callers.empty()||fk.first==0||fk.first==8||fk.first==0x10||fk.first==0x18||fk.first==0x20||fk.first==0x28||fk.first==0x30||fk.first==0x38)if(blocks_.count(fk.first))roots.insert(fk.first);for(const auto&bk:blocks_)if(bk.second.incoming.empty()&&bk.second.functionOwners.empty())roots.insert(bk.first);if(roots.empty()&&!blocks_.empty())roots.insert(blocks_.begin()->first);

    indirectMemoryAccesses_=IndirectAddressAnalysis::analyze(analyzer_->instructions(),addressBlocks,roots,owners,functionRegisterSummaries_,defUseResult_,callBindings_,analyzer_->program());
    std::vector<RomConsumerRecord> indirectAddressConsumers;indirectRomConsumerProofs_=IndirectAddressAnalysis::synthesizeRomConsumers(indirectMemoryAccesses_,analyzer_->program().size(),indirectAddressConsumers);
    stats_.indirectAddress.address=IndirectAddressAnalysis::stats(indirectMemoryAccesses_,indirectRomConsumerProofs_);

    const auto&baseline=!residualClosureClosureBytes_.empty()?residualClosureClosureBytes_:(defUseClosureBytes_.empty()?romClosureBytes_:defUseClosureBytes_);
    indirectAddressClosureProvenance_=IndirectAddressAnalysis::applyClosureOverlay(baseline,indirectRomConsumerProofs_,indirectAddressClosureBytes_);

    std::vector<RomConsumerRecord> allConsumers=romConsumers_;allConsumers.insert(allConsumers.end(),defUseRomConsumers_.begin(),defUseRomConsumers_.end());allConsumers.insert(allConsumers.end(),indirectAddressConsumers.begin(),indirectAddressConsumers.end());
    const auto&objects=!residualClosureRomObjects_.empty()?residualClosureRomObjects_:romObjects_;indirectAddressResidualAudit_=ResidualResearch::auditResidualSpans(indirectAddressClosureBytes_,objects,allConsumers,dormantCodeSeeds_,analyzer_->program());indirectAddressResidualPriorityV2_=ResidualResearch::prioritizeV2(indirectAddressResidualAudit_,indirectAddressClosureBytes_,allConsumers,128);
    // New indirect-address activity is additive research priority only. It never mutates
    // closure or an audit reason.
    for(auto&pr:indirectAddressResidualPriorityV2_){std::size_t near=0;for(const auto&a:indirectMemoryAccesses_)for(auto v:a.address.values){const int d=v<pr.start?static_cast<int>(pr.start-v):v>=pr.end?static_cast<int>(v-pr.end+1):0;if(d<=16){++near;break;}}if(near){pr.score+=static_cast<int>(std::min<std::size_t>(near,5)*3);pr.reason+="; indirect-address analysis nearby static indirect-address activity="+std::to_string(near)+" (priority only)";}}

    std::size_t unresolved=0,newExact=0,newBounded=0;for(std::size_t i=0;i<indirectAddressClosureBytes_.size();++i){if(indirectAddressClosureBytes_[i].primary==RomClosurePrimary::Unresolved)++unresolved;if(i<baseline.size()&&baseline[i].primary==RomClosurePrimary::Unresolved&&indirectAddressClosureBytes_[i].primary!=RomClosurePrimary::Unresolved){if(indirectAddressClosureBytes_[i].staticExactDataUse)++newExact;else if(indirectAddressClosureBytes_[i].boundedConsumer)++newBounded;}}
    stats_.indirectAddress.newlyExactExplainedBytes=newExact;stats_.indirectAddress.newlyBoundedExplainedBytes=newBounded;stats_.indirectAddress.newlyExplainedBytes=newExact+newBounded;stats_.indirectAddress.unresolvedAfterIndirectAddress=unresolved;stats_.indirectAddress.closureProvenanceRecords=indirectAddressClosureProvenance_.size();stats_.indirectAddress.residualAuditSpans=indirectAddressResidualAudit_.size();for(const auto&r:indirectAddressResidualAudit_)stats_.indirectAddress.auditedResidualBytes+=r.length;
}

std::vector<std::string> Decompiler::indirectMemoryLines() const{
    std::vector<std::string>o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper indirect-address analysis indirect-memory address expressions");o.push_back("Only static machine proof contributes to address sets. Runtime min/max is never promoted into a bound.");o.push_back("accesses="+std::to_string(stats_.indirectAddress.address.indirectAccesses)+" exact="+std::to_string(stats_.indirectAddress.address.exactAddresses)+" finite-set="+std::to_string(stats_.indirectAddress.address.finiteSetAddresses)+" ranges="+std::to_string(stats_.indirectAddress.address.rangeAddresses)+" ambiguous="+std::to_string(stats_.indirectAddress.address.ambiguousAddresses)+" unknown="+std::to_string(stats_.indirectAddress.address.unknownAddresses));o.push_back("");for(const auto&r:indirectMemoryAccesses_){o.push_back("access#"+std::to_string(r.id)+" $"+indirectHex16(r.pc)+" "+IndirectAddressAnalysis::directionText(r.direction)+" "+r.operand+" via "+r.addressRegister+(r.displacement?((r.displacement>0?"+":"")+std::to_string(r.displacement)):"")+" => "+IndirectAddressAnalysis::kindText(r.address.kind)+" "+indirectValuesText(r.address));o.push_back("  defs="+indirectIdSet(r.address.originDefinitionIds,"def#")+" provenance="+indirectPcSet(r.address.provenancePCs)+" ram-origin="+indirectPcSet(r.address.ramOriginAddresses)+" calls="+indirectPcSet(r.address.callEvidencePCs)+(r.address.wraparound?" wraparound=yes":"")+(r.address.hasUnknownAlternative?" unknown-alt=yes":""));o.push_back("  "+r.note);}return o;
}

std::vector<std::string> Decompiler::addressRangeLines() const{
    std::vector<std::string>o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper indirect-address analysis address lattice / finite range view");o.push_back("Ranges are finite static alternatives; wraparound and unknown alternatives stay explicit.");o.push_back("");for(const auto&r:indirectMemoryAccesses_)if(r.address.kind!=AddressValueKind::Unknown){std::ostringstream s;s<<"access#"<<r.id<<" @$"<<indirectHex16(r.pc)<<" "<<IndirectAddressAnalysis::kindText(r.address.kind)<<" ";if(r.address.kind==AddressValueKind::Exact)s<<"$"<<indirectHex16(*r.address.values.begin());else{s<<"$"<<indirectHex16(r.address.rangeStart)<<"..$"<<indirectHex16(r.address.rangeEnd);if(r.address.stride)s<<" stride="<<r.address.stride;s<<" members="<<r.address.values.size();}if(r.address.hasUnknownAlternative)s<<" +unknown";if(r.address.wraparound)s<<" [wraparound]";o.push_back(s.str());o.push_back("  chain="+r.arithmeticChain+" defs="+indirectIdSet(r.address.originDefinitionIds,"def#"));}return o;
}

std::vector<std::string> Decompiler::indirectRomConsumerLines() const{
    std::vector<std::string>o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper indirect-address analysis synthesized indirect ROM consumers");o.push_back("Singleton exact addresses may create exact proof. Multi-address finite alternatives create singleton bounded evidence only; mixed ROM/non-ROM or unknown alternatives create no closure.");o.push_back("accepted="+std::to_string(stats_.indirectAddress.address.acceptedRomConsumers)+" exact="+std::to_string(stats_.indirectAddress.address.exactRomConsumers)+" bounded="+std::to_string(stats_.indirectAddress.address.boundedRomConsumers)+" rejected-mixed="+std::to_string(stats_.indirectAddress.address.rejectedMixedAddressConsumers));o.push_back("");for(const auto&r:indirectRomConsumerProofs_){o.push_back("proof#"+std::to_string(r.id)+" access#"+std::to_string(r.accessId)+" pc=$"+indirectHex16(r.pc)+" "+(r.accepted?(r.exact?"EXACT":"BOUNDED"):"DIAGNOSTIC")+" values="+indirectPcSet(r.exactAddressSet));o.push_back("  defs="+indirectIdSet(r.originDefinitionIds,"def#")+" provenance="+indirectPcSet(r.provenancePCs)+" ram-origin="+indirectPcSet(r.ramOriginAddresses)+" calls="+indirectPcSet(r.callEvidencePCs));o.push_back("  "+r.note);}return o;
}

std::vector<std::string> Decompiler::indirectAddressClosureLines() const{
    std::vector<std::string>o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper indirect-address analysis closure delta / provenance");o.push_back("Every newly explained byte below is relative to the verified residual-closure analysis overlay and retains exact access/value provenance.");o.push_back("new="+std::to_string(stats_.indirectAddress.newlyExplainedBytes)+" exact="+std::to_string(stats_.indirectAddress.newlyExactExplainedBytes)+" bounded="+std::to_string(stats_.indirectAddress.newlyBoundedExplainedBytes)+" residual="+std::to_string(stats_.indirectAddress.unresolvedAfterIndirectAddress)+" audit-spans="+std::to_string(stats_.indirectAddress.residualAuditSpans));o.push_back("");for(const auto&r:indirectAddressClosureProvenance_)o.push_back("$"+indirectHex16(r.address)+" "+(r.exact?"exact":"bounded")+" proofs="+indirectIdSet(r.consumerProofIds,"proof#")+" accesses="+indirectIdSet(r.accessIds,"access#")+" pcs="+indirectPcSet(r.accessPCs)+" defs="+indirectIdSet(r.originDefinitionIds,"def#")+" provenance="+indirectPcSet(r.provenancePCs));if(indirectAddressClosureProvenance_.empty())o.push_back("No indirect-address analysis closure delta on this corpus; the stronger address proof still remains available for research and diagnostics.");return o;
}

} // namespace pacripper
