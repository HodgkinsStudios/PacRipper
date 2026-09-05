// PacRipper residual-closure analysis residual closure audit + neutral object/state roles
// Created by Jacob Hodgkins

#include "Decompiler.h"

#include <algorithm>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>

namespace pacripper {
namespace {
std::string residualHex16(std::uint16_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(4)<<std::setfill('0')<<(unsigned)v;return o.str();}
std::string residualPcSet(const std::set<std::uint16_t>&s){std::ostringstream o;o<<"{";std::size_t n=0;for(auto v:s){if(n++)o<<",";o<<"$"<<residualHex16(v);}o<<"}";return o.str();}
std::string residualIdSet(const std::set<std::size_t>&s,const std::string&p=""){std::ostringstream o;o<<"{";std::size_t n=0;for(auto v:s){if(n++)o<<",";o<<p<<v;}o<<"}";return o.str();}
std::string residualDevicesText(const std::set<BoardDeviceKind>&s){std::ostringstream o;o<<"{";std::size_t n=0;for(auto d:s){if(n++)o<<",";o<<HardwareSemantics::deviceText(d);}o<<"}";return o.str();}
std::string residualAuditReasons(const std::set<ResidualAuditReason>&s){std::ostringstream o;std::size_t n=0;for(auto r:s){if(n++)o<<",";o<<ResidualResearch::auditReasonText(r);}return o.str();}
bool residual14(const std::vector<RomByteClosureRecord>& c,std::uint16_t a){return a<c.size()&&c[a].primary==RomClosurePrimary::Unresolved;}
}

void Decompiler::buildResidualClosure(){
    dormantCodeSeeds_.clear();dormantCodeDiscoveries_.clear();romExtentRefinements_.clear();residualAudit_.clear();objectRoles_.clear();stateXrefs_.clear();residualPriorityV2_.clear();residualClosureClosureBytes_.clear();residualClosureRomObjects_.clear();stats_.residualClosure={};if(!analyzer_)return;
    residualClosureClosureBytes_=defUseClosureBytes_.empty()?romClosureBytes_:defUseClosureBytes_;residualClosureRomObjects_=romObjects_;
    for(auto&b:residualClosureClosureBytes_)b.primary=RomClosure::classify(b);
    const std::size_t before=stats_.structuredExpression.unresolvedAfterStructuredExpression;

    // Build only defensible dormant-code entry seeds. Existing static control targets are
    // included only when they currently land in residual bytes; trace-only targets remain
    // explicitly dynamic and cannot create static proof.
    std::set<std::tuple<std::uint16_t,DormantCodeSeedKind,bool>> seenSeeds;
    auto addSeed=[&](std::uint16_t address,DormantCodeSeedKind kind,bool staticProof,bool dynamicOnly,const std::set<std::uint16_t>&src,const std::string&note){
        if(address>=residualClosureClosureBytes_.size()||!residual14(residualClosureClosureBytes_,address))return;
        const auto key=std::make_tuple(address,kind,staticProof);
        if(!seenSeeds.insert(key).second)return;
        DormantCodeSeedRecord s;s.id=dormantCodeSeeds_.size();s.address=address;s.kind=kind;s.staticProof=staticProof;s.dynamicOnly=dynamicOnly;s.sourcePCs=src;s.note=note;dormantCodeSeeds_.push_back(s);
    };
    for(const auto&x:analyzer_->codeXrefs()){std::set<std::uint16_t> src(x.second.begin(),x.second.end());addSeed(x.first,DormantCodeSeedKind::ExistingControlTarget,true,false,src,"existing statically proven control target into residual ROM");}
    // A pointer-table entry is a code seed only when a statically proven consumer uses the
    // table value as an indirect CALL/JP target. Plain RST18 data-pointer tables are not promoted.
    std::map<std::uint16_t,const Instruction*> ins;for(const auto&kv:analyzer_->instructions())ins[kv.first]=&kv.second;
    for(const auto&link:romPointerLinks_){auto oi=std::find_if(romObjects_.begin(),romObjects_.end(),[&](const RomObjectRecord&o){return o.id==link.tableObjectId;});if(oi==romObjects_.end())continue;bool codeUse=false;std::set<std::uint16_t> src;for(auto pc:oi->consumerPCs){auto ii=ins.find(pc);if(ii!=ins.end()&&ii->second->indirect&&(ii->second->flow==FlowKind::Call||ii->second->flow==FlowKind::Jump||ii->second->flow==FlowKind::RelativeJump)){codeUse=true;src.insert(pc);}}if(codeUse)addSeed(link.target,DormantCodeSeedKind::PointerTableCodeUse,true,false,src,"decoded pointer-table entry consumed by a proven indirect control-flow operation");}
    // Imported trace flow destinations are useful dormant-code candidates, but are kept
    // dynamic-only unless another static seed above proves the same address.
    for(const auto&from:analyzer_->dynamicFlowEdges())for(const auto&to:from.second)addSeed(to.first,DormantCodeSeedKind::TraceObservedPc,false,true,{from.first},"trace-observed instruction destination; retained as dynamic-only candidate");

    dormantCodeDiscoveries_=ResidualResearch::discoverDormantCode(analyzer_->program(),residualClosureClosureBytes_,dormantCodeSeeds_);
    for(const auto&d:dormantCodeDiscoveries_)if(d.accepted&&d.staticProof)for(auto a:d.byteAddresses)if(a<residualClosureClosureBytes_.size()){residualClosureClosureBytes_[a].code=true;residualClosureClosureBytes_[a].consumerPCs.insert(d.provenancePCs.begin(),d.provenancePCs.end());}

    std::vector<RomConsumerRecord> allConsumers=romConsumers_;allConsumers.insert(allConsumers.end(),defUseRomConsumers_.begin(),defUseRomConsumers_.end());
    romExtentRefinements_=ResidualResearch::refineObjectExtents(residualClosureRomObjects_,allConsumers,tableSchemas_,residualClosureClosureBytes_);
    // Apply accepted refinements only to the residual-closure analysis overlay. Earlier object/closure records remain verified.
    for(const auto&r:romExtentRefinements_)if(r.accepted){auto oi=std::find_if(residualClosureRomObjects_.begin(),residualClosureRomObjects_.end(),[&](const RomObjectRecord&o){return o.id==r.objectId;});if(oi!=residualClosureRomObjects_.end()){oi->start=r.newStart;oi->end=r.newEnd;oi->exactBoundary=oi->exactBoundary||r.exactClosure;oi->boundedBoundary=oi->boundedBoundary||r.boundedClosure;oi->consumerPCs.insert(r.sourcePCs.begin(),r.sourcePCs.end());}
        const std::uint16_t a0=std::min(r.oldStart,r.newStart),a1=std::max(r.oldEnd,r.newEnd);for(std::size_t a=a0;a<a1&&a<residualClosureClosureBytes_.size();++a){const bool already=a>=r.oldStart&&a<r.oldEnd;if(already)continue;auto&b=residualClosureClosureBytes_[a];if(r.exactClosure)b.staticExactDataUse=true;if(r.boundedClosure)b.boundedConsumer=true;b.consumerPCs.insert(r.sourcePCs.begin(),r.sourcePCs.end());}}
    for(auto&b:residualClosureClosureBytes_)b.primary=RomClosure::classify(b);

    residualAudit_=ResidualResearch::auditResidualSpans(residualClosureClosureBytes_,residualClosureRomObjects_,allConsumers,dormantCodeSeeds_,analyzer_->program());
    residualPriorityV2_=ResidualResearch::prioritizeV2(residualAudit_,residualClosureClosureBytes_,allConsumers,128);

    std::map<std::uint16_t,std::set<std::uint16_t>> pcOwners;for(const auto&bk:blocks_)for(auto pc:bk.second.instructions)pcOwners[pc].insert(bk.second.functionOwners.begin(),bk.second.functionOwners.end());
    stateXrefs_=ObjectStateRoles::buildStateXrefs(ramObjects_,ramShapes_,tableSchemas_,memoryXrefs_,typeEvidence_,routineRoles_,routineNavigation_,analyzer_->ramUsage());
    objectRoles_=ObjectStateRoles::inferRoles(residualClosureRomObjects_,ramObjects_,ramShapes_,tableSchemas_,typeEvidence_,defUseResult_,indexedExpressions_,analyzer_->instructions(),stateXrefs_,pcOwners,routineRoles_,analyzer_->symbols());

    stats_.residualClosure.residual=ResidualResearch::stats(residualAudit_,dormantCodeSeeds_,dormantCodeDiscoveries_,romExtentRefinements_,residualPriorityV2_);stats_.residualClosure.objectState=ObjectStateRoles::stats(objectRoles_,stateXrefs_);
    std::size_t unresolved=0,newExact=0,newBounded=0;const auto&baseline=defUseClosureBytes_.empty()?romClosureBytes_:defUseClosureBytes_;for(std::size_t i=0;i<residualClosureClosureBytes_.size();++i){if(residualClosureClosureBytes_[i].primary==RomClosurePrimary::Unresolved)++unresolved;if(i<baseline.size()&&baseline[i].primary==RomClosurePrimary::Unresolved&&residualClosureClosureBytes_[i].primary!=RomClosurePrimary::Unresolved){if(residualClosureClosureBytes_[i].code||residualClosureClosureBytes_[i].hardData||residualClosureClosureBytes_[i].staticExactDataUse)++newExact;else if(residualClosureClosureBytes_[i].boundedConsumer)++newBounded;}}
    stats_.residualClosure.unresolvedAfterResidualClosure=unresolved;stats_.residualClosure.newlyExplainedBytes=before>unresolved?before-unresolved:0;stats_.residualClosure.newlyExactExplainedBytes=newExact;stats_.residualClosure.newlyBoundedExplainedBytes=newBounded;
}

std::vector<std::string> Decompiler::residualAuditLines() const{
    std::vector<std::string>o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper residual-closure analysis residual ROM closure audit");o.push_back("Every remaining unresolved span receives explicit audit reasons. Audit categories, repetition, priority and dynamic observation never close bytes by themselves.");o.push_back("spans="+std::to_string(stats_.residualClosure.residual.auditSpans)+" unresolved-bytes="+std::to_string(stats_.residualClosure.residual.auditedUnresolvedBytes)+" dormant-seeds="+std::to_string(stats_.residualClosure.residual.dormantSeeds)+" accepted-dormant="+std::to_string(stats_.residualClosure.residual.acceptedDormantDiscoveries)+" extent-refinements="+std::to_string(stats_.residualClosure.residual.extentRefinements));o.push_back("closure delta: exact="+std::to_string(stats_.residualClosure.newlyExactExplainedBytes)+" bounded="+std::to_string(stats_.residualClosure.newlyBoundedExplainedBytes)+" residual="+std::to_string(stats_.residualClosure.unresolvedAfterResidualClosure));o.push_back("");
    for(const auto&r:residualAudit_){o.push_back("audit#"+std::to_string(r.id)+" $"+residualHex16(r.start)+"-$"+residualHex16(static_cast<std::uint16_t>(r.end-1))+" len="+std::to_string(r.length)+" reasons={"+residualAuditReasons(r.reasons)+"}");o.push_back("  objects="+residualIdSet(r.nearbyObjectIds,"obj#")+" consumers="+residualPcSet(r.nearbyConsumerPCs)+" seeds="+residualIdSet(r.dormantSeedIds,"seed#")+" static-evidence="+(r.staticEvidence?"yes":"no")+" dynamic-evidence="+(r.dynamicEvidence?"yes":"no"));o.push_back("  "+r.note);}if(!dormantCodeDiscoveries_.empty()){o.push_back("");o.push_back("Seeded dormant-code discoveries:");for(const auto&d:dormantCodeDiscoveries_)o.push_back("  discovery#"+std::to_string(d.id)+" seed#"+std::to_string(d.seedId)+" entry=$"+residualHex16(d.entry)+" "+ResidualResearch::seedKindText(d.seedKind)+" accepted="+(d.accepted?"yes":"no")+" bytes="+std::to_string(d.byteAddresses.size())+" hard-data-conflict="+(d.hardDataConflict?"yes":"no")+" -- "+d.note);}if(!romExtentRefinements_.empty()){o.push_back("");o.push_back("Finite ROM object extent refinements:");for(const auto&r:romExtentRefinements_)o.push_back("  extent#"+std::to_string(r.id)+" obj#"+std::to_string(r.objectId)+" $"+residualHex16(r.oldStart)+"-$"+residualHex16(static_cast<std::uint16_t>(r.oldEnd-1))+" -> $"+residualHex16(r.newStart)+"-$"+residualHex16(static_cast<std::uint16_t>(r.newEnd-1))+" proof="+ResidualResearch::extentProofText(r.proofKind)+" exact="+(r.exactClosure?"yes":"no")+" bounded="+(r.boundedClosure?"yes":"no")+" pcs="+residualPcSet(r.sourcePCs));}return o;
}

std::vector<std::string> Decompiler::objectRoleLines() const{
    std::vector<std::string>o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper residual-closure analysis neutral semantic ROM/RAM/state roles");o.push_back("Automatic roles are disposable machine-use summaries. Researcher names/comments/types are displayed separately and never become proof.");o.push_back("records="+std::to_string(stats_.residualClosure.objectState.roleRecords)+" rom="+std::to_string(stats_.residualClosure.objectState.romRoleRecords)+" ram/state="+std::to_string(stats_.residualClosure.objectState.ramRoleRecords)+" conflicting-alternatives="+std::to_string(stats_.residualClosure.objectState.conflictingAlternatives));o.push_back("");for(const auto&r:objectRoles_){o.push_back("role#"+std::to_string(r.id)+" "+ObjectStateRoles::targetKindText(r.targetKind)+"#"+std::to_string(r.targetId)+" $"+residualHex16(r.start)+"-$"+residualHex16(static_cast<std::uint16_t>(r.end-1))+" => "+ObjectStateRoles::roleText(r.role)+" [static"+(r.exact?", exact]":", alternative]"));o.push_back("  pcs="+residualPcSet(r.sourcePCs)+" type-evidence="+residualIdSet(r.typeEvidenceIds,"type#")+" schemas="+residualIdSet(r.schemaIds,"schema#")+" routines="+residualPcSet(r.routineEntries)+" devices="+residualDevicesText(r.correlatedDevices));if(!r.alternativeRoleIds.empty())o.push_back("  alternatives="+residualIdSet(r.alternativeRoleIds,"role#")+(r.conflictingRoleIds.empty()?"":" conflicts="+residualIdSet(r.conflictingRoleIds,"role#")));o.push_back("  "+r.evidenceSummary);if(!r.researcherName.empty()||!r.researcherComment.empty()||!r.researcherTypeHint.empty())o.push_back("  researcher-annotation (not proof): name='"+r.researcherName+"' type='"+r.researcherTypeHint+"' comment='"+r.researcherComment+"'");}return o;
}

std::vector<std::string> Decompiler::stateXrefLines() const{
    std::vector<std::string>o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper residual-closure analysis state transition / xref summaries");o.push_back("Exact static addresses are definite; bounded addresses are possible; dynamic corroboration and hardware correlations remain separate from semantic naming.");o.push_back("records="+std::to_string(stats_.residualClosure.objectState.stateXrefs)+" definite-reader="+std::to_string(stats_.residualClosure.objectState.stateXrefsWithDefiniteReaders)+" definite-writer="+std::to_string(stats_.residualClosure.objectState.stateXrefsWithDefiniteWriters)+" dynamic-corroborated="+std::to_string(stats_.residualClosure.objectState.dynamicallyCorroboratedStateXrefs));o.push_back("");for(const auto&r:stateXrefs_){o.push_back("statexref#"+std::to_string(r.id)+" "+ObjectStateRoles::stateXrefTargetText(r.targetKind)+"#"+std::to_string(r.targetId)+" $"+residualHex16(r.start)+"-$"+residualHex16(static_cast<std::uint16_t>(r.end-1)));o.push_back("  readers definite="+residualPcSet(r.definiteReaderPCs)+" possible="+residualPcSet(r.possibleReaderPCs)+" routines(def/poss)="+residualPcSet(r.definiteReaderRoutines)+" / "+residualPcSet(r.possibleReaderRoutines));o.push_back("  writers definite="+residualPcSet(r.definiteWriterPCs)+" possible="+residualPcSet(r.possibleWriterPCs)+" routines(def/poss)="+residualPcSet(r.definiteWriterRoutines)+" / "+residualPcSet(r.possibleWriterRoutines));o.push_back("  write-origins defs="+residualIdSet(r.writeDefinitionIds,"def#")+" pcs="+residualPcSet(r.writeValueOriginPCs)+" type-evidence="+residualIdSet(r.typeEvidenceIds,"type#")+" hardware-correlations="+residualDevicesText(r.hardwareCorrelations)+" call-neighbors="+residualPcSet(r.callPathNeighbors));if(!r.masks.empty()){std::set<std::uint16_t> m=r.masks;o.push_back("  masks="+residualPcSet(m));}if(!r.ranges.empty()){std::ostringstream s;s<<"  ranges={";std::size_t n=0;for(const auto&x:r.ranges){if(n++)s<<",";s<<x.first<<".."<<x.second;}s<<"}";o.push_back(s.str());}if(r.dynamicCorroborated)o.push_back("  dynamic-only/corroborating readers="+residualPcSet(r.dynamicReaderPCs)+" writers="+residualPcSet(r.dynamicWriterPCs));o.push_back("  "+r.note);}return o;
}

std::vector<std::string> Decompiler::residualPriorityV2Lines() const{
    std::vector<std::string>o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper residual-closure analysis residual priority v2");o.push_back("Scores order research attention only. They never alter byte closure, object extents, code proof or semantic roles.");o.push_back("");for(const auto&r:residualPriorityV2_)o.push_back("audit#"+std::to_string(r.auditId)+" $"+residualHex16(r.start)+"-$"+residualHex16(static_cast<std::uint16_t>(r.end-1))+" len="+std::to_string(r.length)+" score="+std::to_string(r.score)+"  "+r.reason);return o;
}

} // namespace pacripper
