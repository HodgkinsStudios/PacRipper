// PacRipper semantic-lift engine whole-ROM provenance + recompilable semantic-lift foundation
// Created by Jacob Hodgkins

#include "Decompiler.h"

#include <iomanip>
#include <sstream>

namespace pacripper {
namespace {
std::string h26(std::uint16_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(4)<<std::setfill('0')<<(unsigned)v;return o.str();}
std::string h826(std::uint8_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(2)<<std::setfill('0')<<(unsigned)v;return o.str();}
std::string bytes26(const std::vector<std::uint8_t>&v){std::ostringstream o;for(std::size_t i=0;i<v.size();++i){if(i)o<<' ';o<<h826(v[i]);}return o.str();}
}

void Decompiler::buildSemanticLift(){
    semanticLiftProvenanceLedger_.clear();
    semanticLiftLiftedOperations_.clear();
    semanticLiftLiftedBlocks_.clear();
    semanticLiftDifferentialRecords_.clear();
    stats_.semanticLift={};
    if(!analyzer_)return;

    // Only actual decoded analyzer instructions can be semantic-lift operations.
    // system-root reachability analysis system roots are intersected with that instruction inventory so the
    // lift denominator is stable and cannot count inline/data reachability records.
    std::set<std::uint16_t> systemRootPCs;
    for(const auto&r:systemRootReachability_)systemRootPCs.insert(r.pc);
    std::set<std::uint16_t> rootedInstructionPCs;
    for(const auto&kv:analyzer_->instructions()){
        if((analyzer_->hasStaticInstructionProof(kv.first)&&!analyzer_->isTraceDiscoveredInstruction(kv.first))||systemRootPCs.count(kv.first))
            rootedInstructionPCs.insert(kv.first);
    }

    std::vector<SemanticBlockInput> blockInputs;
    blockInputs.reserve(blocks_.size());
    for(const auto&kv:blocks_){
        SemanticBlockInput b;b.start=kv.second.start;b.end=kv.second.end;
        for(auto pc:kv.second.instructions)if(rootedInstructionPCs.count(pc))b.instructionPCs.push_back(pc);
        if(!b.instructionPCs.empty())blockInputs.push_back(std::move(b));
    }

    std::vector<std::uint16_t> fallthrough(65536,0);
    for(const auto&kv:analyzer_->instructions())fallthrough[kv.first]=continuationAfter(kv.second);

    semanticLiftProvenanceLedger_=SemanticLiftEngine::buildProvenanceLedger(
        *analyzer_,im2VectorClosureBytes_,residualExtentClosureProvenance_,im2VectorClosureProvenance_,
        im2VectorVectorDomainProofs_,rootedInstructionPCs,stats_.semanticLift);
    SemanticLiftEngine::lowerBlocks(*analyzer_,blockInputs,fallthrough,
        semanticLiftLiftedOperations_,semanticLiftLiftedBlocks_,stats_.semanticLift);
    semanticLiftDifferentialRecords_=SemanticLiftEngine::verifyBlocks(*analyzer_,blockInputs,
        semanticLiftLiftedOperations_,semanticLiftLiftedBlocks_,stats_.semanticLift,3);
    stats_.semanticLift.deterministicSourceMap=true;
}

std::vector<std::string> Decompiler::semanticLiftProvenanceLines() const{
    std::vector<std::string> out;
    std::ostringstream s;s<<"semantic-lift engine whole-ROM provenance: records="<<stats_.semanticLift.provenanceRecords
        <<" resolved="<<stats_.semanticLift.resolvedRomBytes<<" unresolved="<<stats_.semanticLift.unresolvedRomBytes
        <<" incomplete_provenance="<<stats_.semanticLift.incompleteProvenanceBytes
        <<" frozen_100_percent="<<(stats_.semanticLift.romByteAccountingFrozen?"yes":"no")
        <<" complete="<<(stats_.semanticLift.wholeRomProvenanceComplete?"yes":"no");out.push_back(s.str());
    for(const auto&r:semanticLiftProvenanceLedger_)if(!r.provenanceComplete||r.overlappingEvidence){
        std::ostringstream x;x<<"$"<<h26(r.address)<<" byte=$"<<(analyzer_&&r.address<analyzer_->program().size()?h826(analyzer_->program()[r.address]):"??")
            <<" primary="<<RomClosure::primaryText(r.primary)<<" provenance="<<(r.provenanceComplete?"complete":"INCOMPLETE")
            <<" overlap="<<(r.overlappingEvidence?"yes":"no")<<" note="<<r.note;out.push_back(x.str());
    }
    return out;
}

std::vector<std::string> Decompiler::semanticLiftLiftLines() const{
    std::vector<std::string> out;
    std::ostringstream s;s<<"semantic-lift engine semantic lift: rooted_instructions="<<stats_.semanticLift.rootedCodeInstructions
        <<" lifted="<<stats_.semanticLift.mechanicallyLiftedInstructions<<" unsupported="<<stats_.semanticLift.unsupportedInstructionSemantics
        <<" blocks="<<stats_.semanticLift.liftedBlocks<<" fully_supported_blocks="<<stats_.semanticLift.fullySupportedBlocks;out.push_back(s.str());
    for(const auto&o:semanticLiftLiftedOperations_){std::ostringstream x;x<<o.stableId<<" pc=$"<<h26(o.sourcePC)<<" fallthrough=$"<<h26(o.fallthroughPC)
        <<" bytes=["<<bytes26(o.bytes)<<"] kind="<<SemanticLiftEngine::semanticKindText(o.kind)<<" supported="<<(o.supported?"yes":"no")
        <<" source=\""<<o.rawText<<"\"";out.push_back(x.str());}
    return out;
}

std::vector<std::string> Decompiler::semanticLiftDifferentialLines() const{
    std::vector<std::string> out;
    std::ostringstream s;s<<"semantic-lift engine differential verification: verified_blocks="<<stats_.semanticLift.differentiallyVerifiedBlocks
        <<" mismatches="<<stats_.semanticLift.differentialMismatches<<" snapshots="<<stats_.semanticLift.differentialSnapshots
        <<" operations="<<stats_.semanticLift.differentialOperations;out.push_back(s.str());
    for(const auto&r:semanticLiftDifferentialRecords_){std::ostringstream x;x<<r.blockId<<" supported="<<(r.supported?"yes":"no")
        <<" accepted="<<(r.accepted?"yes":"no")<<" snapshots="<<r.snapshots<<" ops="<<r.operationsCompared;
        if(r.firstDivergencePC!=0xFFFF){x<<" first_divergence=$"<<h26(r.firstDivergencePC);}
        x<<" note="<<r.diagnostic;out.push_back(x.str());}
    return out;
}

} // namespace pacripper
