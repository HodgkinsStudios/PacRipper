// PacRipper semantic reconciliation correction/reconciliation audit
// Created by Jacob Hodgkins

#include "Decompiler.h"

#include <algorithm>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>

namespace pacripper {
namespace {
std::string h28(std::uint16_t v){std::ostringstream s;s<<std::uppercase<<std::hex<<std::setfill('0')<<std::setw(4)<<v;return s.str();}
}

void Decompiler::buildReconciliation(){
    reconciliationCanonicalInstructions_.clear();reconciliationClosureBytes_.clear();reconciliationFinalResidual_.clear();stats_.reconciliation={};
    if(!analyzer_)return;
    const auto& program=analyzer_->program();
    Z80Disassembler dis;
    std::map<std::uint16_t,ReconciliationCanonicalInstructionRecord> byPc;

    // Reconcile the two independently rooted executable inventories.  The old
    // Analyzer graph remains useful; system-root reachability analysis adds the independently rooted IM2
    // graph.  Neither is allowed to erase the other.
    for(const auto&kv:analyzer_->instructions()){
        if(!analyzer_->hasStaticInstructionProof(kv.first)||analyzer_->isTraceDiscoveredInstruction(kv.first))continue;
        auto&r=byPc[kv.first];r.pc=kv.first;r.length=kv.second.length();r.bytes=kv.second.bytes;r.mnemonic=kv.second.mnemonic;r.operands=kv.second.operands;r.analyzerRoot=true;
    }
    for(const auto&rr:systemRootReachability_){
        auto&r=byPc[rr.pc];r.pc=rr.pc;r.systemRootReachable=true;r.systemRootReachabilityIds.insert(rr.id);
        const auto in=dis.decode(program,rr.pc);
        if(r.bytes.empty()){r.length=in.length();r.bytes=in.bytes;r.mnemonic=in.mnemonic;r.operands=in.operands;}
        if(in.length()!=rr.length)++stats_.reconciliation.systemRootDecodeLengthMismatches;
    }

    std::map<std::uint16_t,const SemanticOracleLiftedOperation*> oracleByPc;
    for(const auto&op:semanticOracleLiftedOperations_)oracleByPc[op.sourcePC]=&op;
    for(auto&kv:byPc){
        auto&r=kv.second;
        auto it=oracleByPc.find(r.pc);
        if(it!=oracleByPc.end()){
            const auto&op=*it->second;r.semanticOracleOperationIds.insert(op.id);r.semanticOracleSemanticallyVerified=op.supported;
            bool bytesMatch=r.pc+op.bytes.size()<=program.size();
            for(std::size_t i=0;bytesMatch&&i<op.bytes.size();++i)if(program[r.pc+i]!=op.bytes[i])bytesMatch=false;
            r.semanticOracleSourceBytesMatch=bytesMatch;if(!bytesMatch)++stats_.reconciliation.semanticOracleByteMismatches;
        }
    }

    std::set<std::uint16_t> codeBytes;
    std::size_t nextId=0;
    for(auto&kv:byPc){
        auto&r=kv.second;r.id=nextId++;
        if(r.analyzerRoot)++stats_.reconciliation.analyzerInstructionStarts;
        if(r.systemRootReachable)++stats_.reconciliation.systemRootInstructionStarts;
        if(r.analyzerRoot&&r.systemRootReachable)++stats_.reconciliation.analyzerSystemOverlapStarts;
        if(r.systemRootReachable&&!r.analyzerRoot)++stats_.reconciliation.systemOnlyInstructionStarts;
        if(r.semanticOracleSemanticallyVerified&&r.semanticOracleSourceBytesMatch)++stats_.reconciliation.semanticOracleCoveredCanonicalInstructions;
        for(std::size_t n=0;n<r.length&&static_cast<std::size_t>(r.pc)+n<program.size();++n)codeBytes.insert(static_cast<std::uint16_t>(r.pc+n));
        r.note=(r.analyzerRoot?"analyzer-root ":"")+(r.systemRootReachable?std::string("system-root "):std::string())+(r.semanticOracleSemanticallyVerified?std::string("semanticOracle-verified"):std::string("not-yet-lifted"));
        reconciliationCanonicalInstructions_.push_back(r);
    }
    auto&st=stats_.reconciliation;st.canonicalInstructionStarts=reconciliationCanonicalInstructions_.size();st.canonicalCodeBytes=codeBytes.size();
    st.canonicalInstructionsNotYetLifted=st.canonicalInstructionStarts-st.semanticOracleCoveredCanonicalInstructions;
    std::size_t activeInstructionEnd=0;
    for(const auto&r:reconciliationCanonicalInstructions_){
        const std::size_t pc=r.pc;
        if(pc<activeInstructionEnd)++st.canonicalInstructionBoundaryConflicts;
        activeInstructionEnd=std::max(activeInstructionEnd,pc+r.length);
    }

    // The upstream residual-extent analysis correction reopens spans that an incomplete sparse
    // pointer-selector domain had incorrectly been used to close negatively.
    for(const auto&n:residualExtentNegativeReferenceProofs_)if(n.incompletePointerDomainPotentialReference){st.incompletePointerDomainVetoBytes+=n.length;++st.incompletePointerDomainVetoSpans;}

    // Rebuild the canonical byte view.  system-root reachability analysis rooted instruction bytes are
    // promoted to code here rather than rewriting the established analysis maps.
    reconciliationClosureBytes_=im2VectorClosureBytes_;
    for(auto a:codeBytes){
        auto&b=reconciliationClosureBytes_.at(a);if(b.provenUnused)++st.canonicalCodePreviouslyMarkedUnused;b.provenUnused=false;b.code=true;b.primary=RomClosure::classify(b);
    }

    bool in=false;std::size_t start=0;
    for(std::size_t i=0;i<reconciliationClosureBytes_.size();++i){
        const bool unresolved=reconciliationClosureBytes_[i].primary==RomClosurePrimary::Unresolved;
        if(unresolved){++st.unresolvedAfterReconciliation;if(!in){in=true;start=i;}}
        else if(in){ReconciliationResidualRecord r;r.id=reconciliationFinalResidual_.size();r.start=static_cast<std::uint16_t>(start);r.end=static_cast<std::uint16_t>(i);r.length=i-start;r.reason="incomplete selector/data ownership remains open after correction";reconciliationFinalResidual_.push_back(r);in=false;}
    }
    if(in){ReconciliationResidualRecord r;r.id=reconciliationFinalResidual_.size();r.start=static_cast<std::uint16_t>(start);r.end=static_cast<std::uint16_t>(reconciliationClosureBytes_.size());r.length=reconciliationClosureBytes_.size()-start;r.reason="incomplete selector/data ownership remains open after correction";reconciliationFinalResidual_.push_back(r);}
    st.residualSpansAfterReconciliation=reconciliationFinalResidual_.size();
    st.canonicalInventorySelfConsistent=st.systemRootDecodeLengthMismatches==0&&st.semanticOracleByteMismatches==0&&st.canonicalInstructionBoundaryConflicts==0&&st.canonicalCodePreviouslyMarkedUnused==0;
    st.semanticOracleSubsetVerified=stats_.semanticOracle.independentOracleMismatches==0&&stats_.semanticOracle.completeRootedSemanticCoverage&&st.semanticOracleCoveredCanonicalInstructions==stats_.semanticOracle.mechanicallyLiftedInstructions;
    st.oldCompleteSemanticClaimSuperseded=st.canonicalInstructionStarts>stats_.semanticOracle.rootedCodeInstructions;
}

std::vector<std::string> Decompiler::reconciliationReconciliationLines() const{
    std::vector<std::string>o;if(!ready_)return{"Decompiler model not built."};const auto&s=stats_.reconciliation;
    o.push_back("PacRipper semantic reconciliation correction/reconciliation");
    o.push_back("canonical instructions="+std::to_string(s.canonicalInstructionStarts)+" code-bytes="+std::to_string(s.canonicalCodeBytes)+" legacy="+std::to_string(s.analyzerInstructionStarts)+" system-root="+std::to_string(s.systemRootInstructionStarts)+" overlap="+std::to_string(s.analyzerSystemOverlapStarts));
    o.push_back("SemanticOracle verified canonical subset="+std::to_string(s.semanticOracleCoveredCanonicalInstructions)+" / "+std::to_string(s.canonicalInstructionStarts)+" not-yet-lifted="+std::to_string(s.canonicalInstructionsNotYetLifted)+"; old complete-semantic claim superseded="+(s.oldCompleteSemanticClaimSuperseded?"yes":"no"));
    o.push_back("incomplete-pointer veto bytes="+std::to_string(s.incompletePointerDomainVetoBytes)+" spans="+std::to_string(s.incompletePointerDomainVetoSpans)+" final unresolved="+std::to_string(s.unresolvedAfterReconciliation)+" spans="+std::to_string(s.residualSpansAfterReconciliation));
    o.push_back("boundary-conflicts="+std::to_string(s.canonicalInstructionBoundaryConflicts)+" self-consistent="+std::string(s.canonicalInventorySelfConsistent?"yes":"no")+" SemanticOracle-subset-verified="+(s.semanticOracleSubsetVerified?"yes":"no"));
    for(const auto&r:reconciliationFinalResidual_)o.push_back("residual28#"+std::to_string(r.id)+" $"+h28(r.start)+"-$"+h28(static_cast<std::uint16_t>(r.end-1))+" len="+std::to_string(r.length)+" :: "+r.reason);
    return o;
}

} // namespace pacripper
