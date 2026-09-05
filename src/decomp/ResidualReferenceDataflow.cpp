// PacRipper residual-reference analysis residual high-ROM consumer discovery / negative-reference proof
// Created by Jacob Hodgkins

#include "Decompiler.h"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <map>
#include <queue>
#include <sstream>

namespace pacripper {
namespace {
std::string h16(std::uint16_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(4)<<std::setfill('0')<<(unsigned)v;return o.str();}
std::string pcs17(const std::set<std::uint16_t>& s){std::ostringstream o;o<<"{";std::size_t n=0;for(auto v:s){if(n++)o<<",";o<<"$"<<h16(v);}o<<"}";return o.str();}
std::string ids17(const std::set<std::size_t>& s,const char* p=""){std::ostringstream o;o<<"{";std::size_t n=0;for(auto v:s){if(n++)o<<",";o<<p<<v;}o<<"}";return o.str();}
bool staticIndependent(const Analyzer* a,std::uint16_t pc){return a&&a->hasStaticInstructionProof(pc)&&!a->isTraceDiscoveredInstruction(pc);}
bool staticInstructionMatches(const Analyzer* a,std::uint16_t pc,const char* mnemonic,const char* operands){
    if(!staticIndependent(a,pc))return false;
    const auto it=a->instructions().find(pc);
    return it!=a->instructions().end()&&it->second.mnemonic==mnemonic&&it->second.operands==operands;
}
bool overlaps17(std::uint16_t a0,std::uint16_t a1,std::uint16_t b0,std::uint16_t b1){return a0<b1&&b0<a1;}
std::set<std::uint16_t> operandHexWords(const std::string& text){
    std::set<std::uint16_t> out;
    for(std::size_t p=0;p+5<=text.size();++p){
        if(text[p]!='$') continue;
        unsigned v=0;
        bool ok=true;
        for(std::size_t i=1;i<=4;++i){const char c=text[p+i];unsigned d=0;if(c>='0'&&c<='9')d=c-'0';else if(c>='A'&&c<='F')d=10+c-'A';else if(c>='a'&&c<='f')d=10+c-'a';else{ok=false;break;}v=(v<<4)|d;}
        if(ok&&(p+5==text.size()||!std::isxdigit(static_cast<unsigned char>(text[p+5]))))out.insert(static_cast<std::uint16_t>(v));
    }
    return out;
}
bool readDirection(IndirectMemoryDirection d){return d==IndirectMemoryDirection::Read||d==IndirectMemoryDirection::ReadWrite;}
}

void Decompiler::buildResidualReference(){
    systemRomSemantics_.clear();negativeReferenceEvidence_.clear();unusedRomRegions_.clear();
    residualReferenceSemanticOverlaps_.clear();residualReferenceClosureProvenance_.clear();residualReferenceClosureBytes_.clear();stats_.residualReference={};
    if(!analyzer_)return;
    const auto& program=analyzer_->program();
    const auto& baseline=!highRomClosureBytes_.empty()?highRomClosureBytes_:(!indirectAddressClosureBytes_.empty()?indirectAddressClosureBytes_:romClosureBytes_);
    residualReferenceClosureBytes_=baseline;

    // Canonical Pac-Man IM2 system semantics. the established analysis pipeline seeded only the
    // startup $FA vector at $3FFA. residual-reference analysis keeps those layers verified and adds
    // a separate system-consumer overlay for two positively proven vector
    // consumers: the startup $FA word and the later $FC word. This is a
    // positive-consumer proof only; it does not infer that neighboring bytes or
    // every other possible vector-table slot are unused.
    //
    // I=$3F is established at $0001/$0003 and IM 2 at $233B. The $FA latch
    // value is proven by local constant propagation at $233F. The $FC value is
    // proven independently by the static $3000 -> ... -> $317D path and local
    // XOR A / SUB $04 value flow into OUT ($00),A at $3183, followed by a static
    // continuation to EI at $3196. The $FC target $008D is recorded as a new
    // system-root candidate rather than injected into the verified the established analysis pipeline CFG.
    auto exactAAt=[&](std::uint16_t pc,std::uint8_t expected){
        const auto ib=instructionToBlock_.find(pc);if(ib==instructionToBlock_.end())return false;
        const auto bb=blocks_.find(ib->second);if(bb==blocks_.end())return false;
        RegisterState state=bb->second.entryState;
        for(auto ip:bb->second.instructions){
            if(ip==pc){const auto v=state.regs.find("A");return v!=state.regs.end()&&v->second.known&&v->second.bits==8&&v->second.value==expected;}
            if(!staticIndependent(analyzer_,ip))return false;
            const auto ii=analyzer_->instructions().find(ip);if(ii==analyzer_->instructions().end())return false;
            transferInstruction(ii->second,state);
        }
        return false;
    };
    auto staticCfgPath=[&](std::uint16_t fromPc,std::uint16_t toPc){
        const auto fi=instructionToBlock_.find(fromPc),ti=instructionToBlock_.find(toPc);
        if(fi==instructionToBlock_.end()||ti==instructionToBlock_.end())return false;
        if(!staticIndependent(analyzer_,fromPc)||!staticIndependent(analyzer_,toPc))return false;
        if(fi->second==ti->second){
            const auto& ins=blocks_.at(fi->second).instructions;
            auto f=std::find(ins.begin(),ins.end(),fromPc),t=std::find(ins.begin(),ins.end(),toPc);
            return f!=ins.end()&&t!=ins.end()&&f<=t;
        }
        std::queue<std::uint16_t> q;std::set<std::uint16_t> seen;q.push(fi->second);seen.insert(fi->second);
        while(!q.empty()){
            const auto b=q.front();q.pop();const auto bi=blocks_.find(b);if(bi==blocks_.end())continue;
            for(const auto& e:bi->second.outgoing){
                if(e.to<0||e.kind==CfgEdgeKind::DynamicIndirect||e.kind==CfgEdgeKind::DynamicReturn||e.kind==CfgEdgeKind::Indirect||e.kind==CfgEdgeKind::Return)continue;
                const auto n=static_cast<std::uint16_t>(e.to);if(!blocks_.count(n)||blocks_.at(n).instructions.empty()||!staticIndependent(analyzer_,blocks_.at(n).instructions.front()))continue;
                if(n==ti->second)return true;
                if(seen.insert(n).second)q.push(n);
            }
        }
        return false;
    };

    bool iPageProof=staticInstructionMatches(analyzer_,0x0001,"LD","A,$3F")&&
                    staticInstructionMatches(analyzer_,0x0003,"LD","I,A")&&
                    exactAAt(0x0003,0x3F)&&staticCfgPath(0x0001,0x0003);
    bool im2Proof=staticInstructionMatches(analyzer_,0x233B,"IM","2")&&staticCfgPath(0x0003,0x233B);
    std::set<std::uint16_t> staticIWrites,staticImChanges;
    for(const auto& kv:analyzer_->instructions()){
        if(!staticIndependent(analyzer_,kv.first))continue;
        const auto& in=kv.second;
        if(in.mnemonic=="LD"&&in.operands=="I,A")staticIWrites.insert(in.address);
        if(in.mnemonic=="IM")staticImChanges.insert(in.address);
    }
    iPageProof=iPageProof&&staticIWrites==std::set<std::uint16_t>({0x0003});
    im2Proof=im2Proof&&staticImChanges==std::set<std::uint16_t>({0x233B});

    struct VectorProofInput{std::uint8_t vectorByte;std::set<std::uint16_t> proofPCs;bool latchProof;std::string source;std::string note;};
    std::vector<VectorProofInput> vectorProofs;
    VectorProofInput fa;
    fa.vectorByte=0xFA;fa.proofPCs={0x0001,0x0003,0x233B,0x233D,0x233F,0x2349};
    fa.latchProof=staticInstructionMatches(analyzer_,0x233D,"LD","A,$FA")&&
                  staticInstructionMatches(analyzer_,0x233F,"OUT","($00),A")&&exactAAt(0x233F,0xFA)&&
                  staticInstructionMatches(analyzer_,0x2349,"EI","")&&staticCfgPath(0x233B,0x2349);
    fa.source="Static Pac-Man IM2 setup: I=$3F; exact A=$FA at vector latch; static continuation to EI";
    fa.note="Exact two-byte IM2 vector word for the statically proven $FA board vector; target $3000 was already an independent static root before residual-reference analysis.";
    vectorProofs.push_back(fa);
    VectorProofInput fc;
    fc.vectorByte=0xFC;fc.proofPCs={0x0001,0x0003,0x233B,0x317D,0x317E,0x3181,0x3183,0x3196};
    fc.latchProof=staticInstructionMatches(analyzer_,0x317D,"XOR","A")&&
                  staticInstructionMatches(analyzer_,0x317E,"LD","($5003),A")&&
                  staticInstructionMatches(analyzer_,0x3181,"SUB","$04")&&
                  staticInstructionMatches(analyzer_,0x3183,"OUT","($00),A")&&exactAAt(0x3183,0xFC)&&
                  staticCfgPath(0x3000,0x3183)&&staticInstructionMatches(analyzer_,0x3196,"EI","")&&staticCfgPath(0x3183,0x3196);
    fc.source="Static Pac-Man IM2 chain: $3000 reaches XOR A / SUB $04; exact A=$FC at vector latch; static continuation to EI";
    fc.note="Exact two-byte IM2 vector word for the statically proven $FC board vector; target $008D is a residual-reference analysis-discovered system root candidate and is not retroactively injected into verified the established analysis pipeline reachability.";
    vectorProofs.push_back(fc);

    bool priorFaConsumed=false;
    for(const auto& vp:vectorProofs){
        const std::uint16_t vectorAddress=static_cast<std::uint16_t>((0x3Fu<<8)|vp.vectorByte);
        if(static_cast<std::size_t>(vectorAddress)+1>=program.size())continue;
        const std::uint16_t decoded=static_cast<std::uint16_t>(program[vectorAddress]|(static_cast<std::uint16_t>(program[vectorAddress+1])<<8));
        SystemRomSemanticRecord s;s.id=systemRomSemantics_.size();s.kind=SystemRomSemanticKind::InterruptVectorWord;
        s.start=vectorAddress;s.end=static_cast<std::uint16_t>(vectorAddress+2);s.decodedValue=decoded;s.target=decoded;
        s.interruptPage=0x3F;s.vectorByte=vp.vectorByte;s.exact=true;
        const bool chainProof=vp.vectorByte!=0xFC||priorFaConsumed;
        s.staticProof=iPageProof&&im2Proof&&chainProof&&vp.latchProof&&decoded<program.size();
        s.targetStaticBeforeResidualReference=decoded<program.size()&&staticIndependent(analyzer_,decoded);
        s.proofPCs=vp.proofPCs;s.proofSource=vp.source;s.note=vp.note;
        systemRomSemantics_.push_back(s);
        ResidualReferenceAnalysis::applyExactSystemSemantic(s,baseline,residualReferenceClosureBytes_,residualReferenceClosureProvenance_);
        if(vp.vectorByte==0xFA&&s.staticProof&&s.target==0x3000)priorFaConsumed=true;
    }

    // Inventory all independently-static unknown indirect ROM-capable reads once.
    // These are global blockers: until their effective address alternatives are
    // closed, absence of direct/finite references cannot become exhaustive proof.
    std::set<std::uint16_t> globalUnknownReadBlockers;
    for(const auto& a:indirectMemoryAccesses_){
        if(!readDirection(a.direction)||!a.address.staticProof||a.address.dynamicOnly||!staticIndependent(analyzer_,a.pc))continue;
        if(a.address.kind==AddressValueKind::Unknown||a.address.hasUnknownAlternative)globalUnknownReadBlockers.insert(a.pc);
    }

    for(const auto& residual:highRomResidualAudit_){
        NegativeReferenceRecord n;n.id=negativeReferenceEvidence_.size();n.start=residual.start;n.end=residual.end;n.length=residual.length;
        n.leftRomBoundary=n.start==0;n.rightRomBoundary=n.end==program.size();
        if(n.start>0&&static_cast<std::size_t>(n.start-1)<baseline.size())
            n.leftBoundaryProven=baseline[n.start-1].primary!=RomClosurePrimary::Unresolved;
        if(n.end<baseline.size())n.rightBoundaryProven=baseline[n.end].primary!=RomClosurePrimary::Unresolved;

        for(const auto& kv:analyzer_->instructions()){
            const Instruction& in=kv.second;if(!staticIndependent(analyzer_,in.address))continue;
            for(const auto& m:in.memoryRefs)if(m.address>=n.start&&m.address<n.end)n.directMemoryRefPCs.insert(in.address);
            if(in.target>=0&&static_cast<unsigned>(in.target)>=n.start&&static_cast<unsigned>(in.target)<n.end)n.controlTargetPCs.insert(in.address);
            for(auto v:operandHexWords(in.operands))if(v>=n.start&&v<n.end)n.immediateAddressPCs.insert(in.address);
        }

        for(const auto& a:indirectMemoryAccesses_){
            if(!readDirection(a.direction)||!a.address.staticProof||a.address.dynamicOnly||!staticIndependent(analyzer_,a.pc))continue;
            if(ResidualReferenceAnalysis::addressValueIntersects(a.address,n.start,n.end)){
                n.finiteIndirectAccessIds.insert(a.id);n.finiteIndirectPCs.insert(a.pc);
            }
        }
        n.unknownIndirectReadBlockerPCs=globalUnknownReadBlockers;

        for(const auto& s:systemRomSemantics_)if(s.staticProof&&overlaps17(n.start,n.end,s.start,s.end))n.systemSemanticIds.insert(s.id);
        for(const auto& kv:analyzer_->romDataUsage())if(kv.first>=n.start&&kv.first<n.end){
            n.dynamicReadEvents+=kv.second.readEvents;n.dynamicReadPCs.insert(kv.second.sourcePCs.begin(),kv.second.sourcePCs.end());
        }

        n.directReferenceAbsent=n.directMemoryRefPCs.empty()&&n.immediateAddressPCs.empty();
        n.finiteIndirectReferenceAbsent=n.finiteIndirectAccessIds.empty();
        n.controlReferenceAbsent=n.controlTargetPCs.empty();
        n.systemSemanticAbsent=n.systemSemanticIds.empty();
        n.exhaustiveModeledStaticAbsence=n.directReferenceAbsent&&n.finiteIndirectReferenceAbsent&&n.controlReferenceAbsent&&n.systemSemanticAbsent&&n.unknownIndirectReadBlockerPCs.empty();
        n.supportsUnusedClassification=ResidualReferenceAnalysis::qualifiesUnused(n);
        std::ostringstream note;
        note<<"residual-reference analysis inventories independently-static direct memory references, 16-bit address literals, direct control targets, and indirect-address analysis finite indirect reads. ";
        if(!n.unknownIndirectReadBlockerPCs.empty())note<<"Unknown static indirect-read alternatives remain, so negative evidence is non-exhaustive and cannot classify unused data. ";
        if(n.dynamicReadEvents==0)note<<"The imported trace provides no ROM-data-read contradiction, but this is corroboration only. ";
        if(!n.systemSemanticIds.empty())note<<"A positive system/hardware semantic overlaps this original high-ROM semantic analysis residual span. ";
        note<<"Adjacent proven bytes are boundary evidence only and never extend semantic extent.";n.note=note.str();
        negativeReferenceEvidence_.push_back(n);
        if(n.supportsUnusedClassification)unusedRomRegions_.push_back(ResidualReferenceAnalysis::unusedRegion(n,unusedRomRegions_.size()));
    }

    // Explicitly retain compatible multiple interpretations instead of silently
    // choosing one.  Coalesce contiguous addresses carrying the same label set.
    std::map<std::uint16_t,std::set<std::string>> interpretations;
    for(const auto& s:streamSemantics_)if(s.accepted&&s.staticProof)for(auto a:s.coveredAddresses)interpretations[a].insert("stream#"+std::to_string(s.id));
    for(const auto& r:fixedRecordSemantics_)if(r.staticProof)for(auto a:r.coveredAddresses)interpretations[a].insert("record#"+std::to_string(r.id));
    for(const auto& b:boundedBlockSemantics_)if(b.staticProof)for(auto a:b.coveredAddresses)interpretations[a].insert("block#"+std::to_string(b.id));
    for(const auto& s:systemRomSemantics_)if(s.staticProof)for(std::uint16_t a=s.start;a<s.end;++a)interpretations[a].insert("system#"+std::to_string(s.id));
    for(auto it=interpretations.begin();it!=interpretations.end();){
        if(it->second.size()<2){++it;continue;}const std::uint16_t start=it->first;const auto labels=it->second;std::uint16_t end=static_cast<std::uint16_t>(start+1);auto jt=std::next(it);
        while(jt!=interpretations.end()&&jt->first==end&&jt->second==labels){++end;++jt;}
        SemanticOverlapRecord r;r.id=residualReferenceSemanticOverlaps_.size();r.start=start;r.end=end;r.interpretations=labels;r.compatible=true;r.note="Compatible semantic overlap retained explicitly; no interpretation wins merely by ordering.";residualReferenceSemanticOverlaps_.push_back(r);it=jt;
    }

    std::size_t unresolved=0,newExact=0,newBounded=0,newNegative=0,residualSpans=0;bool inResidual=false;
    for(std::size_t i=0;i<residualReferenceClosureBytes_.size();++i){
        const bool unresolvedHere=residualReferenceClosureBytes_[i].primary==RomClosurePrimary::Unresolved;
        if(unresolvedHere){++unresolved;if(!inResidual){++residualSpans;inResidual=true;}}else inResidual=false;
        if(i<baseline.size()&&baseline[i].primary==RomClosurePrimary::Unresolved&&residualReferenceClosureBytes_[i].primary!=RomClosurePrimary::Unresolved){
            if(residualReferenceClosureBytes_[i].staticExactDataUse||residualReferenceClosureBytes_[i].hardData||residualReferenceClosureBytes_[i].code)++newExact;
            else if(residualReferenceClosureBytes_[i].boundedConsumer)++newBounded;
            else ++newNegative;
        }
    }
    std::set<std::uint16_t> blockerUnion;std::size_t dynamicEvents=0;for(const auto& n:negativeReferenceEvidence_){blockerUnion.insert(n.unknownIndirectReadBlockerPCs.begin(),n.unknownIndirectReadBlockerPCs.end());dynamicEvents+=n.dynamicReadEvents;if(n.exhaustiveModeledStaticAbsence)++stats_.residualReference.exhaustiveNegativeReferenceRecords;}
    stats_.residualReference.negativeReferenceRecords=negativeReferenceEvidence_.size();stats_.residualReference.unusedRomRegions=unusedRomRegions_.size();stats_.residualReference.systemSemanticRecords=systemRomSemantics_.size();stats_.residualReference.overlapRecords=residualReferenceSemanticOverlaps_.size();stats_.residualReference.closureProvenanceRecords=residualReferenceClosureProvenance_.size();
    stats_.residualReference.newlyExactExplainedBytes=newExact;stats_.residualReference.newlyBoundedExplainedBytes=newBounded;stats_.residualReference.newlyNegativeExplainedBytes=newNegative;stats_.residualReference.newlyExplainedBytes=newExact+newBounded+newNegative;stats_.residualReference.unresolvedAfterResidualReference=unresolved;stats_.residualReference.residualSpansAfterResidualReference=residualSpans;stats_.residualReference.unknownIndirectBlockerPCs=blockerUnion.size();stats_.residualReference.dynamicResidualReadEvents=dynamicEvents;
    auto& sc=stats_.residualReference.semanticCoverage;sc.romBytes=program.size();sc.semanticBytesBeforeResidualReference=stats_.highRom.semanticCoverage.semanticBytesAfterHighRom;sc.residualReferenceNewSemanticBytes=newExact;sc.semanticBytesAfterResidualReference=sc.semanticBytesBeforeResidualReference+sc.residualReferenceNewSemanticBytes;sc.checksumOnlyBytes=stats_.highRom.semanticCoverage.checksumOnlyBytes;sc.unresolvedAfterResidualReference=unresolved;
}

std::vector<std::string> Decompiler::negativeRomEvidenceLines() const{
    std::vector<std::string> o;if(!ready_)return{"Decompiler model not built."};
    o.push_back("PacRipper residual-reference analysis negative ROM reference evidence");
    o.push_back("Absence is diagnostic unless every modeled static read alternative is bounded; dynamic absence never creates static proof.");o.push_back("");
    for(const auto& n:negativeReferenceEvidence_){
        std::ostringstream s;s<<"negative#"<<n.id<<" $"<<h16(n.start)<<"-$"<<h16(static_cast<std::uint16_t>(n.end-1))<<" len="<<n.length
            <<" direct="<<n.directMemoryRefPCs.size()<<" literals="<<n.immediateAddressPCs.size()<<" control="<<n.controlTargetPCs.size()<<" finite-indirect="<<n.finiteIndirectAccessIds.size()
            <<" unknown-blockers="<<n.unknownIndirectReadBlockerPCs.size()<<" dynamic-reads="<<n.dynamicReadEvents<<" system="<<n.systemSemanticIds.size()
            <<" exhaustive="<<(n.exhaustiveModeledStaticAbsence?"yes":"no")<<" unused-proof="<<(n.supportsUnusedClassification?"yes":"no");o.push_back(s.str());
        o.push_back("  direct-pcs="+pcs17(n.directMemoryRefPCs)+" literal-pcs="+pcs17(n.immediateAddressPCs)+" finite-indirect-pcs="+pcs17(n.finiteIndirectPCs)+" blockers="+pcs17(n.unknownIndirectReadBlockerPCs));
        o.push_back("  "+n.note);
    }return o;
}

std::vector<std::string> Decompiler::unusedRomRegionLines() const{
    std::vector<std::string> o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper residual-reference analysis unused ROM regions");
    if(unusedRomRegions_.empty()){o.push_back("No canonical region satisfied the exhaustive negative-reference gate. No bytes were classified unused from appearance, adjacency, or trace silence.");return o;}
    for(const auto& r:unusedRomRegions_)
        o.push_back("unused#"+std::to_string(r.id)+" negative#"+std::to_string(r.negativeReferenceId)+" $"+h16(r.start)+"-$"+h16(static_cast<std::uint16_t>(r.end-1))+" accepted="+(r.accepted?"yes":"no")+" :: "+r.note);
    return o;
}

std::vector<std::string> Decompiler::residualReferenceClosureLines() const{
    std::vector<std::string> o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper residual-reference analysis closure delta / provenance");
    o.push_back("new="+std::to_string(stats_.residualReference.newlyExplainedBytes)+" exact="+std::to_string(stats_.residualReference.newlyExactExplainedBytes)+" bounded="+std::to_string(stats_.residualReference.newlyBoundedExplainedBytes)+" negative="+std::to_string(stats_.residualReference.newlyNegativeExplainedBytes)+" residual="+std::to_string(stats_.residualReference.unresolvedAfterResidualReference)+" spans="+std::to_string(stats_.residualReference.residualSpansAfterResidualReference));
    for(const auto& s:systemRomSemantics_)o.push_back("system#"+std::to_string(s.id)+" "+ResidualReferenceAnalysis::systemSemanticKindText(s.kind)+" I=$"+h16(s.interruptPage).substr(2)+" vector=$"+h16(s.vectorByte).substr(2)+" $"+h16(s.start)+"-$"+h16(static_cast<std::uint16_t>(s.end-1))+" -> $"+h16(s.target)+" exact="+(s.exact?"yes":"no")+" static="+(s.staticProof?"yes":"no")+" target-prestatic="+(s.targetStaticBeforeResidualReference?"yes":"no")+" proof="+pcs17(s.proofPCs)+" :: "+s.note);
    for(const auto& p:residualReferenceClosureProvenance_)o.push_back("$"+h16(p.address)+" exact="+(p.exact?"yes":"no")+" bounded="+(p.bounded?"yes":"no")+" negative="+(p.negativeProof?"yes":"no")+" system="+ids17(p.systemSemanticIds,"system#")+" proof="+pcs17(p.proofPCs)+" :: "+p.note);
    return o;
}

} // namespace pacripper
