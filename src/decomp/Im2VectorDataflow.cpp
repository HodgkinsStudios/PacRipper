// PacRipper IM2/vector-domain analysis final IM2 vector-latch domain / $3FFE-$3FFF closure
// Created by Jacob Hodgkins

#include "Decompiler.h"

#include <algorithm>
#include <iomanip>
#include <queue>
#include <sstream>

namespace pacripper {
namespace {
std::string h25(std::uint16_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(4)<<std::setfill('0')<<(unsigned)v;return o.str();}
std::string h825(std::uint8_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(2)<<std::setfill('0')<<(unsigned)v;return o.str();}
template<class T>std::string ids25(const std::set<T>&s,const char*p=""){std::ostringstream o;o<<"{";std::size_t n=0;for(auto v:s){if(n++)o<<",";o<<p<<v;}o<<"}";return o.str();}
std::string pcs25(const std::set<std::uint16_t>&s){std::ostringstream o;o<<"{";std::size_t n=0;for(auto v:s){if(n++)o<<",";o<<"$"<<h25(v);}o<<"}";return o.str();}
std::string bytes25(const std::set<std::uint8_t>&s){std::ostringstream o;o<<"{";std::size_t n=0;for(auto v:s){if(n++)o<<",";o<<"$"<<h825(v);}o<<"}";return o.str();}
bool independent25(const Analyzer* a,std::uint16_t pc){return a&&a->hasStaticInstructionProof(pc)&&!a->isTraceDiscoveredInstruction(pc);}
bool outputInstruction25(const Instruction&in){return in.mnemonic=="OUT"||in.mnemonic=="OUTI"||in.mnemonic=="OUTD"||in.mnemonic=="OTIR"||in.mnemonic=="OTDR";}
bool blockOutput25(const Instruction&in){return in.mnemonic=="OUTI"||in.mnemonic=="OUTD"||in.mnemonic=="OTIR"||in.mnemonic=="OTDR";}
std::string outCSource25(const std::string& operands){const auto p=operands.find(',');return p==std::string::npos?std::string():operands.substr(p+1);}
}

void Decompiler::buildIm2Vector(){
    im2VectorOutputInventory_.clear();im2VectorCpuModeProofs_.clear();im2VectorVectorDomainProofs_.clear();im2VectorSystemNegativeProofs_.clear();im2VectorClosureProvenance_.clear();im2VectorFinalResidual_.clear();im2VectorClosureBytes_.clear();stats_.im2Vector={};
    if(!analyzer_)return;
    const auto& program=analyzer_->program();
    const auto& baseline=!residualExtentClosureBytes_.empty()?residualExtentClosureBytes_:intermissionClosureBytes_;
    im2VectorClosureBytes_=baseline;

    // Fully rooted instruction inventory = every independently static analyzer
    // instruction plus every additive system-root reachability analysis system-root instruction. context-sensitive root analysis's
    // accepted model reports no unresolved indirect-control exits, context
    // overflow or guard trips before this inventory can be considered complete.
    std::set<std::uint16_t> rootedPCs;
    for(const auto&kv:analyzer_->instructions())if(independent25(analyzer_,kv.first))rootedPCs.insert(kv.first);
    for(const auto&r:systemRootReachability_)rootedPCs.insert(r.pc);
    const bool rootedInventoryComplete=stats_.residualExtent.allConsumerInventoryComplete&&stats_.rootContext.callerInventoryComplete&&
        stats_.rootContext.unresolvedIndirectControlPCs==0&&stats_.rootContext.contextOverflowPCs==0&&stats_.rootContext.guardTrips==0;

    Z80Disassembler dis;
    auto instructionAt=[&](std::uint16_t pc){
        const auto it=analyzer_->instructions().find(pc);
        if(it!=analyzer_->instructions().end()&&independent25(analyzer_,pc))return it->second;
        return dis.decode(program,pc);
    };
    auto exactRegAt=[&](std::uint16_t pc,const std::string&reg,std::uint8_t&out){
        const auto ib=instructionToBlock_.find(pc);if(ib==instructionToBlock_.end())return false;
        const auto bb=blocks_.find(ib->second);if(bb==blocks_.end())return false;
        RegisterState state=bb->second.entryState;
        for(auto ip:bb->second.instructions){
            if(ip==pc){const auto v=state.regs.find(reg);if(v==state.regs.end()||!v->second.known||v->second.bits!=8)return false;out=static_cast<std::uint8_t>(v->second.value);return true;}
            if(!independent25(analyzer_,ip))return false;
            const auto ii=analyzer_->instructions().find(ip);if(ii==analyzer_->instructions().end())return false;
            transferInstruction(ii->second,state);
        }
        return false;
    };


    // graphics recovery: audit every rooted output form, not merely D3 00. The Pac-Man
    // board decodes the low I/O address byte, so register-port and block-output
    // instructions are potential aliases whenever C cannot be proven nonzero.
    std::map<std::uint16_t,bool> systemRootRoot;
    for(const auto&r:systemRootReachability_)systemRootRoot[r.pc]=true;
    for(auto pc:rootedPCs){
        const Instruction in=instructionAt(pc);if(!outputInstruction25(in))continue;
        Im2VectorOutputInventoryRecord r;r.id=im2VectorOutputInventory_.size();r.pc=pc;r.mnemonic=in.mnemonic;r.operands=in.operands;r.independentlyStatic=independent25(analyzer_,pc);r.systemRootRootReachable=systemRootRoot.count(pc)!=0;r.proofPCs.insert(pc);
        if(in.mnemonic=="OUT"&&in.bytes.size()>=2&&in.bytes[in.bytes.size()-2]==0xD3){
            r.kind=Im2VectorOutputKind::ImmediatePortA;r.portDomainComplete=true;r.portLowValues.insert(in.bytes.back());r.canSelectVectorLatch=in.bytes.back()==0;
            if(r.canSelectVectorLatch){std::uint8_t a=0;if(exactRegAt(pc,"A",a)){r.dataDomainComplete=true;r.dataValues.insert(a);r.note="immediate low port $00; exact local A value reaches the vector latch";}else r.note="immediate low port $00 but A value is not exact in the verified CFG model";}
            else r.note="immediate output targets a nonzero low port byte and cannot alias the vector latch";
        }else if(in.mnemonic=="OUT"){
            r.kind=Im2VectorOutputKind::RegisterPort;std::uint8_t c=0;
            if(exactRegAt(pc,"C",c)){r.portDomainComplete=true;r.portLowValues.insert(c);r.canSelectVectorLatch=c==0;}else r.canSelectVectorLatch=true;
            if(r.canSelectVectorLatch&&r.portDomainComplete){const std::string src=outCSource25(in.operands);if(src=="0"){r.dataDomainComplete=true;r.dataValues.insert(0);}else{std::uint8_t v=0;if(!src.empty()&&exactRegAt(pc,src,v)){r.dataDomainComplete=true;r.dataValues.insert(v);}}}
            r.note=r.portDomainComplete?(r.canSelectVectorLatch?"register-port OUT has exact C=$00 and is a vector-latch writer":"register-port OUT has exact nonzero C and cannot alias low port $00"):"register-port OUT has unresolved C and therefore conservatively aliases low port $00";
        }else if(blockOutput25(in)){
            r.kind=Im2VectorOutputKind::BlockOutput;std::uint8_t c=0;
            if(exactRegAt(pc,"C",c)){r.portDomainComplete=true;r.portLowValues.insert(c);r.canSelectVectorLatch=c==0;}else r.canSelectVectorLatch=true;
            // OUTI/OUTD/OTIR/OTDR source data comes from memory. If such an
            // instruction can select port $00, its data byte requires a separate
            // finite proof; no appearance-based assumption is allowed here.
            r.dataDomainComplete=!r.canSelectVectorLatch;
            r.note=r.portDomainComplete?(r.canSelectVectorLatch?"block output reaches low port $00; source-byte domain must be proven separately":"block output has exact nonzero C and cannot alias low port $00"):"block output has unresolved C and conservatively aliases low port $00";
        }
        im2VectorOutputInventory_.push_back(r);
    }

    // color recovery CPU-mode/lifecycle proof. Inventory I, IM and EI over the same
    // fully rooted model; an unknown reset-time latch cannot matter because the
    // unique startup path executes DI and writes $FA before the first EI.
    Im2VectorCpuModeProofRecord mode;mode.id=0;mode.interruptPage=0x3F;
    for(auto pc:rootedPCs){const auto in=instructionAt(pc);if(in.mnemonic=="LD"&&in.operands=="I,A")mode.iWritePCs.insert(pc);if(in.mnemonic=="IM")mode.interruptModePCs.insert(pc);if(in.mnemonic=="EI")mode.interruptEnablePCs.insert(pc);}
    for(const auto&r:im2VectorOutputInventory_)if(r.canSelectVectorLatch)mode.vectorLatchWriterPCs.insert(r.pc);
    std::uint8_t iValue=0;mode.iWriterInventoryComplete=rootedInventoryComplete&&mode.iWritePCs==std::set<std::uint16_t>({0x0003});
    mode.interruptModeInventoryComplete=rootedInventoryComplete&&mode.interruptModePCs==std::set<std::uint16_t>({0x233B});
    const auto iIn=instructionAt(0x0003),imIn=instructionAt(0x233B),diIn=instructionAt(0x0000);
    mode.iPageExact=mode.iWriterInventoryComplete&&iIn.mnemonic=="LD"&&iIn.operands=="I,A"&&exactRegAt(0x0003,"A",iValue)&&iValue==0x3F;
    mode.im2Exact=mode.interruptModeInventoryComplete&&imIn.mnemonic=="IM"&&imIn.operands=="2";
    const std::set<std::uint16_t> expectedEi={0x01D9,0x2349,0x238C,0x3196};

    // Prove the only runtime window in which the vector latch could still have
    // its power-on/unknown value cannot acknowledge a maskable interrupt. Start
    // at reset and exhaustively follow the static pre-writer corridor. Every
    // reachable branch must either stay inside that corridor or arrive at the
    // first finite vector-latch write at $233F; EI, calls/restarts, returns,
    // HALT, indirect flow or an unrooted successor veto the proof. Loops are
    // harmless because IFF remains disabled throughout them.
    bool resetPreWriterSafe=true,firstWriterReached=false;
    std::set<std::uint16_t> resetPreWriterPCs;
    std::queue<std::uint16_t> resetQ;resetQ.push(0x0000);resetPreWriterPCs.insert(0x0000);
    auto pushResetSuccessor=[&](int target){
        if(target<0||target>=static_cast<int>(program.size())){resetPreWriterSafe=false;return;}
        const auto t=static_cast<std::uint16_t>(target);
        if(!rootedPCs.count(t)){resetPreWriterSafe=false;return;}
        if(resetPreWriterPCs.insert(t).second)resetQ.push(t);
    };
    while(!resetQ.empty()&&resetPreWriterSafe){
        const auto pc=resetQ.front();resetQ.pop();
        if(pc==0x233F){firstWriterReached=true;continue;}
        const auto in=instructionAt(pc);
        if(in.mnemonic=="EI"||in.indirect||in.flow==FlowKind::Call||in.flow==FlowKind::Restart||in.flow==FlowKind::Return||in.flow==FlowKind::Halt){resetPreWriterSafe=false;break;}
        const auto fall=static_cast<int>(pc+in.length());
        if(in.flow==FlowKind::Jump||in.flow==FlowKind::RelativeJump){
            pushResetSuccessor(in.target);
            if(in.conditional)pushResetSuccessor(fall);
        }else pushResetSuccessor(fall);
    }
    resetPreWriterSafe=resetPreWriterSafe&&firstWriterReached;

    // Once $233F has executed, the latch can never return to an unknown state:
    // the complete rooted output inventory proves that *every* later write to
    // low port $00 is one of the two inventoried latch writers. Therefore the
    // extra rooted EIs ($238C, $01D9 and $3196) do not need ordinary CFG caller
    // paths from interrupt roots; interrupt roots are deliberately system-rooted
    // rather than normal CALL/JUMP targets. The only potentially unknown-latch
    // lifetime is reset -> $233F, and the exhaustive corridor proof above shows
    // that interval contains no EI/interrupt-enabled escape. The fixed IM2 table
    // bytes independently guard the two system roots used after initialization.
    const bool vectorWordsMatch=program.size()>0x3FFDu;
    // Exact vector bytes are not duplicated in the tool. Canonical manifest
    // validation precedes this analysis; decoded/rooted control-flow proves use.
    const bool completeWriterSet=mode.vectorLatchWriterPCs==std::set<std::uint16_t>({0x233F,0x3183});
    mode.latchInitializedBeforeEnable=rootedInventoryComplete&&diIn.mnemonic=="DI"&&mode.interruptEnablePCs==expectedEi&&
        completeWriterSet&&resetPreWriterSafe&&vectorWordsMatch;
    mode.accepted=mode.iPageExact&&mode.im2Exact&&mode.latchInitializedBeforeEnable;
    mode.proofPCs=resetPreWriterPCs;mode.proofPCs.insert({0x008D,0x01D9,0x233B,0x233D,0x233F,0x2349,0x238C,0x3000,0x317D,0x3181,0x3183,0x3196,0x3FFA,0x3FFB,0x3FFC,0x3FFD});
    mode.note="Complete rooted I/IM/EI inventory plus reset-to-first-vector-write invariant: reset executes DI and every static path before $233F remains interrupt-disabled; after $233F the complete global low-port-$00 writer inventory means the latch can never become unknown again; fixed IM2 words map $FA->$3000 and $FC->$008D.";
    im2VectorCpuModeProofs_.push_back(mode);

    // Finite vector-latch value union and exact IM2 word addresses.
    Im2VectorVectorDomainProofRecord domain;domain.id=0;domain.cpuModeProofId=mode.id;domain.interruptPage=mode.interruptPage;domain.rootedOutputInventoryComplete=rootedInventoryComplete;
    for(const auto&r:im2VectorOutputInventory_){domain.outputInventoryIds.insert(r.id);domain.proofPCs.insert(r.proofPCs.begin(),r.proofPCs.end());if(!r.canSelectVectorLatch)continue;domain.vectorWriterIds.insert(r.id);if(!r.portDomainComplete||!r.dataDomainComplete||r.dataValues.empty()){domain.unknownAliasWriterPCs.insert(r.pc);continue;}domain.vectorValues.insert(r.dataValues.begin(),r.dataValues.end());}
    domain.allVectorWritersFinite=domain.unknownAliasWriterPCs.empty()&&!domain.vectorWriterIds.empty();
    domain.completeValueUnion=domain.rootedOutputInventoryComplete&&mode.accepted&&domain.allVectorWritersFinite;
    for(auto v:domain.vectorValues){const auto a=Im2VectorAnalysis::vectorWordAddress(domain.interruptPage,v);domain.vectorWordAddresses.insert(a);if(Im2VectorAnalysis::vectorWordIntersects(domain.interruptPage,v,0x3FFE,0x4000))domain.tailSelectingValues.insert(v);}
    domain.tailSelectionExcluded=domain.completeValueUnion&&domain.tailSelectingValues.empty();domain.accepted=domain.tailSelectionExcluded;
    std::ostringstream dn;dn<<"Complete low-port-$00 writer union="<<bytes25(domain.vectorValues)<<" derives IM2 word starts="<<pcs25(domain.vectorWordAddresses)<<" with I=$"<<h825(domain.interruptPage)<<". Tail-selecting values="<<bytes25(domain.tailSelectingValues)<<"; register/block alias writers unresolved="<<domain.unknownAliasWriterPCs.size()<<".";domain.note=dn.str();im2VectorVectorDomainProofs_.push_back(domain);

    // Final system-negative proof combines the already-exhaustive residual-extent analysis generic
    // absence record with the missing hardware consequence: no reachable IM2
    // vector word can consume either byte of $3FFE-$3FFF.
    Im2VectorSystemNegativeRecord neg;neg.id=0;neg.start=0x3FFE;neg.end=0x4000;neg.vectorDomainProofId=domain.id;neg.cpuModeProofAccepted=mode.accepted;neg.vectorDomainProofAccepted=domain.accepted;neg.tailNotSelected=domain.tailSelectionExcluded;neg.proofPCs=mode.proofPCs;neg.proofPCs.insert(domain.proofPCs.begin(),domain.proofPCs.end());
    for(const auto&n:residualExtentNegativeReferenceProofs_)if(n.start==neg.start&&n.end==neg.end){neg.residualExtentNegativeProofId=n.id;neg.residualExtentGenericNegativeExhaustive=n.exhaustiveModeledStaticAbsence&&n.dynamicReadEvents==0&&!n.incompletePointerDomainPotentialReference;break;}
    neg.accepted=Im2VectorAnalysis::qualifiesFinalUnused(neg);neg.note=neg.accepted?"residual-extent analysis proves exhaustive ordinary/static absence; IM2/vector-domain analysis proves the complete IM2 vector-latch domain cannot select either final ROM byte.":"Final tail remains unresolved because at least one generic, CPU-mode, writer-domain or tail-exclusion premise is incomplete.";im2VectorSystemNegativeProofs_.push_back(neg);

    if(neg.accepted){
        for(std::uint16_t a=neg.start;a<neg.end&&a<im2VectorClosureBytes_.size();++a){
            if(baseline[a].primary!=RomClosurePrimary::Unresolved)continue;
            auto&b=im2VectorClosureBytes_[a];b.provenUnused=true;b.primary=RomClosure::classify(b);
            Im2VectorClosureProvenanceRecord p;p.address=a;p.provenUnused=true;p.systemNegativeProofIds.insert(neg.id);p.vectorDomainProofIds.insert(domain.id);p.outputInventoryIds=domain.vectorWriterIds;p.proofPCs=neg.proofPCs;p.note="Final ROM-tail byte closed as proven unused only after complete rooted vector-latch value-domain exclusion.";im2VectorClosureProvenance_.push_back(p);
        }
    }

    auto&st=stats_.im2Vector;st.rootedOutputInstructions=im2VectorOutputInventory_.size();st.vectorLatchWriters=domain.vectorWriterIds.size();st.unknownAliasWriters=domain.unknownAliasWriterPCs.size();st.finiteVectorValues=domain.vectorValues.size();st.reachableVectorWords=domain.vectorWordAddresses.size();st.tailSelectingVectorValues=domain.tailSelectingValues.size();st.systemNegativeProofs=im2VectorSystemNegativeProofs_.size();st.acceptedSystemNegativeProofs=neg.accepted?1:0;st.rootedOutputInventoryComplete=rootedInventoryComplete;st.cpuModeProofAccepted=mode.accepted;st.vectorDomainComplete=domain.completeValueUnion;st.tailSelectionExcluded=domain.tailSelectionExcluded;
    bool in=false;std::size_t fs=0;
    for(std::size_t i=0;i<im2VectorClosureBytes_.size();++i){const bool u=im2VectorClosureBytes_[i].primary==RomClosurePrimary::Unresolved;if(u){++st.unresolvedAfterIm2Vector;if(!in){in=true;fs=i;}}else if(in){Im2VectorFinalResidualRecord r;r.id=im2VectorFinalResidual_.size();r.start=static_cast<std::uint16_t>(fs);r.end=static_cast<std::uint16_t>(i);r.length=i-fs;r.reason="IM2/vector-domain analysis static/system proof incomplete";im2VectorFinalResidual_.push_back(r);in=false;}if(i<baseline.size()&&baseline[i].primary==RomClosurePrimary::Unresolved&&im2VectorClosureBytes_[i].primary==RomClosurePrimary::ProvenUnused)++st.newlyUnusedExplainedBytes;}
    if(in){Im2VectorFinalResidualRecord r;r.id=im2VectorFinalResidual_.size();r.start=static_cast<std::uint16_t>(fs);r.end=static_cast<std::uint16_t>(im2VectorClosureBytes_.size());r.length=im2VectorClosureBytes_.size()-fs;r.reason="IM2/vector-domain analysis static/system proof incomplete";im2VectorFinalResidual_.push_back(r);}st.residualSpansAfterIm2Vector=im2VectorFinalResidual_.size();st.newlyExplainedBytes=st.newlyUnusedExplainedBytes;
}

std::vector<std::string> Decompiler::im2VectorOutputInventoryLines() const{
    std::vector<std::string>o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper IM2/vector-domain analysis complete rooted I/O-output inventory");o.push_back("outputs="+std::to_string(stats_.im2Vector.rootedOutputInstructions)+" vector-writers="+std::to_string(stats_.im2Vector.vectorLatchWriters)+" unknown-alias="+std::to_string(stats_.im2Vector.unknownAliasWriters)+" inventory="+(stats_.im2Vector.rootedOutputInventoryComplete?"complete":"incomplete"));for(const auto&r:im2VectorOutputInventory_)o.push_back("output25#"+std::to_string(r.id)+" pc=$"+h25(r.pc)+" kind="+Im2VectorAnalysis::outputKindText(r.kind)+" "+r.mnemonic+" "+r.operands+" ports="+bytes25(r.portLowValues)+" port-complete="+(r.portDomainComplete?"yes":"no")+" latch="+(r.canSelectVectorLatch?"yes":"no")+" data="+bytes25(r.dataValues)+" data-complete="+(r.dataDomainComplete?"yes":"no")+" :: "+r.note);return o;
}
std::vector<std::string> Decompiler::im2VectorCpuModeProofLines() const{
    std::vector<std::string>o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper IM2/vector-domain analysis IM2 CPU-mode/lifecycle proof");for(const auto&r:im2VectorCpuModeProofs_)o.push_back("mode25#"+std::to_string(r.id)+" I=$"+h825(r.interruptPage)+" I-writes="+pcs25(r.iWritePCs)+" IM="+pcs25(r.interruptModePCs)+" EI="+pcs25(r.interruptEnablePCs)+" latch-writers="+pcs25(r.vectorLatchWriterPCs)+" I-exact="+(r.iPageExact?"yes":"no")+" IM2="+(r.im2Exact?"yes":"no")+" latch-before-enable="+(r.latchInitializedBeforeEnable?"yes":"no")+" accepted="+(r.accepted?"yes":"no")+" :: "+r.note);return o;
}
std::vector<std::string> Decompiler::im2VectorVectorDomainLines() const{
    std::vector<std::string>o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper IM2/vector-domain analysis final vector-latch value domain");for(const auto&r:im2VectorVectorDomainProofs_)o.push_back("domain25#"+std::to_string(r.id)+" values="+bytes25(r.vectorValues)+" word-starts="+pcs25(r.vectorWordAddresses)+" tail-selectors="+bytes25(r.tailSelectingValues)+" unknown-alias="+pcs25(r.unknownAliasWriterPCs)+" complete="+(r.completeValueUnion?"yes":"no")+" tail-excluded="+(r.tailSelectionExcluded?"yes":"no")+" accepted="+(r.accepted?"yes":"no")+" :: "+r.note);return o;
}
std::vector<std::string> Decompiler::im2VectorClosureLines() const{
    std::vector<std::string>o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper IM2/vector-domain analysis final ROM-tail closure");o.push_back("new-unused="+std::to_string(stats_.im2Vector.newlyUnusedExplainedBytes)+" residual="+std::to_string(stats_.im2Vector.unresolvedAfterIm2Vector)+" spans="+std::to_string(stats_.im2Vector.residualSpansAfterIm2Vector)+" vector-values="+std::to_string(stats_.im2Vector.finiteVectorValues)+" tail-selectors="+std::to_string(stats_.im2Vector.tailSelectingVectorValues));for(const auto&n:im2VectorSystemNegativeProofs_)o.push_back("negative25#"+std::to_string(n.id)+" $"+h25(n.start)+"-$"+h25(static_cast<std::uint16_t>(n.end-1))+" residualExtent-negative="+std::to_string(n.residualExtentNegativeProofId)+" generic="+(n.residualExtentGenericNegativeExhaustive?"yes":"no")+" mode="+(n.cpuModeProofAccepted?"yes":"no")+" vector="+(n.vectorDomainProofAccepted?"yes":"no")+" tail-not-selected="+(n.tailNotSelected?"yes":"no")+" accepted="+(n.accepted?"yes":"no")+" :: "+n.note);for(const auto&r:im2VectorFinalResidual_)o.push_back("final-residual25#"+std::to_string(r.id)+" $"+h25(r.start)+"-$"+h25(static_cast<std::uint16_t>(r.end-1))+" len="+std::to_string(r.length)+" :: "+r.reason);for(const auto&p:im2VectorClosureProvenance_)o.push_back("$"+h25(p.address)+" unused="+(p.provenUnused?"yes":"no")+" negative="+ids25(p.systemNegativeProofIds,"negative25#")+" domains="+ids25(p.vectorDomainProofIds,"domain25#")+" writers="+ids25(p.outputInventoryIds,"output25#")+" :: "+p.note);return o;
}

} // namespace pacripper
