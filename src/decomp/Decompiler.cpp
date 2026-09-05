// Created by Jacob Hodgkins
#include "Decompiler.h"

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iomanip>
#include <queue>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>

namespace pacripper {
namespace {
std::string hex8(std::uint8_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(2)<<std::setfill('0')<<(unsigned)v;return o.str();}
std::string hex16(std::uint16_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(4)<<std::setfill('0')<<(unsigned)v;return o.str();}
bool parseHex4(const std::string& s,std::size_t pos,std::uint16_t& out){
    if(pos>=s.size()||s[pos]!='$'||pos+5>s.size()) return false;
    unsigned v=0;
    for(std::size_t i=1;i<=4;++i){char c=s[pos+i];unsigned d;if(c>='0'&&c<='9')d=c-'0';else if(c>='A'&&c<='F')d=10+c-'A';else if(c>='a'&&c<='f')d=10+c-'a';else return false;v=(v<<4)|d;}out=static_cast<std::uint16_t>(v);return true;
}
std::vector<std::string> splitOperands(const std::string& s){
    std::vector<std::string> v;std::string cur;int depth=0;
    for(char c:s){if(c=='(')++depth;else if(c==')')--depth;if(c==','&&depth==0){v.push_back(cur);cur.clear();}else cur+=c;}if(!cur.empty()||!s.empty())v.push_back(cur);
    for(auto& x:v){std::size_t a=0,b=x.size();while(a<b&&std::isspace((unsigned char)x[a]))++a;while(b>a&&std::isspace((unsigned char)x[b-1]))--b;x=x.substr(a,b-a);}return v;
}
std::string condName(const std::string& op){
    static const char* cs[]={"NZ","Z","NC","C","PO","PE","P","M"};for(const char* c:cs)if(op==c)return op;return {};
}
AbstractValue unknown(unsigned bits){AbstractValue v;v.bits=bits;return v;}
AbstractValue known(std::uint16_t x,unsigned bits){AbstractValue v;v.known=true;v.value=static_cast<std::uint16_t>(bits==8?(x&0xFF):x);v.bits=bits;return v;}
bool sameValue(const AbstractValue&a,const AbstractValue&b){return a.known==b.known&&a.bits==b.bits&&(!a.known||a.value==b.value);}
}

void Decompiler::clear(){
    ready_=false;analyzer_=nullptr;blocks_.clear();functions_.clear();instructionToBlock_.clear();functionEntries_.clear();
    structures_.clear();stackBlocks_.clear();callSites_.clear();observedReturns_.clear();returnMatches_.clear();callReturnEvidence_.clear();conditionEvidence_.clear();romConsumers_.clear();romClosureBytes_.clear();ramPairEvidence_.clear();romObjects_.clear();romPointerLinks_.clear();functionRegisterSummaries_.clear();unresolvedPriority_.clear();defUseResult_={};ramObjects_.clear();defUseRomConsumers_.clear();defUseClosureBytes_.clear();defUseUnresolvedPriority_.clear();hardwareAccesses_.clear();memoryXrefs_.clear();ramShapes_.clear();typeEvidence_.clear();tableSchemas_.clear();routineContracts_.clear();machineValues_.clear();mergeValues_.clear();callBindings_.clear();typedValues_.clear();indexedExpressions_.clear();liftedStatements_.clear();routineBehaviors_.clear();structuredValueRegions_.clear();temporaryElisions_.clear();callContinuities_.clear();routineRoles_.clear();routineSimilarities_.clear();routineClusters_.clear();routineNavigation_.clear();dormantCodeSeeds_.clear();dormantCodeDiscoveries_.clear();romExtentRefinements_.clear();residualAudit_.clear();objectRoles_.clear();stateXrefs_.clear();residualPriorityV2_.clear();residualClosureClosureBytes_.clear();residualClosureRomObjects_.clear();indirectMemoryAccesses_.clear();indirectRomConsumerProofs_.clear();indirectAddressClosureProvenance_.clear();indirectAddressClosureBytes_.clear();indirectAddressResidualAudit_.clear();indirectAddressResidualPriorityV2_.clear();romDecoders_.clear();pointerTableDomains_.clear();streamSemantics_.clear();streamFamilies_.clear();fixedRecordSemantics_.clear();boundedBlockSemantics_.clear();highRomClosureProvenance_.clear();highRomClosureBytes_.clear();highRomResidualAudit_.clear();highRomResidualPriorityV2_.clear();systemRomSemantics_.clear();negativeReferenceEvidence_.clear();unusedRomRegions_.clear();residualReferenceSemanticOverlaps_.clear();residualReferenceClosureProvenance_.clear();residualReferenceClosureBytes_.clear();systemRoots_.clear();systemRootReachability_.clear();systemRootInlineData_.clear();indirectAddressRefinements_.clear();systemRootNegativeReferenceEvidence_.clear();systemRootUnusedRomRegions_.clear();systemRootClosureProvenance_.clear();systemRootClosureBytes_.clear();rootContextAddressContexts_.clear();rootContextAddressProofs_.clear();rootContextNegativeReferenceEvidence_.clear();rootContextUnusedRomRegions_.clear();rootContextClosureProvenance_.clear();rootContextClosureBytes_.clear();memoryAliasWriterContexts_.clear();memoryAliasWriterProofs_.clear();memoryAliasWriterAliases_.clear();memoryAliasAddressProofs_.clear();memoryAliasClosureProvenance_.clear();memoryAliasClosureBytes_.clear();commandStreamWriterAliases_.clear();commandStreamValueProofs_.clear();commandStreamCommandStreams_.clear();commandStreamAddressProofs_.clear();commandStreamClosureProvenance_.clear();commandStreamClosureBytes_.clear();mazeTopologyTopologyInputs_.clear();mazeTopologyDirectionCandidates_.clear();mazeTopologyRetryLoopProofs_.clear();mazeTopologyAddressProofs_.clear();mazeTopologyResidualClassification_.clear();mazeTopologyClosureProvenance_.clear();mazeTopologyClosureBytes_.clear();intermissionDispatchProofs_.clear();intermissionWriterProofs_.clear();intermissionLifecycleProofs_.clear();intermissionAddressProofs_.clear();intermissionClosureProvenance_.clear();intermissionClosureBytes_.clear();residualExtentResidualAudit_.clear();residualExtentExtentProofs_.clear();residualExtentNegativeReferenceProofs_.clear();residualExtentUnusedRegions_.clear();residualExtentClosureProvenance_.clear();residualExtentFinalResidual_.clear();residualExtentClosureBytes_.clear();im2VectorOutputInventory_.clear();im2VectorCpuModeProofs_.clear();im2VectorVectorDomainProofs_.clear();im2VectorSystemNegativeProofs_.clear();im2VectorClosureProvenance_.clear();im2VectorFinalResidual_.clear();im2VectorClosureBytes_.clear();semanticLiftProvenanceLedger_.clear();semanticLiftLiftedOperations_.clear();semanticLiftLiftedBlocks_.clear();semanticLiftDifferentialRecords_.clear();semanticOracleLiftedOperations_.clear();semanticOracleLiftedBlocks_.clear();semanticOracleOracleRecords_.clear();semanticOracleGeneratedSourceMap_.clear();reconciliationCanonicalInstructions_.clear();reconciliationClosureBytes_.clear();reconciliationFinalResidual_.clear();canonicalSemanticLiftedOperations_.clear();canonicalSemanticLiftedBlocks_.clear();canonicalSemanticOracleRecords_.clear();canonicalSemanticSelectorDomains_.clear();canonicalSemanticSelectorReferences_.clear();canonicalSemanticClosureBytes_.clear();canonicalSemanticFinalResidual_.clear();canonicalClosureHighSelectorBounds_.clear();canonicalClosureCanonicalDataObjects_.clear();canonicalClosureNegativeClosure_.clear();canonicalClosureClosureBytes_.clear();canonicalClosureFinalResidual_.clear();romReconstructionReconstructionLedger_.clear();romReconstructionReconstructionMap_.clear();romReconstructionBinaryDiff_.clear();romReconstructionRebuiltBytes_.clear();romRebuilderRebuildResult_={};generatedCodeGeneratedOperations_.clear();generatedCodeGeneratedBlocks_.clear();generatedCodeGeneratedSourceMap_.clear();generatedCodeDifferentialRecords_.clear();platformContractDependencies_.clear();platformContractServiceContracts_.clear();platformContractBoundaryValidation_.clear();nativeRuntimeNativeClasses_.clear();nativeRuntimeValidation_.clear();nativeVideoNativeClasses_.clear();nativeVideoValidation_.clear();nativeVideoCanonicalValidation_.clear();nativeAudioNativeClasses_.clear();nativeAudioValidation_.clear();nativeAudioCanonicalValidation_.clear();nativeIntegrationStateMap_.clear();nativeIntegrationExecutionLedger_.clear();nativeIntegrationValidation_.clear();nativeIntegrationCanonicalValidation_.clear();coreCoverageLedger_.clear();coreDifferentialValidation_.clear();coreCanonicalValidation_.clear();lifecycleSchedulerCoverageLedger_.clear();lifecycleSchedulerDifferentialValidation_.clear();lifecycleSchedulerCanonicalValidation_.clear();creditStartCoverageLedger_.clear();creditStartDifferentialValidation_.clear();creditStartCanonicalValidation_.clear();sessionInitializationCoverageLedger_.clear();sessionInitializationDifferentialValidation_.clear();sessionInitializationCanonicalValidation_.clear();mazePreparationCoverageLedger_.clear();mazePreparationDifferentialValidation_.clear();mazePreparationCanonicalValidation_.clear();displayMapCoverageLedger_.clear();displayMapDifferentialValidation_.clear();displayMapCanonicalValidation_.clear();hudBoardCoverageLedger_.clear();hudBoardDifferentialValidation_.clear();hudBoardCanonicalValidation_.clear();boardInterpreterCoverageLedger_.clear();boardInterpreterDifferentialValidation_.clear();commandInterpreterCoverageLedger_.clear();commandInterpreterDifferentialValidation_.clear();rstUtilityCoverageLedger_.clear();rstUtilityDifferentialValidation_.clear();schedulerUtilityCoverageLedger_.clear();schedulerUtilityDifferentialValidation_.clear();graphicCreditCoverageLedger_.clear();graphicCreditDifferentialValidation_.clear();frameUpdateCoverageLedger_.clear();frameUpdateDifferentialValidation_.clear();objectInputCoverageLedger_.clear();objectInputDifferentialValidation_.clear();frameHelperCoverageLedger_.clear();frameHelperDifferentialValidation_.clear();coordinateRenderCoverageLedger_.clear();coordinateRenderDifferentialValidation_.clear();startupUtilityCoverageLedger_.clear();startupUtilityDifferentialValidation_.clear();startupRuntimeCoverageLedger_.clear();startupRuntimeDifferentialValidation_.clear();interruptSchedulerCoverageLedger_.clear();interruptSchedulerDifferentialValidation_.clear();systemUtilityCoverageLedger_.clear();systemUtilityDifferentialValidation_.clear();startupSelfTestCoverageLedger_.clear();startupSelfTestDifferentialValidation_.clear();coldStateCoverageLedger_.clear();coldStateDifferentialValidation_.clear();coldHelperCoverageLedger_.clear();coldHelperDifferentialValidation_.clear();coordinateDispatchCoverageLedger_.clear();coordinateDispatchDifferentialValidation_.clear();intermissionStateCoverageLedger_.clear();intermissionStateDifferentialValidation_.clear();systemRootPrimaryCoverageLedger_.clear();systemRootPrimaryDifferentialValidation_.clear();systemRootSecondaryCoverageLedger_.clear();systemRootSecondaryDifferentialValidation_.clear();interruptLatchCoverageLedger_.clear();interruptLatchDifferentialValidation_.clear();stats_={};
}

bool Decompiler::build(const Analyzer& analyzer,std::string& error){
    clear(); if(!analyzer.ready()){error="Analyzer has no loaded program.";return false;} analyzer_=&analyzer;
    std::set<std::uint16_t> leaders; discoverLeaders(leaders); buildBlocks(leaders); buildEdges(); buildFunctions(); propagateValues();
    buildConditionSemantics();buildStructure();buildStackModel();buildCallReturnEvidence();buildRomClosure();buildObjectPointerObjects();buildDefUse();buildHardwareSemantic();buildTypeContract();buildContractValue();buildStructuredExpression();buildResidualClosure();buildIndirectAddress();buildHighRom();buildResidualReference();buildSystemRoot();buildRootContext();buildMemoryAlias();buildCommandStream();buildMazeTopology();buildIntermission();buildResidualExtent();buildIm2Vector();buildSemanticLift();buildSemanticOracle();buildReconciliation();buildCanonicalSemantic();buildCanonicalClosure();buildRomReconstruction();buildRomRebuilder();
    stats_.basicBlocks=blocks_.size(); stats_.functions=functions_.size();
    for(const auto& kv:blocks_){stats_.cfgEdges+=kv.second.outgoing.size();if(kv.second.functionOwners.empty())++stats_.unownedBlocks;else if(kv.second.functionOwners.size()>1)++stats_.sharedBlocks;for(const auto&e:kv.second.outgoing){if(e.observedCount)++stats_.observedCfgEdges;if(e.kind==CfgEdgeKind::DynamicIndirect||e.kind==CfgEdgeKind::DynamicReturn)++stats_.dynamicOnlyEdges;}}
    ready_=true;error.clear();return true;
}

std::uint16_t Decompiler::continuationAfter(const Instruction& in) const{
    std::uint32_t n=static_cast<std::uint32_t>(in.address)+in.length();
    if(in.flow==FlowKind::Restart&&(in.target==0x28||in.target==0x30)){
        for(const auto& kv:analyzer_->dataRegions())if(kv.second.sourceAddress==in.address){n=kv.second.end;break;}
    }
    // Logical CFG continuation for Pac-Man's custom CALL-inline convention.
    // The machine CALL still physically pushes address+length ($2B73); $2BCD
    // advances that saved return over five inline bytes before RET reaches $2B78.
    if(in.flow==FlowKind::Call&&in.target==0x2BCD)n+=5;
    return n<=0xFFFFu?static_cast<std::uint16_t>(n):0xFFFF;
}

void Decompiler::discoverLeaders(std::set<std::uint16_t>& leaders){
    const auto& ins=analyzer_->instructions();if(ins.empty())return;leaders.insert(ins.begin()->first);
    const std::uint16_t vectors[]={0,8,0x10,0x18,0x20,0x28,0x30,0x38};for(auto v:vectors)if(ins.count(v)){leaders.insert(v);functionEntries_.insert(v);}
    for(const auto& kv:analyzer_->codeXrefs())if(ins.count(kv.first))leaders.insert(kv.first);
    for(const auto& kv:ins){const Instruction& in=kv.second;
        if(in.flow==FlowKind::Call&&in.target>=0&&in.target<0x4000&&ins.count((std::uint16_t)in.target))functionEntries_.insert((std::uint16_t)in.target);
        if(in.target>=0&&in.target<0x4000&&ins.count((std::uint16_t)in.target))leaders.insert((std::uint16_t)in.target);
        const bool split=(in.flow!=FlowKind::Normal)||in.conditional;
        if(split){const auto c=continuationAfter(in);if(ins.count(c))leaders.insert(c);}
    }
    for(const auto& kv:analyzer_->dispatchTables())for(const auto&e:kv.second.entries){if(ins.count(e.target)){leaders.insert(e.target);functionEntries_.insert(e.target);}}
    for(const auto& from:analyzer_->dynamicFlowEdges()) {
        const auto fi=ins.find(from.first); if(fi==ins.end()) continue;
        const std::uint16_t expected=continuationAfter(fi->second);
        for(const auto& to:from.second) if(ins.count(to.first) && (to.first!=expected || fi->second.flow!=FlowKind::Normal)) leaders.insert(to.first);
    }
    for(const auto& kv:functionEntries_)leaders.insert(kv);
}

void Decompiler::buildBlocks(const std::set<std::uint16_t>& leaders){
    const auto& ins=analyzer_->instructions();
    for(auto it=ins.begin();it!=ins.end();){
        if(!leaders.count(it->first)){++it;continue;}
        BasicBlock b;b.start=it->first;auto jt=it;
        while(jt!=ins.end()){
            if(jt!=it&&leaders.count(jt->first))break;
            const Instruction& in=jt->second;b.instructions.push_back(in.address);instructionToBlock_[in.address]=b.start;
            b.end=static_cast<std::uint16_t>(static_cast<std::uint32_t>(in.address)+in.length());
            const bool terminal=(in.flow!=FlowKind::Normal)||in.conditional;
            const auto next=std::next(jt);
            if(terminal){++jt;break;}
            if(next==ins.end()){++jt;break;}
            const std::uint16_t expected=continuationAfter(in);
            if(next->first!=expected){++jt;break;}
            jt=next;
        }
        blocks_[b.start]=b;it=jt;
    }
    // Dynamically discovered instruction islands can lack a conventional leader.
    for(const auto& kv:ins)if(!instructionToBlock_.count(kv.first)){
        BasicBlock b;b.start=kv.first;b.instructions.push_back(kv.first);b.end=static_cast<std::uint16_t>(kv.first+kv.second.length());instructionToBlock_[kv.first]=b.start;blocks_[b.start]=b;
    }
}

std::string Decompiler::conditionFor(const Instruction& in) const{
    auto ops=splitOperands(in.operands);if(ops.empty())return {};
    if(in.mnemonic=="JR"||in.mnemonic=="JP"||in.mnemonic=="CALL"||in.mnemonic=="RET"){
        const std::string c=condName(ops[0]);if(!c.empty())return c;
    }
    if(in.mnemonic=="DJNZ") return "B!=0";
    return {};
}

std::string Decompiler::renderedConditionFor(const Instruction& in) const{
    const auto it=conditionEvidence_.find(in.address);
    if(it!=conditionEvidence_.end()&&!it->second.expression.empty())return it->second.expression;
    return conditionFor(in);
}

void Decompiler::buildEdges(){
    const auto& ins=analyzer_->instructions();
    auto add=[&](BasicBlock& b,std::uint16_t from,int target,CfgEdgeKind kind,const std::string& cond){
        CfgEdge e{from,target,kind,cond};b.outgoing.push_back(e);if(target>=0){auto bi=blocks_.find((std::uint16_t)target);if(bi!=blocks_.end())bi->second.incoming.insert(b.start);}
    };
    auto blockForTarget=[&](std::uint16_t a)->int{auto it=instructionToBlock_.find(a);return it==instructionToBlock_.end()?-1:(int)it->second;};
    auto inverseConditionText=[&](const std::string& c){if(c=="B!=0")return std::string("B==0");const std::string inv=ConditionSemantics::inverseCondition(c);return inv.empty()?(c.empty()?std::string():std::string("!(")+c+")"):inv;};
    for(auto& kv:blocks_){BasicBlock& b=kv.second;if(b.instructions.empty())continue;const Instruction& in=ins.at(b.instructions.back());const auto cont=continuationAfter(in);const int fall=blockForTarget(cont);const std::string cond=conditionFor(in);
        switch(in.flow){
            case FlowKind::Normal: if(fall>=0)add(b,in.address,fall,CfgEdgeKind::Fallthrough,{});break;
            case FlowKind::Call:{int t=in.target>=0?blockForTarget((std::uint16_t)in.target):-1;if(t>=0)add(b,in.address,t,CfgEdgeKind::Call,cond);if(fall>=0)add(b,in.address,fall,CfgEdgeKind::Fallthrough,{});break;}
            case FlowKind::Jump:case FlowKind::RelativeJump:{
                if(in.indirect){add(b,in.address,-1,CfgEdgeKind::Indirect,{});break;}
                int t=in.target>=0?blockForTarget((std::uint16_t)in.target):-1;if(t>=0)add(b,in.address,t,CfgEdgeKind::BranchTaken,cond);
                if(in.conditional&&fall>=0) add(b,in.address,fall,CfgEdgeKind::BranchNotTaken,cond.empty()?"not-taken":inverseConditionText(cond));
                break;}
            case FlowKind::Return:add(b,in.address,-1,CfgEdgeKind::Return,cond);if(in.conditional&&fall>=0)add(b,in.address,fall,CfgEdgeKind::BranchNotTaken,cond.empty()?"not-return":inverseConditionText(cond));break;
            case FlowKind::Restart:{
                if(in.target==0x20){const auto dt=analyzer_->dispatchTables().find(in.address);if(dt!=analyzer_->dispatchTables().end())for(const auto&e:dt->second.entries){const int t=blockForTarget(e.target);if(t>=0)add(b,in.address,t,CfgEdgeKind::Dispatch,"index="+std::to_string(e.index));}else add(b,in.address,-1,CfgEdgeKind::Indirect,"RST20 unresolved");}
                else {int t=in.target>=0?blockForTarget((std::uint16_t)in.target):-1;if(t>=0)add(b,in.address,t,CfgEdgeKind::Restart,{});if(fall>=0)add(b,in.address,fall,CfgEdgeKind::Fallthrough,{});}break;}
            case FlowKind::Halt:if(fall>=0)add(b,in.address,fall,CfgEdgeKind::Fallthrough,"after interrupt");break;
        }
    }
    // Overlay concrete transitions observed in Pacman Arcade traces. Matching static
    // edges receive counts; otherwise a separately typed dynamic edge is retained.
    for(const auto& from:analyzer_->dynamicFlowEdges()) {
        const auto ib=instructionToBlock_.find(from.first); if(ib==instructionToBlock_.end()) continue;
        auto bb=blocks_.find(ib->second); if(bb==blocks_.end() || bb->second.instructions.empty() || bb->second.instructions.back()!=from.first) continue;
        const auto ii=ins.find(from.first); if(ii==ins.end()) continue;
        for(const auto& to:from.second) {
            const int tb=blockForTarget(to.first); if(tb<0) continue;
            bool matched=false;
            for(auto& e:bb->second.outgoing) if(e.to==tb) { e.observedCount+=to.second; matched=true; break; }
            if(matched) continue;
            CfgEdgeKind kind=CfgEdgeKind::DynamicIndirect;
            if(ii->second.flow==FlowKind::Return) kind=CfgEdgeKind::DynamicReturn;
            CfgEdge e{from.first,tb,kind,"dynamic trace",to.second}; bb->second.outgoing.push_back(e);
            blocks_.at(static_cast<std::uint16_t>(tb)).incoming.insert(bb->first);
        }
    }
}

bool Decompiler::isFunctionEntry(std::uint16_t address) const{return functionEntries_.count(address)!=0;}
std::string Decompiler::functionName(std::uint16_t e) const{return analyzer_->labelFor(e);}
std::string Decompiler::blockName(std::uint16_t s) const{return "block_"+hex16(s);}

void Decompiler::buildFunctions(){
    const auto& ins=analyzer_->instructions();
    // Preserve every known function/handler entry; if a vector wasn't reached it simply won't appear.
    for(auto e:functionEntries_)if(blocks_.count(e)){FunctionModel f;f.entry=e;f.name=functionName(e);functions_[e]=f;}
    for(auto& fk:functions_){const std::uint16_t root=fk.first;std::queue<std::uint16_t> q;std::set<std::uint16_t> seen;q.push(root);
        while(!q.empty()){auto b=q.front();q.pop();if(!seen.insert(b).second)continue;if(b!=root&&isFunctionEntry(b))continue;fk.second.blocks.insert(b);const auto bi=blocks_.find(b);if(bi==blocks_.end())continue;
            for(const auto&e:bi->second.outgoing){if(e.to<0)continue;const auto t=(std::uint16_t)e.to;if(e.kind==CfgEdgeKind::Call||e.kind==CfgEdgeKind::Restart||e.kind==CfgEdgeKind::Dispatch||e.kind==CfgEdgeKind::DynamicReturn||e.kind==CfgEdgeKind::DynamicIndirect){if(isFunctionEntry(t))fk.second.callees.insert(t);continue;}q.push(t);}
        }
    }
    // Direct call ownership and reverse call graph.
    for(const auto& kv:ins){const Instruction& in=kv.second;if(in.flow==FlowKind::Call&&in.target>=0&&functionEntries_.count((std::uint16_t)in.target)){
        auto ib=instructionToBlock_.find(in.address);if(ib==instructionToBlock_.end())continue;for(auto& fk:functions_)if(fk.second.blocks.count(ib->second)){fk.second.callees.insert((std::uint16_t)in.target);break;}
    }}
    for(auto& fk:functions_)for(auto c:fk.second.callees){auto it=functions_.find(c);if(it!=functions_.end())it->second.callers.insert(fk.first);}
    for(auto& kv:blocks_) kv.second.functionOwners.clear();
    for(const auto& fk:functions_) for(auto b:fk.second.blocks) { auto bi=blocks_.find(b); if(bi!=blocks_.end()) bi->second.functionOwners.insert(fk.first); }
}


bool Decompiler::isStructuralEdge(CfgEdgeKind kind) const {
    return kind==CfgEdgeKind::Fallthrough||kind==CfgEdgeKind::BranchTaken||kind==CfgEdgeKind::BranchNotTaken;
}

StructuralGraph Decompiler::structuralGraphFor(std::uint16_t functionEntry) const {
    StructuralGraph graph;graph.entry=functionEntry;
    const auto fi=functions_.find(functionEntry);if(fi==functions_.end())return graph;
    for(auto b:fi->second.blocks) {
        const auto bi=blocks_.find(b);if(bi==blocks_.end())continue;
        if(bi->second.functionOwners.size()==1&&bi->second.functionOwners.count(functionEntry))graph.nodes.insert(b);
    }
    if(!graph.nodes.count(functionEntry))return graph;
    for(auto b:graph.nodes) {
        const auto& block=blocks_.at(b);
        bool hasStructuralSuccessor=false;
        bool hasStaticExit=false;
        for(const auto& e:block.outgoing) {
            if(isStructuralEdge(e.kind)&&e.to>=0) {
                const auto t=static_cast<std::uint16_t>(e.to);
                if(graph.nodes.count(t)){graph.successors[b].insert(t);hasStructuralSuccessor=true;}
                else hasStaticExit=true;
                continue;
            }
            // Explicit returns and unresolved indirect transfers are static outward flow.
            // In particular, a conditional RET has both a branch-not-taken successor and
            // a true exit; retaining both is required for sound post-dominators.
            if(e.kind==CfgEdgeKind::Return||e.kind==CfgEdgeKind::Indirect)hasStaticExit=true;
        }
        if(hasStaticExit||!hasStructuralSuccessor)graph.exits.insert(b);
    }
    // Side entries from another static structural context make a candidate region unsafe.
    // Dynamic-only edges are deliberately ignored here.
    for(const auto& src:blocks_)for(const auto& e:src.second.outgoing) {
        if(!isStructuralEdge(e.kind)||e.to<0) continue;
        const auto t=static_cast<std::uint16_t>(e.to);
        if(graph.nodes.count(t)&&!graph.nodes.count(src.first))graph.externalEntryBlocks.insert(t);
    }
    StructuredControl::rebuildPredecessors(graph);return graph;
}

std::map<std::uint16_t,BranchDescriptor> Decompiler::branchDescriptorsFor(const StructuralGraph& graph) const {
    std::map<std::uint16_t,BranchDescriptor> out;
    for(auto b:graph.nodes) {
        const auto& block=blocks_.at(b);if(block.instructions.empty())continue;const auto& in=analyzer_->instructions().at(block.instructions.back());
        if(!in.conditional) continue;
        BranchDescriptor d;d.block=b;d.sourceAddress=in.address;
        for(const auto& e:block.outgoing) {
            if(e.to<0||!graph.nodes.count(static_cast<std::uint16_t>(e.to)))continue;
            if(e.kind==CfgEdgeKind::BranchTaken){d.taken=e.to;d.takenCondition=e.condition;}
            else if(e.kind==CfgEdgeKind::BranchNotTaken){d.notTaken=e.to;d.notTakenCondition=e.condition;}
        }
        if(d.taken>=0&&d.notTaken>=0)out[b]=d;
    }
    return out;
}

void Decompiler::buildStructure() {
    structures_.clear();
    for(const auto& fk:functions_) {
        StructuralGraph graph=structuralGraphFor(fk.first);if(!graph.nodes.count(fk.first))continue;
        auto branches=branchDescriptorsFor(graph);auto analysis=StructuredControl::analyze(graph,branches);
        if(!analysis.dominators.empty())++stats_.functionsWithDominatorTrees;
        for(const auto& d:analysis.dominators)if(d.second.immediateDominator>=0)++stats_.blocksWithImmediateDominator;
        for(const auto& d:analysis.postDominators)if(d.second.immediatePostDominator>=0)++stats_.blocksWithImmediatePostDominator;
        stats_.naturalLoops+=analysis.loops.size();stats_.fallbackBlocks+=analysis.fallbackBlocks.size();
        for(const auto* r:StructuredControl::flattenRegions(analysis.regions)) {
            switch(r->kind){case RegionKind::If:++stats_.structuredIfRegions;break;case RegionKind::IfElse:++stats_.structuredIfElseRegions;break;case RegionKind::While:++stats_.structuredWhileRegions;break;case RegionKind::DoWhile:++stats_.structuredDoWhileRegions;break;default:break;}
        }
        structures_[fk.first]=std::move(analysis);
    }
}

void Decompiler::buildStackModel() {
    stackBlocks_.clear();
    for(const auto& sk:structures_) {
        const auto& graph=sk.second.graph;if(!graph.nodes.count(sk.first))continue;++stats_.stackModeledFunctions;
        std::queue<std::uint16_t> q;stackBlocks_[sk.first].entryState=StackModel::initialState();stackBlocks_[sk.first].entryInitialized=true;q.push(sk.first);
        std::size_t guard=0;
        while(!q.empty()&&guard++<100000) {
            const auto b=q.front();q.pop();auto& info=stackBlocks_[b];if(!info.entryInitialized)continue;StackState exit=info.entryState;
            const auto& block=blocks_.at(b);
            for(auto a:block.instructions){const auto& in=analyzer_->instructions().at(a);StackModel::applyInstruction(in,exit,static_cast<int>(static_cast<std::uint16_t>(in.address+in.length())));}
            bool exitChanged=!info.exitInitialized||info.exitState.depthKnown!=exit.depthKnown||info.exitState.relativeDepth!=exit.relativeDepth||info.exitState.spKnown!=exit.spKnown||info.exitState.sp!=exit.sp||info.exitState.values!=exit.values;
            info.exitState=exit;info.exitInitialized=true;if(!exitChanged&&guard>graph.nodes.size())continue;
            const auto si=graph.successors.find(b);if(si==graph.successors.end())continue;
            StackState propagated=exit;
            if(!block.instructions.empty()) {
                const auto& terminal=analyzer_->instructions().at(block.instructions.back());
                if(terminal.flow==FlowKind::Call||terminal.flow==FlowKind::Restart) {
                    // The block-exit state above records the certain hardware push. Reaching
                    // the caller continuation also implies callee execution, whose net stack
                    // effect is unknown until separately proven.
                    propagated.depthKnown=false;propagated.spKnown=false;propagated.values.clear();
                }
            }
            for(auto t:si->second) {
                auto& target=stackBlocks_[t];const bool was=target.entryInitialized;bool changed=StackModel::merge(target.entryState,propagated,was);if(!was){target.entryInitialized=true;changed=true;}if(changed)q.push(t);
            }
        }
    }
    for(const auto& kv:stackBlocks_)if(kv.second.entryInitialized)++stats_.stackModeledBlocks;
}

void Decompiler::buildCallReturnEvidence() {
    callSites_.clear();observedReturns_.clear();returnMatches_.clear();callReturnEvidence_.clear();
    for(const auto& fk:functions_){FunctionCallReturnEvidence e;e.functionEntry=fk.first;callReturnEvidence_[fk.first]=e;}
    for(const auto& kv:analyzer_->instructions()) {
        const auto& in=kv.second;if(in.flow!=FlowKind::Call||in.target<0)continue;const auto callee=static_cast<std::uint16_t>(in.target);if(!functions_.count(callee))continue;
        const auto ib=instructionToBlock_.find(in.address);if(ib==instructionToBlock_.end())continue;const auto bi=blocks_.find(ib->second);if(bi==blocks_.end()||bi->second.functionOwners.size()!=1)continue;
        CallSiteRecord c;c.callerFunction=*bi->second.functionOwners.begin();c.callAddress=in.address;c.calleeFunction=callee;c.continuation=continuationAfter(in);callSites_.push_back(c);callReturnEvidence_[callee].staticCallers.insert(c.callerFunction);callReturnEvidence_[callee].staticContinuations.insert(c.continuation);
    }
    stats_.staticCallSites=callSites_.size();
    for(const auto& bk:blocks_)for(const auto& edge:bk.second.outgoing) {
        if(edge.kind!=CfgEdgeKind::DynamicReturn||edge.to<0) continue;
        ObservedReturnRecord r;r.returnAddress=edge.from;r.destination=static_cast<std::uint16_t>(edge.to);r.count=edge.observedCount;
        if(bk.second.functionOwners.size()==1) r.calleeFunction=*bk.second.functionOwners.begin();
        observedReturns_.push_back(r);
    }
    returnMatches_=StackModel::matchReturns(callSites_,observedReturns_);stats_.observedReturnRecords=returnMatches_.size();
    for(const auto& m:returnMatches_) {
        if(m.observed.calleeFunction<0) continue;
        auto it=callReturnEvidence_.find(static_cast<std::uint16_t>(m.observed.calleeFunction));
        if(it==callReturnEvidence_.end()) continue;
        it->second.observedReturnDestinations[m.observed.destination]+=m.observed.count;
        if(m.matchesKnownContinuation){it->second.matchedObservedReturnTransitions+=m.observed.count;stats_.observedReturnsMatchingKnownContinuations+=m.observed.count;}
        else it->second.unmatchedObservedReturnTransitions+=m.observed.count;
    }
}

static AbstractValue getReg(const RegisterState&s,const std::string&r,unsigned bits){auto it=s.regs.find(r);return it==s.regs.end()?unknown(bits):it->second;}
static void putReg(RegisterState&s,const std::string&r,const AbstractValue&v){s.regs[r]=v;}
static void invalidate8(RegisterState&s,const std::string&r){putReg(s,r,unknown(8));}
static void invalidate16(RegisterState&s,const std::string&r){putReg(s,r,unknown(16));}
static void invalidatePair(RegisterState&s,const std::string&r){
    invalidate16(s,r);
    if(r=="BC"){invalidate8(s,"B");invalidate8(s,"C");}
    else if(r=="DE"){invalidate8(s,"D");invalidate8(s,"E");}
    else if(r=="HL"){invalidate8(s,"H");invalidate8(s,"L");}
}
static void setPair(RegisterState&s,const std::string&r,std::uint16_t v){putReg(s,r,known(v,16));if(r=="BC"){putReg(s,"B",known(v>>8,8));putReg(s,"C",known(v,8));}else if(r=="DE"){putReg(s,"D",known(v>>8,8));putReg(s,"E",known(v,8));}else if(r=="HL"){putReg(s,"H",known(v>>8,8));putReg(s,"L",known(v,8));}}
static void syncPairFromBytes(RegisterState&s,const std::string&pair,const std::string&hi,const std::string&lo){auto h=getReg(s,hi,8),l=getReg(s,lo,8);if(h.known&&l.known)putReg(s,pair,known((h.value<<8)|l.value,16));else invalidate16(s,pair);}
static void setByte(RegisterState&s,const std::string&r,std::uint8_t v){putReg(s,r,known(v,8));if(r=="B"||r=="C")syncPairFromBytes(s,"BC","B","C");else if(r=="D"||r=="E")syncPairFromBytes(s,"DE","D","E");else if(r=="H"||r=="L")syncPairFromBytes(s,"HL","H","L");}
static void invalidateByte(RegisterState&s,const std::string&r){invalidate8(s,r);if(r=="B"||r=="C")invalidate16(s,"BC");else if(r=="D"||r=="E")invalidate16(s,"DE");else if(r=="H"||r=="L")invalidate16(s,"HL");}

void Decompiler::transferInstruction(const Instruction& in,RegisterState& s) const{
    const auto& b=in.bytes;if(b.empty())return;
    // Prefix-aware immediate pair loads.
    if(b.size()>=3&&(b[0]==0x01||b[0]==0x11||b[0]==0x21||b[0]==0x31)){const std::uint16_t v=b[1]|(b[2]<<8);const char* r=b[0]==0x01?"BC":b[0]==0x11?"DE":b[0]==0x21?"HL":"SP";setPair(s,r,v);return;}
    if(b.size()>=4&&(b[0]==0xDD||b[0]==0xFD)&&b[1]==0x21){putReg(s,b[0]==0xDD?"IX":"IY",known((std::uint16_t)(b[2]|(b[3]<<8)),16));return;}
    // LD r,n
    static const std::map<std::uint8_t,std::string> imm8={{0x06,"B"},{0x0E,"C"},{0x16,"D"},{0x1E,"E"},{0x26,"H"},{0x2E,"L"},{0x3E,"A"}};
    auto i8=imm8.find(b[0]);if(i8!=imm8.end()&&b.size()>=2){setByte(s,i8->second,b[1]);return;}
    if(b[0]==0xAF){setByte(s,"A",0);return;} // XOR A
    if(b[0]==0x3A){invalidateByte(s,"A");return;} // LD A,(nn)
    if(b[0]==0x2A){invalidate16(s,"HL");invalidateByte(s,"H");invalidateByte(s,"L");return;}
    if(b[0]==0xED&&b.size()>=2){if(b[1]==0x4B)invalidate16(s,"BC");else if(b[1]==0x5B)invalidate16(s,"DE");else if(b[1]==0x6B)invalidate16(s,"HL");else if(b[1]==0x7B)invalidate16(s,"SP");return;}
    // Common LD r,r forms.
    if(b[0]>=0x40&&b[0]<=0x7F&&b[0]!=0x76){static const char* rs[]={"B","C","D","E","H","L","(HL)","A"};const int d=(b[0]>>3)&7,src=b[0]&7;if(d!=6){if(src==6)invalidateByte(s,rs[d]);else{auto v=getReg(s,rs[src],8);putReg(s,rs[d],v);if(!v.known)invalidateByte(s,rs[d]);else setByte(s,rs[d],(std::uint8_t)v.value);}}return;}
    // INC/DEC 8 bit.
    const std::map<std::uint8_t,std::pair<std::string,int>> id8={{0x04,{"B",1}},{0x05,{"B",-1}},{0x0C,{"C",1}},{0x0D,{"C",-1}},{0x14,{"D",1}},{0x15,{"D",-1}},{0x1C,{"E",1}},{0x1D,{"E",-1}},{0x24,{"H",1}},{0x25,{"H",-1}},{0x2C,{"L",1}},{0x2D,{"L",-1}},{0x3C,{"A",1}},{0x3D,{"A",-1}}};
    auto d8=id8.find(b[0]);if(d8!=id8.end()){auto v=getReg(s,d8->second.first,8);if(v.known)setByte(s,d8->second.first,(std::uint8_t)(v.value+d8->second.second));else invalidateByte(s,d8->second.first);return;}
    // INC/DEC pairs.
    const std::map<std::uint8_t,std::pair<std::string,int>> id16={{0x03,{"BC",1}},{0x0B,{"BC",-1}},{0x13,{"DE",1}},{0x1B,{"DE",-1}},{0x23,{"HL",1}},{0x2B,{"HL",-1}},{0x33,{"SP",1}},{0x3B,{"SP",-1}}};
    auto d16=id16.find(b[0]);if(d16!=id16.end()){auto v=getReg(s,d16->second.first,16);if(v.known)setPair(s,d16->second.first,(std::uint16_t)(v.value+d16->second.second));else invalidate16(s,d16->second.first);return;}
    if(b[0]==0xEB){auto de=getReg(s,"DE",16),hl=getReg(s,"HL",16);putReg(s,"DE",hl);putReg(s,"HL",de);if(de.known)setPair(s,"HL",de.value);else{invalidate16(s,"HL");invalidateByte(s,"H");invalidateByte(s,"L");}if(hl.known)setPair(s,"DE",hl.value);else{invalidate16(s,"DE");invalidateByte(s,"D");invalidateByte(s,"E");}return;}
    if(b[0]==0xF9){putReg(s,"SP",getReg(s,"HL",16));return;}
    if(in.mnemonic=="DJNZ") { auto v=getReg(s,"B",8); if(v.known)setByte(s,"B",static_cast<std::uint8_t>(v.value-1)); else invalidateByte(s,"B"); return; }
    // ADD HL,rr (carry out affects flags, not the 16-bit arithmetic result).
    if(b[0]==0x09||b[0]==0x19||b[0]==0x29||b[0]==0x39){const char* rr=b[0]==0x09?"BC":b[0]==0x19?"DE":b[0]==0x29?"HL":"SP";auto x=getReg(s,"HL",16),y=getReg(s,rr,16);if(x.known&&y.known)setPair(s,"HL",static_cast<std::uint16_t>(x.value+y.value));else invalidatePair(s,"HL");return;}
    if(b.size()>=2&&(b[0]==0xDD||b[0]==0xFD)&&(b[1]==0x09||b[1]==0x19||b[1]==0x29||b[1]==0x39)){const std::string dst=b[0]==0xDD?"IX":"IY";const char* rr=b[1]==0x09?"BC":b[1]==0x19?"DE":b[1]==0x29?(b[0]==0xDD?"IX":"IY"):"SP";auto x=getReg(s,dst,16),y=getReg(s,rr,16);if(x.known&&y.known)putReg(s,dst,known(static_cast<std::uint16_t>(x.value+y.value),16));else invalidate16(s,dst);return;}
    if(b.size()>=2&&(b[0]==0xDD||b[0]==0xFD)&&(b[1]==0x23||b[1]==0x2B)){const std::string r=b[0]==0xDD?"IX":"IY";auto v=getReg(s,r,16);if(v.known)putReg(s,r,known(static_cast<std::uint16_t>(v.value+(b[1]==0x23?1:-1)),16));else invalidate16(s,r);return;}
    // Register-source A arithmetic/logical groups. ADC/SBC depend on carry and are invalidated.
    if(b[0]>=0x80&&b[0]<=0xBF){const unsigned group=(b[0]>>3)&7,src=b[0]&7;static const char* rs[]={"B","C","D","E","H","L","(HL)","A"};if(group==7)return; // CP
        if(group==1||group==3){invalidateByte(s,"A");return;} // ADC/SBC
        auto a=getReg(s,"A",8);AbstractValue x=src==6?unknown(8):getReg(s,rs[src],8);if(!a.known||!x.known){invalidateByte(s,"A");return;}std::uint8_t v=static_cast<std::uint8_t>(a.value),q=static_cast<std::uint8_t>(x.value);switch(group){case 0:v=static_cast<std::uint8_t>(v+q);break;case 2:v=static_cast<std::uint8_t>(v-q);break;case 4:v&=q;break;case 5:v^=q;break;case 6:v|=q;break;default:break;}setByte(s,"A",v);return;}
    // Immediate A arithmetic/logical subset.
    if(b.size()>=2&&(b[0]==0xC6||b[0]==0xD6||b[0]==0xE6||b[0]==0xEE||b[0]==0xF6)){auto a=getReg(s,"A",8);if(!a.known){invalidateByte(s,"A");return;}std::uint8_t v=(std::uint8_t)a.value;switch(b[0]){case 0xC6:v=(std::uint8_t)(v+b[1]);break;case 0xD6:v=(std::uint8_t)(v-b[1]);break;case 0xE6:v&=b[1];break;case 0xEE:v^=b[1];break;case 0xF6:v|=b[1];break;}setByte(s,"A",v);return;}
    if(in.mnemonic=="PUSH"){auto sp=getReg(s,"SP",16);if(sp.known)putReg(s,"SP",known(static_cast<std::uint16_t>(sp.value-2),16));else invalidate16(s,"SP");return;}
    if(in.mnemonic=="POP"){auto ops=splitOperands(in.operands);if(!ops.empty()){if(ops[0]=="AF")invalidateByte(s,"A");else invalidatePair(s,ops[0]);}auto sp=getReg(s,"SP",16);if(sp.known)putReg(s,"SP",known(static_cast<std::uint16_t>(sp.value+2),16));else invalidate16(s,"SP");return;}
    // Calls/restarts can run arbitrary hand-written code; do not assume a compiler ABI.
    if(in.flow==FlowKind::Call||in.flow==FlowKind::Restart){for(const char* r:{"A","B","C","D","E","H","L"})invalidateByte(s,r);for(const char* r:{"BC","DE","HL","SP","IX","IY"})invalidate16(s,r);return;}

    // Conservative fallback for mutating instructions not modeled above. This is intentionally
    // biased toward losing a constant rather than preserving a false one.
    const auto ops=splitOperands(in.operands);
    auto invalidateNamed=[&](const std::string&r){
        if(r=="A"||r=="B"||r=="C"||r=="D"||r=="E"||r=="H"||r=="L") invalidateByte(s,r);
        else if(r=="BC"||r=="DE"||r=="HL") invalidatePair(s,r);
        else if(r=="SP"||r=="IX"||r=="IY") invalidate16(s,r);
        else if(r=="AF") invalidateByte(s,"A");
    };
    if(in.mnemonic=="LD"&&!ops.empty()){invalidateNamed(ops[0]);return;}
    if((in.mnemonic=="INC"||in.mnemonic=="DEC")&&!ops.empty()){invalidateNamed(ops[0]);return;}
    if(in.mnemonic=="ADD"||in.mnemonic=="ADC"||in.mnemonic=="SBC"){if(ops.size()>=2)invalidateNamed(ops[0]);else invalidateByte(s,"A");return;}
    if(in.mnemonic=="SUB"||in.mnemonic=="AND"||in.mnemonic=="OR"||in.mnemonic=="XOR"||in.mnemonic=="NEG"||in.mnemonic=="DAA"||in.mnemonic=="CPL"||in.mnemonic=="RLCA"||in.mnemonic=="RRCA"||in.mnemonic=="RLA"||in.mnemonic=="RRA"||in.mnemonic=="RLD"||in.mnemonic=="RRD"){invalidateByte(s,"A");return;}
    if(in.mnemonic=="EXX"){invalidatePair(s,"BC");invalidatePair(s,"DE");invalidatePair(s,"HL");return;}
    if(in.mnemonic=="EX"&&!ops.empty()){if(in.operands.find("AF")!=std::string::npos)invalidateByte(s,"A");else{invalidatePair(s,"DE");invalidatePair(s,"HL");}return;}
    if(in.mnemonic=="IN"&&!ops.empty()){invalidateNamed(ops[0]);return;}
    if(in.mnemonic=="LDI"||in.mnemonic=="LDIR"||in.mnemonic=="LDD"||in.mnemonic=="LDDR"){invalidatePair(s,"BC");invalidatePair(s,"DE");invalidatePair(s,"HL");return;}
    if(in.mnemonic=="CPI"||in.mnemonic=="CPIR"||in.mnemonic=="CPD"||in.mnemonic=="CPDR"){invalidatePair(s,"BC");invalidatePair(s,"HL");return;}
    if(in.mnemonic=="RLC"||in.mnemonic=="RRC"||in.mnemonic=="RL"||in.mnemonic=="RR"||in.mnemonic=="SLA"||in.mnemonic=="SRA"||in.mnemonic=="SLL"||in.mnemonic=="SRL"||in.mnemonic=="RES"||in.mnemonic=="SET"){if(!ops.empty())invalidateNamed(ops.back());return;}
}

RegisterState Decompiler::transferBlock(const BasicBlock& b,const RegisterState& entry) const{RegisterState s=entry;for(auto a:b.instructions)transferInstruction(analyzer_->instructions().at(a),s);return s;}

bool Decompiler::mergeState(RegisterState& dst,const RegisterState& src,bool initialized) const{
    static const char* regs[]={"A","B","C","D","E","H","L","BC","DE","HL","SP","IX","IY"};bool changed=false;
    if(!initialized){dst=src;return true;}
    for(const char* r:regs){const unsigned bits=std::string(r).size()==1?8:16;auto a=getReg(dst,r,bits),b=getReg(src,r,bits);AbstractValue m=(a.known&&b.known&&a.value==b.value)?known(a.value,bits):unknown(bits);if(!sameValue(a,m)){dst.regs[r]=m;changed=true;}}
    return changed;
}

void Decompiler::propagateValues(){
    std::map<std::uint16_t,bool> init;std::queue<std::uint16_t> q;
    // Every function entry begins from an unknown state. Reset vector gets a conventional known SP only if code establishes it itself; no guesses here.
    for(auto e:functionEntries_)if(blocks_.count(e)){init[e]=true;q.push(e);}
    if(q.empty()&&!blocks_.empty()){init[blocks_.begin()->first]=true;q.push(blocks_.begin()->first);}
    std::size_t guard=0;
    while(!q.empty()&&guard++<200000){const auto a=q.front();q.pop();auto it=blocks_.find(a);if(it==blocks_.end())continue;BasicBlock& b=it->second;const RegisterState newExit=transferBlock(b,b.entryState);bool exitChanged=false;
        static const char* regs[]={"A","B","C","D","E","H","L","BC","DE","HL","SP","IX","IY"};for(const char* r:regs){unsigned bits=std::string(r).size()==1?8:16;if(!sameValue(getReg(b.exitState,r,bits),getReg(newExit,r,bits))){exitChanged=true;break;}}
        b.exitState=newExit;
        if(!exitChanged&&guard>blocks_.size())continue;
        for(const auto&e:b.outgoing){if(e.to<0||e.kind==CfgEdgeKind::Call||e.kind==CfgEdgeKind::Restart||e.kind==CfgEdgeKind::Dispatch)continue;auto bi=blocks_.find((std::uint16_t)e.to);if(bi==blocks_.end())continue;bool was=init[bi->first];bool changed=mergeState(bi->second.entryState,b.exitState,was);if(!was){init[bi->first]=true;changed=true;}if(changed)q.push(bi->first);}
    }
    stats_.propagatedBlockEntries=0;stats_.constantRegisterFacts=0;
    for(const auto& kv:blocks_){auto ii=init.find(kv.first);if(ii!=init.end()&&ii->second)++stats_.propagatedBlockEntries;for(const auto& rv:kv.second.entryState.regs)if(rv.second.known)++stats_.constantRegisterFacts;}
}


void Decompiler::buildRomClosure(){
    romConsumers_.clear();
    romClosureBytes_.clear();
    ramPairEvidence_.clear();
    stats_.romClosure={};
    if(!analyzer_)return;
    const auto& program=analyzer_->program();
    if(program.empty())return;

    romClosureBytes_.resize(program.size());
    for(std::size_t i=0;i<romClosureBytes_.size();++i)romClosureBytes_[i].address=static_cast<std::uint16_t>(i);

    // The closure map is deliberately non-exclusive. A byte can be executable and also
    // observed/read as data. Primary labels are selected only for presentation.
    for(const auto& kv:analyzer_->instructions()){
        const auto& in=kv.second;
        for(std::size_t n=0;n<in.length()&&static_cast<std::size_t>(in.address)+n<program.size();++n)
            romClosureBytes_[static_cast<std::size_t>(in.address)+n].code=true;
    }
    for(const auto& kv:analyzer_->dataRegions()){
        const auto& r=kv.second;
        for(std::size_t a=r.start;a<r.end&&a<program.size();++a)romClosureBytes_[a].hardData=true;
    }
    for(const auto& c:analyzer_->dataCandidates())
        for(std::size_t a=c.start;a<c.end&&a<program.size();++a)romClosureBytes_[a].candidate=true;

    auto addConsumer=[&](RomConsumerRecord rec){
        if(rec.start>=program.size()||rec.end<=rec.start)return;
        rec.end=static_cast<std::uint16_t>(std::min<std::size_t>(program.size(),rec.end));
        romConsumers_.push_back(rec);
        for(std::size_t a=rec.start;a<rec.end;++a){
            auto& b=romClosureBytes_[a];
            b.consumerPCs.insert(rec.pc);
            if(rec.dynamic)b.dynamicDataUse=true;
            if(rec.exact&&!rec.dynamic)b.staticExactDataUse=true;
            if(rec.bounded)b.boundedConsumer=true;
        }
    };

    // Dynamic non-fetch reads are factual data-use evidence. They remain non-exclusive:
    // a byte can still be executable in another context.
    for(const auto& kv:analyzer_->romDataUsage()){
        for(auto pc:kv.second.sourcePCs){
            RomConsumerRecord r;r.pc=pc;r.start=kv.first;r.end=static_cast<std::uint16_t>(kv.first+1);
            r.kind=RomConsumerKind::DynamicObservedRead;r.exact=true;r.dynamic=true;
            r.note="observed non-fetch ROM read on imported Pacman Arcade bus trace";
            addConsumer(r);
        }
    }

    auto immediatePair=[&](const Instruction& in,std::string& reg,std::uint16_t& value)->bool{
        const auto& b=in.bytes;
        if(b.size()>=3&&(b[0]==0x01||b[0]==0x11||b[0]==0x21||b[0]==0x31)){
            reg=b[0]==0x01?"BC":b[0]==0x11?"DE":b[0]==0x21?"HL":"SP";
            value=static_cast<std::uint16_t>(b[1]|(static_cast<std::uint16_t>(b[2])<<8));return true;
        }
        if(b.size()>=4&&(b[0]==0xDD||b[0]==0xFD)&&b[1]==0x21){
            reg=b[0]==0xDD?"IX":"IY";value=static_cast<std::uint16_t>(b[2]|(static_cast<std::uint16_t>(b[3])<<8));return true;
        }
        return false;
    };

    for(const auto& kv:analyzer_->instructions()){
        std::string reg;std::uint16_t value=0;
        if(immediatePair(kv.second,reg,value)&&value<program.size()){
            romClosureBytes_[value].pointerTarget=true;
            ++stats_.romClosure.immediateRomPointerSeeds;
        }
    }

    struct ByteRange{bool known=false;unsigned lo=0,hi=255;};
    using RangeMap=std::map<std::string,ByteRange>;
    auto exactRange=[](unsigned v){ByteRange r;r.known=true;r.lo=r.hi=v&0xFFu;return r;};
    auto unknownRange=[](){return ByteRange{};};
    auto getRange=[&](const RangeMap& m,const std::string& r){auto it=m.find(r);return it==m.end()?unknownRange():it->second;};
    auto setUnknown=[&](RangeMap& m,const std::string& r){m[r]=unknownRange();};
    auto setExact=[&](RangeMap& m,const std::string& r,unsigned v){m[r]=exactRange(v);};
    auto initRanges=[&](const RegisterState& state){
        RangeMap m;for(const char* r:{"A","B","C","D","E","H","L"}){auto v=getReg(state,r,8);if(v.known)setExact(m,r,v.value);else setUnknown(m,r);}return m;
    };
    auto invalidateAllRanges=[&](RangeMap& m){for(const char* r:{"A","B","C","D","E","H","L"})setUnknown(m,r);};
    auto rangeTransfer=[&](const Instruction& in,RangeMap& m){
        const auto& b=in.bytes;if(b.empty())return;
        static const std::map<std::uint8_t,std::string> imm8={{0x06,"B"},{0x0E,"C"},{0x16,"D"},{0x1E,"E"},{0x26,"H"},{0x2E,"L"},{0x3E,"A"}};
        auto ii=imm8.find(b[0]);if(ii!=imm8.end()&&b.size()>=2){setExact(m,ii->second,b[1]);return;}
        if(b[0]==0xAF){setExact(m,"A",0);return;}
        if(b[0]>=0x40&&b[0]<=0x7F&&b[0]!=0x76){static const char* rs[]={"B","C","D","E","H","L","(HL)","A"};const int d=(b[0]>>3)&7,src=b[0]&7;if(d!=6){if(src==6)setUnknown(m,rs[d]);else m[rs[d]]=getRange(m,rs[src]);}return;}
        const std::map<std::uint8_t,std::pair<std::string,int>> id8={{0x04,{"B",1}},{0x05,{"B",-1}},{0x0C,{"C",1}},{0x0D,{"C",-1}},{0x14,{"D",1}},{0x15,{"D",-1}},{0x1C,{"E",1}},{0x1D,{"E",-1}},{0x24,{"H",1}},{0x25,{"H",-1}},{0x2C,{"L",1}},{0x2D,{"L",-1}},{0x3C,{"A",1}},{0x3D,{"A",-1}}};
        auto di=id8.find(b[0]);if(di!=id8.end()){auto r=getRange(m,di->second.first);if(r.known&&((di->second.second>0&&r.hi<255)||(di->second.second<0&&r.lo>0))){r.lo=static_cast<unsigned>(static_cast<int>(r.lo)+di->second.second);r.hi=static_cast<unsigned>(static_cast<int>(r.hi)+di->second.second);m[di->second.first]=r;}else setUnknown(m,di->second.first);return;}
        if(in.mnemonic=="DJNZ"){auto r=getRange(m,"B");if(r.known&&r.lo>0){--r.lo;--r.hi;m["B"]=r;}else setUnknown(m,"B");return;}
        if(b.size()>=2&&b[0]==0xE6){auto r=getRange(m,"A");(void)r;ByteRange q;q.known=true;q.lo=0;q.hi=b[1];m["A"]=q;return;}
        if(b.size()>=2&&b[0]==0xC6){auto r=getRange(m,"A");if(r.known&&r.hi+b[1]<=255){r.lo+=b[1];r.hi+=b[1];m["A"]=r;}else setUnknown(m,"A");return;}
        if(b.size()>=2&&b[0]==0xD6){auto r=getRange(m,"A");if(r.known&&r.lo>=b[1]){r.lo-=b[1];r.hi-=b[1];m["A"]=r;}else setUnknown(m,"A");return;}
        if(b[0]==0x87){auto r=getRange(m,"A");if(r.known&&r.hi<=127){r.lo*=2;r.hi*=2;m["A"]=r;}else setUnknown(m,"A");return;}
        if(b[0]>=0x80&&b[0]<=0x87){static const char* rs[]={"B","C","D","E","H","L","(HL)","A"};const int src=b[0]&7;if(src==6){setUnknown(m,"A");return;}auto a=getRange(m,"A"),x=getRange(m,rs[src]);if(a.known&&x.known&&a.hi+x.hi<=255){a.lo+=x.lo;a.hi+=x.hi;m["A"]=a;}else setUnknown(m,"A");return;}
        if(b[0]==0x2F){auto r=getRange(m,"A");if(r.known){const unsigned lo=255-r.hi,hi=255-r.lo;r.lo=lo;r.hi=hi;m["A"]=r;}else setUnknown(m,"A");return;}
        if(b[0]==0x07){auto r=getRange(m,"A");if(r.known&&r.lo==r.hi){const unsigned v=r.lo;m["A"]=exactRange(((v<<1)|(v>>7))&0xFF);}else setUnknown(m,"A");return;}
        if(b[0]==0x0F){auto r=getRange(m,"A");if(r.known&&r.lo==r.hi){const unsigned v=r.lo;m["A"]=exactRange(((v>>1)|(v<<7))&0xFF);}else setUnknown(m,"A");return;}
        if(in.mnemonic=="CP"||in.mnemonic=="BIT"||in.mnemonic=="SCF"||in.mnemonic=="CCF"||in.mnemonic=="NOP")return;
        if(in.flow==FlowKind::Call||in.flow==FlowKind::Restart){invalidateAllRanges(m);return;}
        const auto ops=splitOperands(in.operands);
        auto invalidateNamed=[&](const std::string& r){if(r=="A"||r=="B"||r=="C"||r=="D"||r=="E"||r=="H"||r=="L")setUnknown(m,r);else if(r=="BC"){setUnknown(m,"B");setUnknown(m,"C");}else if(r=="DE"){setUnknown(m,"D");setUnknown(m,"E");}else if(r=="HL"){setUnknown(m,"H");setUnknown(m,"L");}else if(r=="AF")setUnknown(m,"A");};
        if(in.mnemonic=="LD"&&!ops.empty()){invalidateNamed(ops[0]);return;}
        if((in.mnemonic=="INC"||in.mnemonic=="DEC")&&!ops.empty()){invalidateNamed(ops[0]);return;}
        if(in.mnemonic=="ADD"||in.mnemonic=="ADC"||in.mnemonic=="SBC"){if(ops.size()>=2)invalidateNamed(ops[0]);else setUnknown(m,"A");return;}
        if(in.mnemonic=="SUB"||in.mnemonic=="AND"||in.mnemonic=="OR"||in.mnemonic=="XOR"||in.mnemonic=="NEG"||in.mnemonic=="DAA"||in.mnemonic=="CPL"||in.mnemonic=="RLCA"||in.mnemonic=="RRCA"||in.mnemonic=="RLA"||in.mnemonic=="RRA"||in.mnemonic=="RLD"||in.mnemonic=="RRD"){setUnknown(m,"A");return;}
        if(in.mnemonic=="EXX"){for(const char* r:{"B","C","D","E","H","L"})setUnknown(m,r);return;}
        if(in.mnemonic=="EX"){for(const char* r:{"A","D","E","H","L"})setUnknown(m,r);return;}
        if(in.mnemonic=="POP"){if(!ops.empty())invalidateNamed(ops[0]);return;}
    };

    // ROM-closure analysis interval propagation across static structural CFG edges.  The older
    // local replay intentionally knew only values available at a basic-block
    // entry from constant propagation constant propagation.  That loses useful-but-still-safe
    // facts at merges such as "B is either $08 or $09".  Here we compute a
    // conservative interval hull per byte register.  Unknown on either incoming
    // path remains unknown; otherwise the join is [min(lo), max(hi)].  Dynamic
    // edges, calls, restarts and dispatch edges are never used as proof.
    std::map<std::uint16_t,RangeMap> propagatedRangeEntries;
    std::map<std::uint16_t,bool> propagatedRangeInitialized;
    auto sameRange=[](const ByteRange& a,const ByteRange& b){return a.known==b.known&&(!a.known||(a.lo==b.lo&&a.hi==b.hi));};
    auto mergeRanges=[&](RangeMap& dst,const RangeMap& src,bool initialized){
        bool changed=false;
        if(!initialized){dst=src;return true;}
        for(const char* r:{"A","B","C","D","E","H","L"}){
            const auto a=getRange(dst,r),b=getRange(src,r);ByteRange m;
            if(a.known&&b.known){m.known=true;m.lo=std::min(a.lo,b.lo);m.hi=std::max(a.hi,b.hi);}
            if(!sameRange(a,m)){dst[r]=m;changed=true;}
        }
        return changed;
    };
    std::queue<std::uint16_t> rangeQueue;
    for(auto entry:functionEntries_){
        if(!blocks_.count(entry))continue;
        propagatedRangeEntries[entry]=initRanges(RegisterState{});
        propagatedRangeInitialized[entry]=true;
        rangeQueue.push(entry);
    }
    if(rangeQueue.empty()&&!blocks_.empty()){
        propagatedRangeEntries[blocks_.begin()->first]=initRanges(RegisterState{});
        propagatedRangeInitialized[blocks_.begin()->first]=true;
        rangeQueue.push(blocks_.begin()->first);
    }
    std::size_t rangeGuard=0;
    while(!rangeQueue.empty()&&rangeGuard++<500000){
        const auto ba=rangeQueue.front();rangeQueue.pop();auto bi=blocks_.find(ba);if(bi==blocks_.end())continue;
        RangeMap out=propagatedRangeEntries[ba];
        for(auto ia:bi->second.instructions)rangeTransfer(analyzer_->instructions().at(ia),out);
        for(const auto& e:bi->second.outgoing){
            if(e.to<0||!isStructuralEdge(e.kind))continue;
            const auto to=static_cast<std::uint16_t>(e.to);if(!blocks_.count(to))continue;
            const bool was=propagatedRangeInitialized[to];
            bool changed=mergeRanges(propagatedRangeEntries[to],out,was);
            if(!was){propagatedRangeInitialized[to]=true;changed=true;}
            if(changed)rangeQueue.push(to);
        }
    }
    auto rangesAtBlock=[&](std::uint16_t blockAddress,const RegisterState& fallback){
        auto it=propagatedRangeInitialized.find(blockAddress);
        if(it!=propagatedRangeInitialized.end()&&it->second)return propagatedRangeEntries[blockAddress];
        return initRanges(fallback);
    };

    auto parseIndexed=[&](const std::string& op,std::string& reg,int& disp)->bool{
        if(op.size()<4||op.front()!='('||op.back()!=')')return false;
        if(op=="(HL)"||op=="(DE)"||op=="(BC)"){reg=op.substr(1,2);disp=0;return true;}
        if(op.rfind("(IX",0)!=0&&op.rfind("(IY",0)!=0)return false;
        reg=op.substr(1,2);disp=0;
        const std::string inner=op.substr(3,op.size()-4);
        if(inner.empty())return true;
        char* end=nullptr;long v=std::strtol(inner.c_str(),&end,10);if(end&&*end=='\0'){disp=static_cast<int>(v);return true;}
        return false;
    };
    auto resolveOperand=[&](const std::string& op,const RegisterState& state,std::string& reg,std::uint16_t& address)->bool{
        int disp=0;if(!parseIndexed(op,reg,disp))return false;auto v=getReg(state,reg,16);if(!v.known)return false;address=static_cast<std::uint16_t>(v.value+disp);return true;
    };
    auto memoryReadOperands=[&](const Instruction& in){
        std::vector<std::string> reads;const auto ops=splitOperands(in.operands);
        if(in.mnemonic=="LD"){
            if(ops.size()>=2&&ops[1].find('(')!=std::string::npos)reads.push_back(ops[1]);
        }else if(in.mnemonic=="INC"||in.mnemonic=="DEC"||in.mnemonic=="BIT"||in.mnemonic=="RES"||in.mnemonic=="SET"||in.mnemonic=="RLC"||in.mnemonic=="RRC"||in.mnemonic=="RL"||in.mnemonic=="RR"||in.mnemonic=="SLA"||in.mnemonic=="SRA"||in.mnemonic=="SLL"||in.mnemonic=="SRL"){
            if(!ops.empty()&&ops.back().find('(')!=std::string::npos)reads.push_back(ops.back());
        }else if(in.mnemonic=="ADD"||in.mnemonic=="ADC"||in.mnemonic=="SUB"||in.mnemonic=="SBC"||in.mnemonic=="AND"||in.mnemonic=="XOR"||in.mnemonic=="OR"||in.mnemonic=="CP"){
            for(const auto& op:ops)if(op.find('(')!=std::string::npos)reads.push_back(op);
        }
        return reads;
    };

    for(const auto& bk:blocks_){
        RegisterState state=bk.second.entryState;RangeMap ranges=rangesAtBlock(bk.first,state);
        for(auto a:bk.second.instructions){
            const auto& in=analyzer_->instructions().at(a);

            for(const auto& mr:in.memoryRefs){
                if(mr.address<program.size()&&(mr.access==RefAccess::Read||mr.access==RefAccess::ReadWrite)){
                    RomConsumerRecord r;r.pc=in.address;r.start=mr.address;r.end=static_cast<std::uint16_t>(mr.address+1);r.kind=RomConsumerKind::DirectAbsoluteRead;r.exact=true;r.note="absolute ROM address encoded by instruction";addConsumer(r);
                }
            }

            for(const auto& op:memoryReadOperands(in)){
                std::string reg;std::uint16_t address=0;if(resolveOperand(op,state,reg,address)&&address<program.size()){
                    RomConsumerRecord r;r.pc=in.address;r.start=address;r.end=static_cast<std::uint16_t>(address+1);r.pointerRegister=reg;r.exact=true;
                    r.kind=(reg=="IX"||reg=="IY")?RomConsumerKind::IndexedRegisterRead:RomConsumerKind::IndirectRegisterRead;
                    r.note="pointer value proven by conservative register propagation";addConsumer(r);
                }
            }

            if(in.mnemonic=="LDI"||in.mnemonic=="LDD"){
                auto hl=getReg(state,"HL",16);if(hl.known&&hl.value<program.size()){
                    RomConsumerRecord r;r.pc=in.address;r.start=hl.value;r.end=static_cast<std::uint16_t>(hl.value+1);r.kind=RomConsumerKind::BlockTransferRead;r.pointerRegister="HL";r.exact=true;r.note="single-byte Z80 block transfer source";addConsumer(r);
                }
            }else if(in.mnemonic=="LDIR"||in.mnemonic=="LDDR"||in.mnemonic=="CPIR"||in.mnemonic=="CPDR"){
                auto hl=getReg(state,"HL",16),bc=getReg(state,"BC",16);if(hl.known&&bc.known&&bc.value>0){
                    std::uint32_t lo=hl.value,hi=hl.value;
                    if(in.mnemonic=="LDIR"||in.mnemonic=="CPIR")hi=lo+bc.value;else{if(lo+1>=bc.value){lo=lo+1-bc.value;hi=hl.value+1;}else hi=0;}
                    if(hi>lo&&hi<=program.size()){
                        RomConsumerRecord r;r.pc=in.address;r.start=static_cast<std::uint16_t>(lo);r.end=static_cast<std::uint16_t>(hi);r.kind=RomConsumerKind::BlockTransferRead;r.pointerRegister="HL";r.exact=true;r.note="block instruction count and source pointer both proven";addConsumer(r);
                    }
                }
            }

            if(in.mnemonic=="POP"){
                auto sp=getReg(state,"SP",16);if(sp.known&&static_cast<std::size_t>(sp.value)+1u<program.size()){
                    RomConsumerRecord r;r.pc=in.address;r.start=sp.value;r.end=static_cast<std::uint16_t>(sp.value+2);r.kind=RomConsumerKind::StackRead;r.pointerRegister="SP";r.exact=true;r.note="POP with statically proven SP inside program ROM";addConsumer(r);
                }
            }

            if(in.flow==FlowKind::Restart&&(in.target==0x10||in.target==0x18)){
                auto hl=getReg(state,"HL",16);
                const std::string idx=in.target==0x10?"A":"B";const auto br=getRange(ranges,idx);
                if(hl.known&&br.known){
                    const std::uint16_t scale=in.target==0x10?1u:2u;
                    std::uint16_t lo=0,hi=0;
                    if(RomClosure::boundedLookupRange(hl.value,br.lo,br.hi,scale,program.size(),lo,hi)){
                        RomConsumerRecord r;r.pc=in.address;r.start=lo;r.end=hi;r.pointerRegister="HL";r.indexRegister=idx;
                        r.kind=in.target==0x10?RomConsumerKind::Rst10ByteLookup:RomConsumerKind::Rst18WordLookup;
                        r.exact=br.lo==br.hi;r.bounded=br.lo!=br.hi;
                        std::ostringstream note;note<<"Pac-Man lookup helper with proven HL base and "<<idx<<" range "<<br.lo;
                        if(br.lo!=br.hi) note<<".."<<br.hi;
                        note<<" from local value/range evidence";r.note=note.str();addConsumer(r);
                    }
                }
            }

            transferInstruction(in,state);rangeTransfer(in,ranges);
        }
    }

    // ROM-closure analysis protocol closure. These recognizers are intentionally strict: they only
    // accept machine-code shapes whose loop bounds or terminators are themselves proven.
    // They do not classify data exclusively; they add non-exclusive consumer evidence.
    auto nextInstruction=[&](std::uint16_t address)->const Instruction*{
        auto it=analyzer_->instructions().upper_bound(address);
        return it==analyzer_->instructions().end()?nullptr:&it->second;
    };
    auto isBackwardTo=[&](const Instruction& in,std::uint16_t low,std::uint16_t high){
        return in.target>=0&&static_cast<std::uint16_t>(in.target)>=low&&static_cast<std::uint16_t>(in.target)<=high&&static_cast<std::uint16_t>(in.target)<in.address;
    };
    auto uniqueOwner=[&](std::uint16_t pc)->int{
        auto ib=instructionToBlock_.find(pc);if(ib==instructionToBlock_.end())return -1;
        auto bb=blocks_.find(ib->second);if(bb==blocks_.end()||bb->second.functionOwners.size()!=1)return -1;
        return static_cast<int>(*bb->second.functionOwners.begin());
    };

    // A simple sentinel stream is proven when a fixed ROM pointer feeds LD A,(pair),
    // immediately tests A for zero, conditionally returns on zero, increments the
    // pointer on every back-edge path, and has no other mutation of that pointer.
    // The terminating zero is therefore a machine-proven boundary.
    for(const auto& kv:analyzer_->instructions()){
        std::string reg;std::uint16_t base=0;
        if(!immediatePair(kv.second,reg,base)||base>=program.size()||(reg!="DE"&&reg!="BC"&&reg!="HL"))continue;
        const std::uint16_t seedEnd=continuationAfter(kv.second);
        const std::uint8_t loadOp=reg=="DE"?0x1A:reg=="BC"?0x0A:0x7E;
        const std::uint8_t incOp=reg=="DE"?0x13:reg=="BC"?0x03:0x23;
        const Instruction* read=nullptr;const Instruction* inc=nullptr;bool zeroReturn=false,back=false,badMutation=false;
        for(auto it=analyzer_->instructions().lower_bound(seedEnd);it!=analyzer_->instructions().end()&&it->first<static_cast<std::uint16_t>(seedEnd+0x40);++it){
            const auto& in=it->second;if(in.bytes.empty())continue;
            if(!read&&in.bytes[0]==loadOp){
                if(reg=="HL"&&in.operands.find("(HL)")==std::string::npos)continue;
                read=&in;continue;
            }
            if(!read)continue;
            if(!zeroReturn){
                const Instruction* a=nextInstruction(read->address);const Instruction* r=a?nextInstruction(a->address):nullptr;
                if(a&&r&&a->bytes.size()==1&&a->bytes[0]==0xA7&&r->bytes.size()==1&&r->bytes[0]==0xC8)zeroReturn=true;
            }
            if(in.bytes[0]==incOp){if(!inc)inc=&in;else badMutation=true;continue;}
            if(in.address>read->address&&isBackwardTo(in,seedEnd,read->address)&&inc&&in.address>inc->address)back=true;
            // Conservative pair-replacement test. Arithmetic using the pair as a source
            // is fine; writes/reloads/decrements make the sequential proof ineligible.
            if(reg=="DE"&&(in.bytes[0]==0x11||in.bytes[0]==0x1B||in.mnemonic=="EX"||(in.mnemonic=="POP"&&in.operands=="DE")))badMutation=true;
            if(reg=="BC"&&(in.bytes[0]==0x01||in.bytes[0]==0x0B||(in.mnemonic=="POP"&&in.operands=="BC")))badMutation=true;
            if(reg=="HL"&&(in.bytes[0]==0x21||in.bytes[0]==0x2B||(in.mnemonic=="POP"&&in.operands=="HL")))badMutation=true;
        }
        if(!read||!zeroReturn||!inc||!back||badMutation)continue;
        const int seedOwner=uniqueOwner(kv.second.address),readOwner=uniqueOwner(read->address);if(seedOwner<0||seedOwner!=readOwner)continue;
        std::size_t end=base;while(end<program.size()&&program[end]!=0)++end;if(end>=program.size())continue;++end;
        RomConsumerRecord r;r.pc=read->address;r.start=base;r.end=static_cast<std::uint16_t>(end);r.kind=RomConsumerKind::SentinelSequentialRead;r.pointerRegister=reg;r.exact=true;
        r.note="fixed ROM base + zero-test/conditional-return + single dominating pointer increment proves sequential extent through terminating zero";addConsumer(r);
    }

    // Pac-Man contains a compact signed command stream interpreter: LD A,(BC), test
    // zero, branch on sign, consume either one signed command byte or a two-byte
    // positive command+operand, advance BC, and jump back. Matching the entire shape
    // lets us follow the ROM-defined stride safely until the actual sentinel.
    for(const auto& kv:analyzer_->instructions()){
        std::string reg;std::uint16_t base=0;if(!immediatePair(kv.second,reg,base)||reg!="BC"||base>=program.size())continue;
        const std::uint16_t begin=continuationAfter(kv.second),limit=static_cast<std::uint16_t>(std::min<unsigned>(0xFFFFu,begin+0x50u));
        const Instruction* firstRead=nullptr;int incCount=0,readCount=0;bool zeroRet=false,signBranch=false,back=false,bad=false;
        for(auto it=analyzer_->instructions().lower_bound(begin);it!=analyzer_->instructions().end()&&it->first<limit;++it){const auto& in=it->second;if(in.bytes.empty())continue;
            if(in.bytes[0]==0x0A){++readCount;if(!firstRead)firstRead=&in;}
            if(in.bytes[0]==0x03)++incCount;
            if(firstRead){const Instruction* a=nextInstruction(firstRead->address);const Instruction* r=a?nextInstruction(a->address):nullptr;if(a&&r&&a->bytes.size()==1&&a->bytes[0]==0xA7&&r->bytes.size()==1&&r->bytes[0]==0xC8)zeroRet=true;}
            if(in.bytes[0]==0xFA&&in.target>=0)signBranch=true;
            if(firstRead&&in.bytes[0]==0xC3&&in.target==firstRead->address)back=true;
            if(in.bytes[0]==0x0B||(in.mnemonic=="POP"&&in.operands=="BC"))bad=true;
        }
        if(!firstRead||readCount<2||incCount!=2||!zeroRet||!signBranch||!back||bad)continue;
        const int seedOwner=uniqueOwner(kv.second.address),readOwner=uniqueOwner(firstRead->address);if(seedOwner<0||seedOwner!=readOwner)continue;
        std::size_t p=base;bool ok=false;std::size_t guard=0;
        while(p<program.size()&&guard++<program.size()){
            const std::uint8_t v=program[p];if(v==0){++p;ok=true;break;}
            if(v&0x80u)++p;else {if(p+1>=program.size())break;p+=2;}
        }
        if(!ok||p<=base)continue;
        RomConsumerRecord r;r.pc=firstRead->address;r.start=base;r.end=static_cast<std::uint16_t>(p);r.kind=RomConsumerKind::EncodedSentinelRead;r.pointerRegister="BC";r.exact=true;
        r.note="matched signed one/two-byte command protocol; ROM bytes determine stride and zero sentinel proves final boundary";addConsumer(r);
    }

    // Strict nested counted-loop idiom used by the maze-layout table: a fixed IY ROM
    // base, B outer count, C inner count, one (IY+0) read and one INC IY per inner
    // iteration, DEC C/JR NZ inner latch, DEC B/JR NZ outer latch. The product of the
    // two literal counters proves the complete sequential byte extent.
    for(const auto& kv:analyzer_->instructions()){
        std::string reg;std::uint16_t base=0;if(!immediatePair(kv.second,reg,base)||reg!="IY"||base>=program.size())continue;
        const std::uint16_t begin=continuationAfter(kv.second),limit=static_cast<std::uint16_t>(std::min<unsigned>(0xFFFFu,begin+0x70u));
        const Instruction *bInit=nullptr,*cInit=nullptr,*read=nullptr,*inc=nullptr,*decC=nullptr,*innerBack=nullptr,*decB=nullptr,*outerBack=nullptr;bool otherIYWrite=false;
        for(auto it=analyzer_->instructions().lower_bound(begin);it!=analyzer_->instructions().end()&&it->first<limit;++it){const auto& in=it->second;const auto& b=in.bytes;if(b.empty())continue;
            if(!bInit&&b.size()>=2&&b[0]==0x06){bInit=&in;continue;}
            if(bInit&&!cInit&&b.size()>=2&&b[0]==0x0E){cInit=&in;continue;}
            if(cInit&&!read&&in.operands.find("(IY+0)")!=std::string::npos){for(const auto& op:memoryReadOperands(in))if(op=="(IY+0)"){read=&in;break;}if(read)continue;}
            if(read&&!inc&&b.size()>=2&&b[0]==0xFD&&b[1]==0x23){inc=&in;continue;}
            if(inc&&!decC&&b[0]==0x0D){decC=&in;continue;}
            if(decC&&!innerBack&&in.target>=0&&in.address>decC->address&&static_cast<std::uint16_t>(in.target)<=read->address){innerBack=&in;continue;}
            if(innerBack&&!decB&&b[0]==0x05){decB=&in;continue;}
            if(decB&&!outerBack&&in.target>=0&&in.address>decB->address&&static_cast<std::uint16_t>(in.target)<=cInit->address){outerBack=&in;break;}
            if(b.size()>=2&&b[0]==0xFD&&(b[1]==0x21||b[1]==0x2B||b[1]==0xE1))otherIYWrite=true;
        }
        if(!bInit||!cInit||!read||!inc||!decC||!innerBack||!decB||!outerBack||otherIYWrite)continue;
        const int seedOwner=uniqueOwner(kv.second.address),readOwner=uniqueOwner(read->address);if(seedOwner<0||seedOwner!=readOwner)continue;
        const unsigned outer=bInit->bytes[1],inner=cInit->bytes[1];if(!outer||!inner)continue;
        const std::size_t count=static_cast<std::size_t>(outer)*inner;if(static_cast<std::size_t>(base)+count>program.size())continue;
        RomConsumerRecord r;r.pc=read->address;r.start=base;r.end=static_cast<std::uint16_t>(base+count);r.kind=RomConsumerKind::CountedSequentialRead;r.pointerRegister="IY";r.exact=true;
        std::ostringstream note;note<<"literal nested counters B="<<outer<<" and C="<<inner<<" with one IY read/increment per inner iteration prove "<<count<<" sequential bytes";r.note=note.str();addConsumer(r);
    }

    // Bit-indexed fixed-record consumers.  This recognizes a machine-code idiom
    // where B is initialized to N, a mask is shifted while DJNZ scans N bits, the
    // selected bit number is converted to a byte offset by repeated RLCA, and LDIR
    // copies a literal-width record from caller-supplied HL.  Every possible record
    // lies inside one bounded ROM span; no gameplay-state assumption is required.
    for(const auto& fk:functions_){
        std::vector<const Instruction*> fin;
        for(auto ba:fk.second.blocks){auto bi=blocks_.find(ba);if(bi==blocks_.end())continue;for(auto ia:bi->second.instructions)fin.push_back(&analyzer_->instructions().at(ia));}
        std::sort(fin.begin(),fin.end(),[](const Instruction* a,const Instruction* b){return a->address<b->address;});
        const Instruction *bInit=nullptr,*shift=nullptr,*djnz=nullptr,*decB=nullptr,*ldAB=nullptr,*ldCA=nullptr,*zeroB=nullptr,*addHLBC=nullptr,*widthLoad=nullptr,*ldir=nullptr;
        unsigned rotates=0;
        for(const auto* ip:fin){const auto& b=ip->bytes;if(b.empty())continue;
            if(!bInit&&b.size()>=2&&b[0]==0x06&&b[1]>0&&b[1]<=32){bInit=ip;continue;}
            if(!bInit)continue;
            if(!shift&&b.size()>=2&&b[0]==0xCB&&b[1]==0x3B){shift=ip;continue;}
            if(shift&&!djnz&&b[0]==0x10&&ip->target>=0&&static_cast<std::uint16_t>(ip->target)<=shift->address){djnz=ip;continue;}
            if(djnz&&!decB&&b[0]==0x05){decB=ip;continue;}
            if(decB&&!ldAB&&b[0]==0x78){ldAB=ip;continue;}
            if(ldAB&&!ldCA&&b[0]==0x07){++rotates;continue;}
            if(ldAB&&!ldCA&&b[0]==0x4F&&rotates>0){ldCA=ip;continue;}
            if(ldCA&&!zeroB&&b.size()>=2&&b[0]==0x06&&b[1]==0){zeroB=ip;continue;}
            if(zeroB&&!addHLBC&&b[0]==0x09){addHLBC=ip;continue;}
            if(addHLBC&&!widthLoad&&b.size()>=3&&b[0]==0x01){widthLoad=ip;continue;}
            if(widthLoad&&!ldir&&b.size()>=2&&b[0]==0xED&&b[1]==0xB0){ldir=ip;break;}
        }
        if(!bInit||!shift||!djnz||!decB||!ldAB||!ldCA||!zeroB||!addHLBC||!widthLoad||!ldir||rotates>7)continue;
        const unsigned records=bInit->bytes[1],scale=1u<<rotates,width=static_cast<unsigned>(widthLoad->bytes[1]|(static_cast<unsigned>(widthLoad->bytes[2])<<8));
        if(!width||width>0x100||scale!=width||(records-1u)*scale+width>0x1000u)continue;
        // Require at least one conditional branch out of the scan loop toward the
        // selection path; otherwise a coincidental opcode sequence is insufficient.
        bool selectionBranch=false;for(const auto* ip:fin)if(ip->conditional&&ip->target>=0&&ip->address>=bInit->address&&ip->address<djnz->address&&static_cast<std::uint16_t>(ip->target)>djnz->address&&static_cast<std::uint16_t>(ip->target)<=decB->address){selectionBranch=true;break;}
        if(!selectionBranch)continue;
        for(const auto& ck:analyzer_->instructions()){const auto& site=ck.second;if(site.flow!=FlowKind::Call||site.target<0||static_cast<std::uint16_t>(site.target)!=fk.first)continue;
            auto ib=instructionToBlock_.find(site.address);if(ib==instructionToBlock_.end())continue;auto cb=blocks_.find(ib->second);if(cb==blocks_.end())continue;RegisterState state=cb->second.entryState;bool reached=false;
            for(auto ia:cb->second.instructions){if(ia==site.address){reached=true;break;}transferInstruction(analyzer_->instructions().at(ia),state);}if(!reached)continue;auto hl=getReg(state,"HL",16);if(!hl.known||hl.value>=program.size())continue;
            const std::size_t end=static_cast<std::size_t>(hl.value)+(records-1u)*scale+width;if(end>program.size())continue;
            RomConsumerRecord r;r.pc=ldir->address;r.start=hl.value;r.end=static_cast<std::uint16_t>(end);r.kind=RomConsumerKind::CountedSequentialRead;r.pointerRegister="HL";r.indexRegister="B";r.bounded=true;
            std::ostringstream note;note<<"CALL $"<<hex16(site.address)<<" supplies exact HL base; literal B="<<records<<" bit scan selects record 0.."<<(records-1)<<", "<<rotates<<" RLCA scale by "<<scale<<", and LDIR width="<<width;r.note=note.str();addConsumer(r);
        }
    }

    // A related bit-scan idiom feeds RST $18 directly.  When caller-supplied HL is
    // untouched before the helper and B starts at N then is decremented on the selected
    // path, the RST can index only entries 0..N-1 of an N-word table.  Decode the words
    // only as pointer-target evidence; their pointee extent remains unknown here.
    for(const auto& fk:functions_){
        std::vector<const Instruction*> fin;for(auto ba:fk.second.blocks){auto bi=blocks_.find(ba);if(bi==blocks_.end())continue;for(auto ia:bi->second.instructions)fin.push_back(&analyzer_->instructions().at(ia));}
        std::sort(fin.begin(),fin.end(),[](const Instruction* a,const Instruction* b){return a->address<b->address;});
        const Instruction *bInit=nullptr,*shift=nullptr,*djnz=nullptr,*decB=nullptr,*rst18=nullptr;
        for(const auto* ip:fin){const auto& b=ip->bytes;if(b.empty())continue;if(!bInit&&b.size()>=2&&b[0]==0x06&&b[1]>0&&b[1]<=32){bInit=ip;continue;}if(!bInit)continue;
            if(!shift&&b.size()>=2&&b[0]==0xCB&&b[1]==0x3B){shift=ip;continue;}if(shift&&!djnz&&b[0]==0x10&&ip->target>=0&&static_cast<std::uint16_t>(ip->target)<=shift->address){djnz=ip;continue;}
            if(djnz&&!decB&&b[0]==0x05){decB=ip;continue;}if(decB&&!rst18&&ip->flow==FlowKind::Restart&&ip->target==0x18){rst18=ip;break;}
        }
        if(!bInit||!shift||!djnz||!decB||!rst18)continue;
        bool selectionBranch=false,hlStable=true;for(const auto* ip:fin){if(ip->address>=rst18->address)break;if(ip->address>=bInit->address&&ip->address<djnz->address&&ip->conditional&&ip->target>=0&&static_cast<std::uint16_t>(ip->target)>djnz->address&&static_cast<std::uint16_t>(ip->target)<=decB->address)selectionBranch=true;
            const auto writes=ConditionSemantics::writtenRegisters(*ip);if(writes.count("HL")||writes.count("H")||writes.count("L"))hlStable=false;
        }if(!selectionBranch||!hlStable)continue;
        const unsigned entries=bInit->bytes[1];
        for(const auto& ck:analyzer_->instructions()){const auto& site=ck.second;if(site.flow!=FlowKind::Call||site.target<0||static_cast<std::uint16_t>(site.target)!=fk.first)continue;auto ib=instructionToBlock_.find(site.address);if(ib==instructionToBlock_.end())continue;auto cb=blocks_.find(ib->second);if(cb==blocks_.end())continue;RegisterState state=cb->second.entryState;bool reached=false;
            for(auto ia:cb->second.instructions){if(ia==site.address){reached=true;break;}transferInstruction(analyzer_->instructions().at(ia),state);}if(!reached)continue;auto hl=getReg(state,"HL",16);if(!hl.known||static_cast<std::size_t>(hl.value)+entries*2u>program.size())continue;
            RomConsumerRecord r;r.pc=rst18->address;r.start=hl.value;r.end=static_cast<std::uint16_t>(hl.value+entries*2u);r.kind=RomConsumerKind::Rst18WordLookup;r.pointerRegister="HL";r.indexRegister="B";r.bounded=true;
            std::ostringstream note;note<<"CALL $"<<hex16(site.address)<<" supplies exact HL base; literal B="<<entries<<" bit scan plus DEC B constrains RST $18 index to 0.."<<(entries-1);r.note=note.str();addConsumer(r);
            for(unsigned index=0;index<entries;++index){const std::size_t off=static_cast<std::size_t>(hl.value)+2u*index;const std::uint16_t target=static_cast<std::uint16_t>(program[off]|(static_cast<std::uint16_t>(program[off+1])<<8));if(target<program.size()&&!romClosureBytes_[target].pointerTarget){romClosureBytes_[target].pointerTarget=true;++stats_.romClosure.derivedRomPointerTargets;}}
        }
    }

    // Call-edge register propagation is machine semantics, not a calling-convention
    // guess: Z80 CALL does not alter general registers. For every statically direct CALL,
    // replay the caller block to the CALL and seed the callee entry with those concrete
    // register facts. Follow only static intra-function edges and stop precision across
    // nested calls/RSTs via transferInstruction's conservative clobber behavior.
    for(const auto& ck:analyzer_->instructions()){
        const auto& call=ck.second;if(call.flow!=FlowKind::Call||call.target<0)continue;
        const auto callAddress=call.address,callee=static_cast<std::uint16_t>(call.target);
        auto ib=instructionToBlock_.find(callAddress);if(ib==instructionToBlock_.end())continue;auto callerBlock=blocks_.find(ib->second);if(callerBlock==blocks_.end())continue;
        RegisterState seed=callerBlock->second.entryState;bool reached=false;
        for(auto a:callerBlock->second.instructions){if(a==callAddress){reached=true;break;}transferInstruction(analyzer_->instructions().at(a),seed);}
        if(!reached)continue;
        putReg(seed,"SP",unknown(16));
        auto fit=functions_.find(callee);if(fit==functions_.end()||!blocks_.count(callee))continue;
        std::map<std::uint16_t,RegisterState> states;std::map<std::uint16_t,bool> initialized;std::queue<std::uint16_t> q;states[callee]=seed;initialized[callee]=true;q.push(callee);std::size_t guard=0;
        while(!q.empty()&&guard++<5000){const auto ba=q.front();q.pop();auto bit=blocks_.find(ba);if(bit==blocks_.end()||!fit->second.blocks.count(ba))continue;RegisterState state=states[ba];
            for(auto ia:bit->second.instructions){const auto& in=analyzer_->instructions().at(ia);
                for(const auto& op:memoryReadOperands(in)){std::string preg;std::uint16_t address=0;if(resolveOperand(op,state,preg,address)&&address<program.size()){
                    RomConsumerRecord r;r.pc=in.address;r.start=address;r.end=static_cast<std::uint16_t>(address+1);r.kind=RomConsumerKind::InterproceduralRead;r.pointerRegister=preg;r.exact=true;
                    std::ostringstream note;note<<"exact register value propagated over CALL at $"<<hex16(callAddress)<<" into callee $"<<hex16(callee);r.note=note.str();addConsumer(r);
                }}
                transferInstruction(in,state);
            }
            for(const auto& e:bit->second.outgoing){if(e.to<0||!isStructuralEdge(e.kind))continue;const auto to=static_cast<std::uint16_t>(e.to);if(!fit->second.blocks.count(to))continue;bool was=initialized[to];bool changed=mergeState(states[to],state,was);if(!was){initialized[to]=true;changed=true;}if(changed)q.push(to);}
        }
    }

    // Recover call-indexed RST $18 word tables and the delimited stream protocol
    // they feed. This is detected from code shape, not from a hard-coded Pac-Man table
    // address. B ranges at direct CALL sites come from local machine-level range evidence.
    // Exact B values yield exact consumers; finite B ranges yield bounded consumers.
    for(const auto& fk:functions_){
        std::uint16_t lookupPc=0,tableBase=0;bool protocol=false;
        auto eb=blocks_.find(fk.first);if(eb==blocks_.end())continue;
        RegisterState local;
        for(std::size_t ii=0;ii<eb->second.instructions.size();++ii){const auto ia=eb->second.instructions[ii];const auto& in=analyzer_->instructions().at(ia);
            if(in.flow==FlowKind::Restart&&in.target==0x18){auto hl=getReg(local,"HL",16);if(!hl.known||hl.value>=program.size())break;
                const Instruction* n1=nextInstruction(in.address);const Instruction* n2=n1?nextInstruction(n1->address):nullptr;const Instruction* n3=n2?nextInstruction(n2->address):nullptr;
                if(n1&&n2&&n3&&n1->bytes.size()==1&&n1->bytes[0]==0x5E&&n2->bytes.size()==1&&n2->bytes[0]==0x23&&n3->bytes.size()==1&&n3->bytes[0]==0x56){lookupPc=in.address;tableBase=hl.value;}
                break;
            }
            transferInstruction(in,local);
        }
        if(!lookupPc)continue;
        // Require the normal-path stream delimiter idiom LD A,(HL) / CP $2F somewhere
        // in this same recovered function before treating decoded words as stream pointers.
        for(auto ba:fk.second.blocks){auto bi=blocks_.find(ba);if(bi==blocks_.end())continue;for(std::size_t i=0;i+1<bi->second.instructions.size();++i){
            const auto& a=analyzer_->instructions().at(bi->second.instructions[i]);const auto& c=analyzer_->instructions().at(bi->second.instructions[i+1]);
            if(a.bytes.size()==1&&a.bytes[0]==0x7E&&c.bytes.size()==2&&c.bytes[0]==0xFE&&c.bytes[1]==0x2F){protocol=true;break;}
        }if(protocol)break;}
        if(!protocol)continue;

        for(const auto& ck:analyzer_->instructions()){const auto& call=ck.second;
            const bool directCall=call.flow==FlowKind::Call;
            const bool directTailTransfer=(call.flow==FlowKind::Jump||call.flow==FlowKind::RelativeJump)&&!call.conditional&&!call.indirect;
            if((!directCall&&!directTailTransfer)||call.target<0||static_cast<std::uint16_t>(call.target)!=fk.first)continue;
            const auto callAddress=call.address;auto ib=instructionToBlock_.find(callAddress);if(ib==instructionToBlock_.end())continue;auto cb=blocks_.find(ib->second);if(cb==blocks_.end())continue;
            RangeMap ranges=rangesAtBlock(cb->first,cb->second.entryState);bool reached=false;for(auto ia:cb->second.instructions){if(ia==callAddress){reached=true;break;}rangeTransfer(analyzer_->instructions().at(ia),ranges);}if(!reached)continue;
            const auto br=getRange(ranges,"B");if(!br.known||br.lo>br.hi||br.hi-br.lo>64||br.lo>=0x80)continue;const unsigned hi=std::min<unsigned>(br.hi,0x7F);
            std::uint16_t tableStart=0,tableEnd=0;if(!RomClosure::boundedLookupRange(tableBase,static_cast<std::uint16_t>(br.lo),static_cast<std::uint16_t>(hi),2,program.size(),tableStart,tableEnd))continue;
            RomConsumerRecord tr;tr.pc=lookupPc;tr.start=tableStart;tr.end=tableEnd;tr.kind=RomConsumerKind::Rst18WordLookup;tr.pointerRegister="HL";tr.indexRegister="B";tr.exact=br.lo==hi;tr.bounded=br.lo!=hi;
            std::ostringstream tn;tn<<"B="<<br.lo;if(br.lo!=hi)tn<<".."<<hi;tn<<" propagated to callee from "<<(directCall?"CALL":"unconditional direct jump")<<" $"<<hex16(callAddress)<<"; RST $18 reads little-endian word(s)";tr.note=tn.str();addConsumer(tr);

            for(unsigned index=br.lo;index<=hi;++index){const std::size_t off=static_cast<std::size_t>(tableBase)+2u*index;if(off+1>=program.size())break;const std::uint16_t target=static_cast<std::uint16_t>(program[off]|(static_cast<std::uint16_t>(program[off+1])<<8));if(target>=program.size())continue;
                if(!romClosureBytes_[target].pointerTarget){romClosureBytes_[target].pointerTarget=true;++stats_.romClosure.derivedRomPointerTargets;}
                // Normal (<$80) protocol: two-byte prefix, then bytes until $2F. B is
                // repurposed as the pre-delimiter length. A negative post-delimiter byte
                // is repeated without advancing HL; otherwise exactly that many bytes are
                // read sequentially after the delimiter.
                if(static_cast<std::size_t>(target)+2>=program.size())continue;
                std::size_t q=static_cast<std::size_t>(target)+2;
                const std::size_t maxScan=std::min<std::size_t>(program.size(),q+0x100);
                while(q<maxScan&&program[q]!=0x2F)++q;
                if(q>=maxScan||q+1>=program.size())continue;
                const std::size_t preCount=q-(static_cast<std::size_t>(target)+2);
                if(preCount==0)continue;
                std::size_t end=q+2;
                if((program[q+1]&0x80u)==0){end=q+1+preCount;if(end>program.size())continue;}
                if(end<=target)continue;
                RomConsumerRecord sr;sr.pc=lookupPc;sr.start=target;sr.end=static_cast<std::uint16_t>(end);sr.kind=RomConsumerKind::DelimitedStreamRead;sr.pointerRegister="HL";sr.indexRegister="B";sr.exact=br.lo==hi;sr.bounded=br.lo!=hi;
                std::ostringstream sn;sn<<"word at $"<<hex16(static_cast<std::uint16_t>(off))<<" decodes to $"<<hex16(target)<<"; matched $2F-delimited normal stream path for possible B=$"<<hex8(static_cast<std::uint8_t>(index));sr.note=sn.str();addConsumer(sr);
            }
        }
    }

    // Direct 16-bit RAM load/store opcodes prove that adjacent bytes form one machine
    // word at the access site. This is pair metadata, not a semantic type guess.
    auto physicalRam=[](std::uint16_t a){return (a>=0x4000&&a<=0x47FF)||(a>=0x4C00&&a<=0x4FFF);};
    std::map<std::pair<std::uint16_t,std::string>,RamPairEvidenceRecord> pairMap;
    for(const auto& kv:analyzer_->instructions()){
        const auto& in=kv.second;const auto& b=in.bytes;std::uint16_t addr=0;std::string reg;bool rd=false,wr=false,matched=false;
        if(b.size()>=3&&(b[0]==0x2A||b[0]==0x22)){addr=static_cast<std::uint16_t>(b[1]|(b[2]<<8));reg="HL";rd=b[0]==0x2A;wr=b[0]==0x22;matched=true;}
        else if(b.size()>=4&&b[0]==0xED&&(b[1]==0x4B||b[1]==0x5B||b[1]==0x6B||b[1]==0x7B||b[1]==0x43||b[1]==0x53||b[1]==0x63||b[1]==0x73)){
            addr=static_cast<std::uint16_t>(b[2]|(b[3]<<8));const std::uint8_t op=b[1];reg=(op==0x4B||op==0x43)?"BC":(op==0x5B||op==0x53)?"DE":(op==0x6B||op==0x63)?"HL":"SP";rd=(op&0x08)!=0;wr=!rd;matched=true;
        }else if(b.size()>=4&&(b[0]==0xDD||b[0]==0xFD)&&(b[1]==0x2A||b[1]==0x22)){
            addr=static_cast<std::uint16_t>(b[2]|(b[3]<<8));reg=b[0]==0xDD?"IX":"IY";rd=b[1]==0x2A;wr=b[1]==0x22;matched=true;
        }
        if(!matched||addr==0xFFFF||!physicalRam(addr)||!physicalRam(static_cast<std::uint16_t>(addr+1)))continue;
        auto key=std::make_pair(addr,reg);auto& r=pairMap[key];r.address=addr;r.pairRegister=reg;r.read=r.read||rd;r.write=r.write||wr;r.sourcePCs.insert(in.address);
        r.note="direct Z80 16-bit RAM "+std::string(rd?"load":"store")+" proves adjacent low/high byte pairing";
    }

    // Mark a direct RAM pair as pointer-like only when a load of that pair is followed,
    // before a call or obvious pair replacement, by an indirect memory access through it
    // in the same basic block. This avoids labeling counters as pointers merely because
    // they occupy two bytes.
    for(auto& pk:pairMap){auto& rec=pk.second;if(!rec.read)continue;
        for(const auto& bk:blocks_){bool armed=false;for(auto a:bk.second.instructions){const auto& in=analyzer_->instructions().at(a);const auto& b=in.bytes;
                bool thisLoad=false;if(rec.pairRegister=="HL"&&b.size()>=3&&b[0]==0x2A)thisLoad=(static_cast<std::uint16_t>(b[1]|(b[2]<<8))==rec.address);
                else if(b.size()>=4&&b[0]==0xED){const std::uint16_t ad=static_cast<std::uint16_t>(b[2]|(b[3]<<8));if(ad==rec.address){if(rec.pairRegister=="BC"&&b[1]==0x4B)thisLoad=true;else if(rec.pairRegister=="DE"&&b[1]==0x5B)thisLoad=true;else if(rec.pairRegister=="HL"&&b[1]==0x6B)thisLoad=true;else if(rec.pairRegister=="SP"&&b[1]==0x7B)thisLoad=true;}}
                else if(b.size()>=4&&(b[0]==0xDD||b[0]==0xFD)&&b[1]==0x2A){const std::uint16_t ad=static_cast<std::uint16_t>(b[2]|(b[3]<<8));if(ad==rec.address&&rec.pairRegister==(b[0]==0xDD?"IX":"IY"))thisLoad=true;}
                if(thisLoad){armed=true;continue;}if(!armed)continue;
                if(in.flow==FlowKind::Call||in.flow==FlowKind::Restart)break;
                const std::string needle="("+rec.pairRegister;if(in.operands.find(needle)!=std::string::npos){rec.pointerLike=true;rec.note+="; subsequently dereferenced in the same basic block";break;}
                const auto ops=splitOperands(in.operands);if(!ops.empty()&&(ops[0]==rec.pairRegister||ops[0]=="H"||ops[0]=="L"||ops[0]=="D"||ops[0]=="E"||ops[0]=="B"||ops[0]=="C"))break;
            }if(rec.pointerLike)break;}
    }
    for(auto& kv:pairMap)ramPairEvidence_.push_back(std::move(kv.second));

    for(auto& b:romClosureBytes_)b.primary=RomClosure::classify(b);
    RomClosureStats st;st.romBytes=romClosureBytes_.size();st.consumers=romConsumers_.size();st.immediateRomPointerSeeds=stats_.romClosure.immediateRomPointerSeeds;st.derivedRomPointerTargets=stats_.romClosure.derivedRomPointerTargets;st.ramPairs=ramPairEvidence_.size();
    for(const auto& r:romConsumers_){if(r.dynamic)++st.dynamicConsumers;else if(r.exact)++st.exactStaticConsumers;if(r.bounded)++st.boundedConsumers;}
    for(const auto& r:ramPairEvidence_)if(r.pointerLike)++st.pointerLikeRamPairs;
    for(const auto& b:romClosureBytes_){
        switch(b.primary){case RomClosurePrimary::Code:++st.codeBytes;break;case RomClosurePrimary::CodeAndDataUse:++st.codeAndDataUseBytes;break;case RomClosurePrimary::HardData:++st.hardDataBytes;break;case RomClosurePrimary::ProvenDataUse:++st.provenDataUseBytes;break;case RomClosurePrimary::BoundedConsumer:++st.boundedConsumerBytes;break;case RomClosurePrimary::Candidate:++st.candidateBytes;break;case RomClosurePrimary::PointerTarget:++st.pointerTargetBytes;break;case RomClosurePrimary::ProvenUnused:++st.provenUnusedBytes;break;case RomClosurePrimary::Unresolved:++st.unresolvedBytes;break;}
        if(b.code||b.hardData||b.staticExactDataUse||b.dynamicDataUse)++st.evidenceBackedExplainedBytes;
        if(b.code||b.hardData||b.staticExactDataUse||b.dynamicDataUse||b.boundedConsumer)++st.boundedExplainedBytes;
    }
    stats_.romClosure=st;
}

void Decompiler::buildConditionSemantics(){
    conditionEvidence_.clear();
    stats_.conditionalFlagBranches=0;
    stats_.flagProducerResolvedBranches=0;
    stats_.semanticConditionBranches=0;
    stats_.crossBlockSemanticConditions=0;
    stats_.semanticConditionsSuppressedByClobber=0;

    struct OriginFact {
        int producer=-1;
        std::set<std::string> clobberedRegisters;
        bool memoryClobbered=false;
    };
    struct OriginState { OriginFact z,c,s,pv; };

    auto fact=[&](OriginState& s,unsigned mask)->OriginFact&{
        if(mask==FlagZ)return s.z;
        if(mask==FlagC)return s.c;
        if(mask==FlagS)return s.s;
        return s.pv;
    };
    auto constFact=[&](const OriginState& s,unsigned mask)->const OriginFact&{
        if(mask==FlagZ)return s.z;
        if(mask==FlagC)return s.c;
        if(mask==FlagS)return s.s;
        return s.pv;
    };
    auto clearFact=[](OriginFact& f){
        f.producer=-1;
        f.clobberedRegisters.clear();
        f.memoryClobbered=false;
    };
    auto defineFact=[](OriginFact& f,std::uint16_t address){
        f.producer=static_cast<int>(address);
        f.clobberedRegisters.clear();
        f.memoryClobbered=false;
    };
    auto forMasks=[&](unsigned masks,const auto& fn){
        for(unsigned m:{FlagZ,FlagC,FlagS,FlagPV}) if(masks&m) fn(m);
    };
    auto apply=[&](OriginState& state,const Instruction& in){
        const auto writes=ConditionSemantics::writtenRegisters(in);
        const bool writesMem=ConditionSemantics::writesMemory(in);

        // Any value modification after a flag producer matters when a later semantic
        // expression refers to that value. Record it even if the instruction preserves
        // the tested flag; a subsequent flag definition resets the dependency history.
        for(unsigned m:{FlagZ,FlagC,FlagS,FlagPV}){
            OriginFact& f=fact(state,m);
            if(f.producer<0)continue;
            f.clobberedRegisters.insert(writes.begin(),writes.end());
            if(writesMem)f.memoryClobbered=true;
        }

        const FlagEffect e=ConditionSemantics::flagEffect(in);
        forMasks(e.unknown,[&](unsigned m){clearFact(fact(state,m));});
        forMasks(e.defined,[&](unsigned m){defineFact(fact(state,m),in.address);});
    };
    auto sameFact=[](const OriginFact& a,const OriginFact& b){
        return a.producer==b.producer &&
               a.clobberedRegisters==b.clobberedRegisters &&
               a.memoryClobbered==b.memoryClobbered;
    };
    auto same=[&](const OriginState& a,const OriginState& b){
        return sameFact(a.z,b.z)&&sameFact(a.c,b.c)&&sameFact(a.s,b.s)&&sameFact(a.pv,b.pv);
    };
    auto mergeFact=[&](OriginFact& dst,const OriginFact& src){
        if(dst.producer!=src.producer){
            const bool changed=dst.producer>=0 || !dst.clobberedRegisters.empty() || dst.memoryClobbered;
            clearFact(dst);
            return changed;
        }
        if(dst.producer<0)return false;
        const std::size_t before=dst.clobberedRegisters.size();
        dst.clobberedRegisters.insert(src.clobberedRegisters.begin(),src.clobberedRegisters.end());
        const bool memBefore=dst.memoryClobbered;
        dst.memoryClobbered=dst.memoryClobbered||src.memoryClobbered;
        return before!=dst.clobberedRegisters.size() || memBefore!=dst.memoryClobbered;
    };
    auto merge=[&](OriginState& dst,const OriginState& src,bool initialized)->bool{
        if(!initialized){dst=src;return true;}
        bool changed=false;
        changed=mergeFact(dst.z,src.z)||changed;
        changed=mergeFact(dst.c,src.c)||changed;
        changed=mergeFact(dst.s,src.s)||changed;
        changed=mergeFact(dst.pv,src.pv)||changed;
        return changed;
    };
    auto dependenciesStable=[&](const std::set<std::string>& deps,const OriginFact& f)->bool{
        for(const auto& dep:deps){
            if(dep=="MEM"){
                if(f.memoryClobbered)return false;
            }else if(f.clobberedRegisters.count(dep))return false;
        }
        return true;
    };
    auto unstableDescription=[&](const std::set<std::string>& deps,const OriginFact& f){
        std::vector<std::string> changed;
        for(const auto& dep:deps){
            if(dep=="MEM"){
                if(f.memoryClobbered)changed.push_back("memory");
            }else if(f.clobberedRegisters.count(dep))changed.push_back(dep);
        }
        std::ostringstream o;
        for(std::size_t i=0;i<changed.size();++i){if(i)o<<", ";o<<changed[i];}
        return o.str();
    };
    auto semanticFor=[&](const std::string& raw,const Instruction& producer,const OriginFact& f)->std::string{
        const std::string candidate=ConditionSemantics::expressionFor(raw,producer);
        if(candidate.empty())return {};
        const auto deps=ConditionSemantics::expressionDependencies(raw,producer);
        if(!dependenciesStable(deps,f))return {};
        return operandWithSymbols(candidate);
    };
    auto capture=[&](const BasicBlock& block,const Instruction& in,const OriginState& state){
        if(!in.conditional)return;
        const std::string raw=conditionFor(in);
        const unsigned mask=ConditionSemantics::flagMaskForCondition(raw);
        if(mask==FlagNone)return;

        ConditionEvidenceRecord rec;
        rec.branchAddress=in.address;
        rec.rawCondition=raw;
        const OriginFact& origin=constFact(state,mask);
        rec.producerAddress=origin.producer;
        rec.clobberedRegisters=origin.clobberedRegisters;
        rec.memoryClobbered=origin.memoryClobbered;

        if(rec.producerAddress>=0){
            const auto pi=analyzer_->instructions().find(static_cast<std::uint16_t>(rec.producerAddress));
            if(pi!=analyzer_->instructions().end()){
                rec.producerInstruction=pi->second.text();
                const std::string candidate=ConditionSemantics::expressionFor(raw,pi->second);
                const auto deps=ConditionSemantics::expressionDependencies(raw,pi->second);
                rec.dependenciesStable=dependenciesStable(deps,origin);
                if(candidate.empty()){
                    rec.semanticNote="producer known; semantic relationship intentionally not lifted";
                }else if(!rec.dependenciesStable){
                    rec.semanticNote="dependent value changed after producer";
                    const std::string changed=unstableDescription(deps,origin);
                    if(!changed.empty())rec.semanticNote+=": "+changed;
                }else{
                    rec.expression=operandWithSymbols(candidate);
                    rec.semanticNote="semantic expression proven from producer and stable dependencies";
                }
                const auto pb=instructionToBlock_.find(pi->first);
                rec.crossBlock=(pb!=instructionToBlock_.end()&&pb->second!=block.start);
            }else{
                rec.producerAddress=-1;
                rec.dependenciesStable=false;
                rec.semanticNote="producer address is outside the decoded instruction map";
            }
        }else{
            rec.dependenciesStable=false;
            rec.semanticNote="flag producer ambiguous or unknown";
        }

        auto old=conditionEvidence_.find(in.address);
        // Prefer a proven producer over an unresolved local record. If both are proven,
        // the function-local fixed-point result is canonical because it includes
        // dependency stability across all accepted incoming paths.
        if(old==conditionEvidence_.end()||rec.producerAddress>=0||old->second.producerAddress<0)
            conditionEvidence_[in.address]=rec;
    };

    // First resolve every branch using only facts established earlier in the same block.
    // This remains valid even for shared/unowned blocks because it requires no ownership guess.
    for(const auto& bk:blocks_){
        OriginState state;
        for(auto a:bk.second.instructions){
            const auto& in=analyzer_->instructions().at(a);
            capture(bk.second,in,state);
            apply(state,in);
        }
    }

    // Then extend exact producer identities across uniquely-owned, intra-function static
    // control-flow edges. Producer facts merge only when every predecessor agrees on the
    // same ROM instruction address. Dependency clobbers are unioned across those paths.
    for(const auto& fk:functions_){
        std::set<std::uint16_t> nodes;
        for(auto b:fk.second.blocks){
            const auto bi=blocks_.find(b);
            if(bi!=blocks_.end()&&bi->second.functionOwners.size()==1&&bi->second.functionOwners.count(fk.first))nodes.insert(b);
        }
        if(!nodes.count(fk.first))continue;

        std::map<std::uint16_t,OriginState> entries,exits;
        std::map<std::uint16_t,bool> initialized;
        std::queue<std::uint16_t> q;
        initialized[fk.first]=true;
        q.push(fk.first);
        std::size_t guard=0;
        while(!q.empty()&&guard++<200000){
            const auto b=q.front();q.pop();
            OriginState state=entries[b];
            for(auto a:blocks_.at(b).instructions)apply(state,analyzer_->instructions().at(a));
            const bool exitChanged=!same(exits[b],state);
            exits[b]=state;
            if(!exitChanged&&guard>nodes.size())continue;
            for(const auto& e:blocks_.at(b).outgoing){
                if(!isStructuralEdge(e.kind)||e.to<0)continue;
                const auto t=static_cast<std::uint16_t>(e.to);
                if(!nodes.count(t))continue;
                const bool was=initialized[t];
                const bool changed=merge(entries[t],state,was);
                if(!was)initialized[t]=true;
                if(changed||!was)q.push(t);
            }
        }
        for(auto b:nodes){
            if(!initialized[b])continue;
            OriginState state=entries[b];
            for(auto a:blocks_.at(b).instructions){
                const auto& in=analyzer_->instructions().at(a);
                capture(blocks_.at(b),in,state);
                apply(state,in);
            }
        }
    }

    // Replace raw edge labels only when both flag provenance and every expression
    // dependency are proven stable. The inverse edge is checked independently against
    // the same clobber record instead of relying on textual negation.
    for(auto& bk:blocks_)for(auto& e:bk.second.outgoing){
        const auto ri=conditionEvidence_.find(e.from);
        if(ri==conditionEvidence_.end())continue;
        const auto& rec=ri->second;
        std::string raw=rec.rawCondition;
        if(e.kind==CfgEdgeKind::BranchNotTaken){
            const std::string inv=ConditionSemantics::inverseCondition(rec.rawCondition);
            if(!inv.empty())raw=inv;
        }
        std::string text=raw;
        if(rec.producerAddress>=0){
            const auto pi=analyzer_->instructions().find(static_cast<std::uint16_t>(rec.producerAddress));
            if(pi!=analyzer_->instructions().end()){
                OriginFact f;
                f.producer=rec.producerAddress;
                f.clobberedRegisters=rec.clobberedRegisters;
                f.memoryClobbered=rec.memoryClobbered;
                const std::string sem=semanticFor(raw,pi->second,f);
                if(!sem.empty())text=sem;
            }
        }
        if(e.kind==CfgEdgeKind::BranchTaken||e.kind==CfgEdgeKind::BranchNotTaken||e.kind==CfgEdgeKind::Call||e.kind==CfgEdgeKind::Return)e.condition=text;
    }

    stats_.conditionalFlagBranches=conditionEvidence_.size();
    for(const auto& kv:conditionEvidence_){
        const auto& r=kv.second;
        if(r.producerAddress>=0)++stats_.flagProducerResolvedBranches;
        if(!r.expression.empty()){
            ++stats_.semanticConditionBranches;
            if(r.crossBlock)++stats_.crossBlockSemanticConditions;
        }else if(r.producerAddress>=0&&!r.dependenciesStable){
            ++stats_.semanticConditionsSuppressedByClobber;
        }
    }
}

std::string Decompiler::edgeKindText(CfgEdgeKind k) const{switch(k){case CfgEdgeKind::Fallthrough:return"fallthrough";case CfgEdgeKind::BranchTaken:return"branch-taken";case CfgEdgeKind::BranchNotTaken:return"branch-not-taken";case CfgEdgeKind::Call:return"call";case CfgEdgeKind::Restart:return"restart";case CfgEdgeKind::Dispatch:return"dispatch";case CfgEdgeKind::Return:return"return";case CfgEdgeKind::Indirect:return"indirect";case CfgEdgeKind::DynamicIndirect:return"dynamic-indirect";case CfgEdgeKind::DynamicReturn:return"dynamic-return";}return"?";}
std::string Decompiler::valueText(const AbstractValue&v) const{if(!v.known)return"?";return std::string("$")+(v.bits==8?hex8((std::uint8_t)v.value):hex16(v.value));}
std::string Decompiler::stateText(const RegisterState&s) const{std::ostringstream o;bool first=true;for(const char*r:{"A","BC","DE","HL","SP","IX","IY"}){auto v=getReg(s,r,std::string(r).size()==1?8:16);if(v.known){if(!first)o<<" ";o<<r<<"="<<valueText(v);first=false;}}return first?"(no constants)":o.str();}

std::string Decompiler::operandWithSymbols(const std::string& operand) const{
    std::string out;for(std::size_t i=0;i<operand.size();){std::uint16_t a=0;if(parseHex4(operand,i,a)){
            std::string repl="$"+hex16(a);
            if(const auto* user=analyzer_->symbols().find(a)) repl=user->name;
            else if(a<0x4000&&analyzer_->instructions().count(a)) repl=analyzer_->labelFor(a);
            else {auto ru=analyzer_->ramUsage().find(a);if(ru!=analyzer_->ramUsage().end())repl=ru->second.symbol;}
            out+=repl;i+=5;
        }else out+=operand[i++];}return out;
}

std::vector<std::string> Decompiler::instructionIR(const Instruction& in) const{
    std::vector<std::string> out;const std::string ops=operandWithSymbols(in.operands);auto parts=splitOperands(ops);
    auto emit=[&](const std::string&s){out.push_back("@"+hex16(in.address)+"  "+s);};
    if(in.mnemonic=="LD"&&parts.size()==2){emit(parts[0]+" := "+parts[1]);return out;}
    if(in.mnemonic=="XOR"&&parts.size()==1&&parts[0]=="A"){emit("A := $00");return out;}
    if(in.mnemonic=="DJNZ"){emit("B := B - 1");std::string target=in.target>=0?blockName(instructionToBlock_.count((std::uint16_t)in.target)?instructionToBlock_.at((std::uint16_t)in.target):(std::uint16_t)in.target):ops;emit("if (B != 0) goto "+target);return out;}
    if(in.mnemonic=="INC"&&parts.size()==1){emit(parts[0]+" := "+parts[0]+" + 1");return out;}
    if(in.mnemonic=="DEC"&&parts.size()==1){emit(parts[0]+" := "+parts[0]+" - 1");return out;}
    if((in.mnemonic=="ADD"||in.mnemonic=="ADC"||in.mnemonic=="SUB"||in.mnemonic=="SBC"||in.mnemonic=="AND"||in.mnemonic=="OR"||in.mnemonic=="XOR")&&!parts.empty()){
        if(parts.size()==2)emit(parts[0]+" := "+parts[0]+" "+in.mnemonic+" "+parts[1]);else emit("A := A "+in.mnemonic+" "+parts[0]);return out;}
    if(in.mnemonic=="CP"&&!parts.empty()){emit("FLAGS := compare(A, "+parts.back()+")");return out;}
    if(in.flow==FlowKind::Call){std::string target=in.target>=0?functionName((std::uint16_t)in.target):ops;const auto c=renderedConditionFor(in);emit(c.empty()?"call "+target+"()":"if ("+c+") call "+target+"()");return out;}
    if(in.flow==FlowKind::Jump||in.flow==FlowKind::RelativeJump){std::string target=in.target>=0?blockName(instructionToBlock_.count((std::uint16_t)in.target)?instructionToBlock_.at((std::uint16_t)in.target):(std::uint16_t)in.target):ops;const auto c=renderedConditionFor(in);emit(c.empty()?"goto "+target:"if ("+c+") goto "+target);return out;}
    if(in.flow==FlowKind::Return){const auto c=renderedConditionFor(in);emit(c.empty()?"return":"if ("+c+") return");return out;}
    if(in.flow==FlowKind::Restart){
        if(in.target==0x20){const auto dt=analyzer_->dispatchTables().find(in.address);emit(dt==analyzer_->dispatchTables().end()?"dispatch_rst20(?)":"dispatch_rst20(table_$"+hex16(dt->second.start)+", entries="+std::to_string(dt->second.entries.size())+")");}
        else if(in.target==0x28||in.target==0x30){std::vector<std::uint8_t> payload;for(const auto& kv:analyzer_->dataRegions())if(kv.second.sourceAddress==in.address)for(std::uint16_t a=kv.second.start;a<kv.second.end;++a)payload.push_back(analyzer_->program()[a]);std::ostringstream x;if(in.target==0x28&&payload.size()>=2)x<<"rst28_inline(B=$"<<hex8(payload[0])<<", C=$"<<hex8(payload[1])<<")";else{x<<"rst30_inline(";for(std::size_t i=0;i<payload.size();++i){if(i)x<<", ";x<<"$"<<hex8(payload[i]);}x<<")";}emit(x.str());}
        else emit("restart("+std::to_string(in.target)+")");
        return out;}
    if(in.flow==FlowKind::Halt){emit("halt_until_interrupt()");return out;}
    if(in.mnemonic=="PUSH"||in.mnemonic=="POP"){emit(in.mnemonic=="PUSH"?"push("+ops+")":""+ops+" := pop()");return out;}
    if(in.mnemonic=="EX"){emit("exchange("+ops+")");return out;}
    if(in.mnemonic=="NOP"){emit("nop");return out;}
    emit("z80."+in.mnemonic+(ops.empty()?"":" "+ops));return out;
}

std::vector<std::string> Decompiler::cfgLines() const{
    std::vector<std::string> o;if(!ready_){o.push_back("Decompiler model not built.");return o;}o.push_back("PacRipper control-flow graph");o.push_back("Basic blocks: "+std::to_string(stats_.basicBlocks)+"  edges: "+std::to_string(stats_.cfgEdges)+"  functions/handlers: "+std::to_string(stats_.functions)+"  shared: "+std::to_string(stats_.sharedBlocks)+"  unowned: "+std::to_string(stats_.unownedBlocks)+"  observed-edges: "+std::to_string(stats_.observedCfgEdges));o.push_back("");
    for(const auto& kv:blocks_){const auto&b=kv.second;std::ostringstream h;h<<blockName(b.start)<<"  $"<<hex16(b.start)<<"  ins="<<b.instructions.size()<<"  in="<<b.incoming.size()<<"  owners="<<b.functionOwners.size()<<"  entry "<<stateText(b.entryState);o.push_back(h.str());for(const auto&e:b.outgoing){std::ostringstream x;x<<"  -> ";if(e.to>=0)x<<blockName((std::uint16_t)e.to);else x<<"<no concrete target>";x<<"  ["<<edgeKindText(e.kind);if(!e.condition.empty())x<<": "<<e.condition;if(e.observedCount)x<<"; observed="<<e.observedCount;x<<"]";o.push_back(x.str());}o.push_back("");}
    return o;
}

std::vector<std::string> Decompiler::irLines() const{
    std::vector<std::string> o;if(!ready_){o.push_back("Decompiler model not built.");return o;}o.push_back("PacRipper low-level IR");o.push_back("Every IR statement begins with the exact source ROM instruction address.");o.push_back("");
    for(const auto&kv:blocks_){o.push_back(blockName(kv.first)+":  ; entry "+stateText(kv.second.entryState));for(auto a:kv.second.instructions){auto lines=instructionIR(analyzer_->instructions().at(a));for(auto&l:lines)o.push_back("  "+l);}o.push_back("  ; exit "+stateText(kv.second.exitState));o.push_back("");}return o;
}

void Decompiler::appendDefUseExpressionComments(std::vector<std::string>& out,std::uint16_t address,const std::string& indent) const{
    for(const auto& e:defUseResult_.expressions){
        if(e.instructionAddress!=address||!e.exact||e.text.empty())continue;
        std::ostringstream s;s<<indent<<"// def-use analysis exact: "<<e.entity<<" = "<<e.text<<"; provenance={";
        std::size_t n=0;for(auto pc:e.provenance){if(n++)s<<",";s<<"$"<<hex16(pc);}
        s<<"}";out.push_back(s.str());
    }
}

void Decompiler::appendHardwareSemanticHardwareComments(std::vector<std::string>& out,std::uint16_t address,const std::string& indent) const{
    for(const auto& r:hardwareAccesses_){
        if(r.pc!=address||!r.staticProof||r.device==BoardDeviceKind::None||r.device==BoardDeviceKind::MixedOrUnknown)continue;
        std::ostringstream s;s<<indent<<"// hardware-semantics analysis hardware: ";
        if(!r.intrinsic.empty())s<<r.intrinsic;
        else{s<<HardwareSemantics::accessText(r.access)<<" "<<HardwareSemantics::deviceText(r.device)<<" $"<<hex16(r.start);if(r.end>r.start+1)s<<"-$"<<hex16(static_cast<std::uint16_t>(r.end-1));}
        s<<" ["<<HardwareSemantics::resolutionText(r.addressResolution)<<", "<<HardwareSemantics::effectText(r.effect);if(r.dynamicObserved)s<<", trace-corroborated";s<<"] provenance={";
        std::size_t n=0;for(auto pc:r.provenancePCs){if(n++)s<<",";s<<"$"<<hex16(pc);}s<<"}";out.push_back(s.str());
    }
}

std::vector<std::string> Decompiler::pseudocodeLines() const{
    std::vector<std::string> o;if(!ready_){o.push_back("Decompiler model not built.");return o;}
    o.push_back("PacRipper conservative pseudocode");
    o.push_back("Function entries are evidence-backed CALL/vector/RST20 targets. Shared and unowned blocks are kept explicit instead of forcing a guessed owner.");
    o.push_back("Every emitted statement carries its exact source ROM instruction address.");
    o.push_back("");
    auto emitBlock=[&](const BasicBlock& b,const std::string& indent){
        o.push_back(indent+blockName(b.start)+":");
        if(!b.entryState.regs.empty()) { const std::string st=stateText(b.entryState); if(st!="(no constants)") o.push_back(indent+"  // proven entry constants: "+st); }
        for(auto a:b.instructions){appendTypeContractTypeComments(o,a,indent+"  ");appendHardwareSemanticHardwareComments(o,a,indent+"  ");appendDefUseExpressionComments(o,a,indent+"  ");const Instruction& in=analyzer_->instructions().at(a);auto lines=instructionIR(in);for(auto line:lines){const auto p=line.find("  ");const std::string core=p==std::string::npos?line:line.substr(p+2);o.push_back(indent+"  "+core+";  // $"+hex16(a));}}
    };
    for(const auto&fk:functions_){const auto&f=fk.second;o.push_back("function "+f.name+"() {  // ROM $"+hex16(f.entry));
        std::size_t shared=0;
        for(auto bs:f.blocks){const auto bi=blocks_.find(bs);if(bi==blocks_.end())continue;if(bi->second.functionOwners.size()>1){++shared;continue;}emitBlock(bi->second,"  ");}
        if(shared)o.push_back("  // "+std::to_string(shared)+" shared block(s) reachable from this function are emitted once in the shared-block section below.");
        if(!f.callees.empty()){std::ostringstream c;c<<"  // callees: ";std::size_t n=0;for(auto a:f.callees){if(n++)c<<", ";c<<functionName(a);}o.push_back(c.str());}
        o.push_back("}");o.push_back("");
    }
    bool anyShared=false;for(const auto&kv:blocks_)if(kv.second.functionOwners.size()>1){if(!anyShared){o.push_back("shared_blocks {  // blocks reached from multiple inferred function entries");anyShared=true;}std::ostringstream owners;owners<<"  // owners: ";std::size_t n=0;for(auto f:kv.second.functionOwners){if(n++)owners<<", ";owners<<functionName(f);}o.push_back(owners.str());emitBlock(kv.second,"  ");o.push_back("");}if(anyShared){o.push_back("}");o.push_back("");}
    bool anyUnowned=false;for(const auto&kv:blocks_)if(kv.second.functionOwners.empty()){if(!anyUnowned){o.push_back("unassigned_blocks {  // proven code without a defensible inferred function owner yet");anyUnowned=true;}emitBlock(kv.second,"  ");o.push_back("");}if(anyUnowned)o.push_back("}");
    return o;
}


std::string Decompiler::addressSetText(const std::set<std::uint16_t>& values) const {
    std::ostringstream o;std::size_t n=0;for(auto v:values){if(n++)o<<", ";o<<"$"<<hex16(v);}return o.str();
}

void Decompiler::appendStructuredBlockLines(std::vector<std::string>& out,std::uint16_t block,
                                            const std::string& indent,bool skipProvingBranch,
                                            std::uint16_t provingAddress) const {
    const auto bi=blocks_.find(block);if(bi==blocks_.end())return;out.push_back(indent+blockName(block)+":");
    if(!bi->second.entryState.regs.empty()){const auto st=stateText(bi->second.entryState);if(st!="(no constants)")out.push_back(indent+"  // proven entry constants: "+st);}
    for(auto a:bi->second.instructions){appendTypeContractTypeComments(out,a,indent+"  ");appendHardwareSemanticHardwareComments(out,a,indent+"  ");appendDefUseExpressionComments(out,a,indent+"  ");if(skipProvingBranch&&a==provingAddress){out.push_back(indent+"  // control transfer at $"+hex16(a)+" lifted by the enclosing structured region");continue;}auto lines=instructionIR(analyzer_->instructions().at(a));for(auto line:lines){const auto pos=line.find("  ");const std::string core=pos==std::string::npos?line:line.substr(pos+2);out.push_back(indent+"  "+core+";  // $"+hex16(a));}}
}

void Decompiler::appendStructuredRegionLines(std::vector<std::string>& out,const StructuredRegion& r,
                                             const std::string& indent) const {
    const std::string cond=r.condition.empty()?"/* unresolved Z80 flag condition */":r.condition;
    auto emitSet=[&](const std::set<std::uint16_t>& set,const std::string& bodyIndent,std::uint16_t skipAddress) {
        std::set<std::uint16_t> childBlocks;std::map<std::uint16_t,const StructuredRegion*> childAt;
        for(const auto& c:r.children)if(std::includes(set.begin(),set.end(),c.blocks.begin(),c.blocks.end())){childBlocks.insert(c.blocks.begin(),c.blocks.end());childAt[c.entry]=&c;}
        for(auto b:set){auto ci=childAt.find(b);if(ci!=childAt.end()){appendStructuredRegionLines(out,*ci->second,bodyIndent);continue;}if(childBlocks.count(b))continue;const bool skip=skipAddress!=0&&blocks_.at(b).instructions.end()!=std::find(blocks_.at(b).instructions.begin(),blocks_.at(b).instructions.end(),skipAddress);appendStructuredBlockLines(out,b,bodyIndent,skip,skipAddress);}
    };
    switch(r.kind){
        case RegionKind::If:
            appendStructuredBlockLines(out,r.entry,indent,true,r.conditionAddress);
            out.push_back(indent+"if ("+cond+") {  // proven by branch at ROM $"+hex16(r.conditionAddress)+", join $"+(r.join>=0?hex16(static_cast<std::uint16_t>(r.join)):std::string("????")));
            emitSet(r.trueBlocks,indent+"  ",0);out.push_back(indent+"}");break;
        case RegionKind::IfElse:
            appendStructuredBlockLines(out,r.entry,indent,true,r.conditionAddress);
            out.push_back(indent+"if ("+cond+") {  // proven by branch at ROM $"+hex16(r.conditionAddress)+", join $"+(r.join>=0?hex16(static_cast<std::uint16_t>(r.join)):std::string("????")));
            emitSet(r.trueBlocks,indent+"  ",0);out.push_back(indent+"} else {");emitSet(r.falseBlocks,indent+"  ",0);out.push_back(indent+"}");break;
        case RegionKind::While:{
            out.push_back(indent+"while (true) {  // natural loop header $"+hex16(r.entry));
            appendStructuredBlockLines(out,r.entry,indent+"  ",true,r.conditionAddress);
            out.push_back(indent+"  if (!("+cond+")) break;  // proven exit test at ROM $"+hex16(r.conditionAddress));
            std::set<std::uint16_t> body=r.blocks;body.erase(r.entry);emitSet(body,indent+"  ",0);out.push_back(indent+"}");break;}
        case RegionKind::DoWhile:
            out.push_back(indent+"do {  // natural loop header $"+hex16(r.entry));emitSet(r.blocks,indent+"  ",r.conditionAddress);out.push_back(indent+"} while ("+cond+");  // proven by branch at ROM $"+hex16(r.conditionAddress));break;
        default:
            for(auto b:r.blocks) appendStructuredBlockLines(out,b,indent,false,0);
            break;
    }
}

std::vector<std::string> Decompiler::structuredPseudocodeLines() const {
    std::vector<std::string> o;if(!ready_){o.push_back("Decompiler model not built.");return o;}
    o.push_back("PacRipper structured pseudocode");
    o.push_back("Only structures proven from function-local static CFG edges are lifted. Dynamic-only edges never prove a region.");
    o.push_back("Low-level block labels/gotos remain inside or beside structured regions whenever the graph is ambiguous. Every statement retains ROM provenance.");o.push_back("");
    for(const auto& fk:functions_) {
        const auto& f=fk.second;o.push_back("function "+f.name+"() {  // ROM $"+hex16(f.entry));
        auto si=structures_.find(f.entry);
        if(si!=structures_.end()) {
            const auto flat=StructuredControl::flattenRegions(si->second.regions);o.push_back("  // structural CFG blocks="+std::to_string(si->second.graph.nodes.size())+", loops="+std::to_string(si->second.loops.size())+", lifted-regions="+std::to_string(flat.size()));
            o.push_back("  // Address-ordered presentation only; remaining labels/gotos preserve non-structured control flow.");
            std::map<std::uint16_t,const StructuredRegion*> rootAt;std::set<std::uint16_t> rootBlocks;
            for(const auto& r:si->second.regions){rootAt[r.entry]=&r;rootBlocks.insert(r.blocks.begin(),r.blocks.end());}
            bool inFallbackRun=false;
            for(auto b:si->second.graph.nodes){
                const auto ri=rootAt.find(b);
                if(ri!=rootAt.end()){inFallbackRun=false;appendStructuredRegionLines(o,*ri->second,"  ");continue;}
                if(rootBlocks.count(b))continue;
                if(!inFallbackRun){o.push_back("  // goto fallback: following block(s) were not safely liftable");inFallbackRun=true;}
                appendStructuredBlockLines(o,b,"  ");
            }
        } else o.push_back("  // no uniquely-owned function-local structural CFG was available; use low-level pseudocode.");
        std::size_t shared=0;for(auto b:f.blocks){const auto bi=blocks_.find(b);if(bi!=blocks_.end()&&bi->second.functionOwners.size()>1)++shared;}if(shared)o.push_back("  // "+std::to_string(shared)+" shared block(s) are kept in the shared section below.");
        if(!f.callees.empty()){std::ostringstream c;c<<"  // callees: ";std::size_t n=0;for(auto a:f.callees){if(n++)c<<", ";c<<functionName(a);}o.push_back(c.str());}
        o.push_back("}");o.push_back("");
    }
    bool anyShared=false;for(const auto&kv:blocks_)if(kv.second.functionOwners.size()>1){if(!anyShared){o.push_back("shared_blocks {  // intentionally not forced into one function/structure");anyShared=true;}appendStructuredBlockLines(o,kv.first,"  ");o.push_back("");}if(anyShared){o.push_back("}");o.push_back("");}
    bool anyUnowned=false;for(const auto&kv:blocks_)if(kv.second.functionOwners.empty()){if(!anyUnowned){o.push_back("unassigned_blocks {  // proven code without a defensible inferred function owner");anyUnowned=true;}appendStructuredBlockLines(o,kv.first,"  ");o.push_back("");}if(anyUnowned)o.push_back("}");
    return o;
}

std::vector<std::string> Decompiler::dominatorLines() const {
    std::vector<std::string> o;if(!ready_){o.push_back("Decompiler model not built.");return o;}o.push_back("PacRipper function-local dominators");o.push_back("Only uniquely-owned blocks and static fallthrough/branch edges participate.");o.push_back("");
    for(const auto& sk:structures_){o.push_back(functionName(sk.first)+"  entry=$"+hex16(sk.first));for(const auto& d:sk.second.dominators){std::ostringstream x;x<<"  "<<blockName(d.first)<<"  idom=";if(d.second.immediateDominator<0)x<<"<root/none>";else x<<blockName(static_cast<std::uint16_t>(d.second.immediateDominator));x<<"  Dom={"<<addressSetText(d.second.dominators)<<"}";o.push_back(x.str());}o.push_back("");}return o;
}

std::vector<std::string> Decompiler::postDominatorLines() const {
    std::vector<std::string> o;if(!ready_){o.push_back("Decompiler model not built.");return o;}o.push_back("PacRipper function-local post-dominators");o.push_back("A synthetic exit is used internally but is never exposed as a ROM address.");o.push_back("");
    for(const auto& sk:structures_){o.push_back(functionName(sk.first)+"  entry=$"+hex16(sk.first));for(const auto& d:sk.second.postDominators){std::ostringstream x;x<<"  "<<blockName(d.first)<<"  ipdom=";if(d.second.immediatePostDominator<0)x<<"<synthetic-exit/none>";else x<<blockName(static_cast<std::uint16_t>(d.second.immediatePostDominator));x<<"  PostDom={"<<addressSetText(d.second.postDominators)<<"}";o.push_back(x.str());}o.push_back("");}return o;
}

std::vector<std::string> Decompiler::loopLines() const {
    std::vector<std::string> o;if(!ready_){o.push_back("Decompiler model not built.");return o;}o.push_back("PacRipper natural loops");o.push_back("Back-edges are accepted only when the header dominates the tail on the static structural CFG.");o.push_back("");
    for(const auto& sk:structures_) {
        for(const auto& l:sk.second.loops) o.push_back(functionName(sk.first)+"  header="+blockName(l.header)+"  blocks={"+addressSetText(l.blocks)+"}  latches={"+addressSetText(l.latches)+"}  exits={"+addressSetText(l.exits)+"}");
    }
    return o;
}

std::vector<std::string> Decompiler::structureLines() const {
    std::vector<std::string> o;if(!ready_){o.push_back("Decompiler model not built.");return o;}
    o.push_back("PacRipper structured-control analysis structured-control analysis");o.push_back("Functions with dominator trees: "+std::to_string(stats_.functionsWithDominatorTrees)+"  idom blocks: "+std::to_string(stats_.blocksWithImmediateDominator)+"  ipdom blocks: "+std::to_string(stats_.blocksWithImmediatePostDominator));
    o.push_back("Natural loops: "+std::to_string(stats_.naturalLoops)+"  if: "+std::to_string(stats_.structuredIfRegions)+"  if/else: "+std::to_string(stats_.structuredIfElseRegions)+"  while: "+std::to_string(stats_.structuredWhileRegions)+"  do/while: "+std::to_string(stats_.structuredDoWhileRegions)+"  fallback blocks: "+std::to_string(stats_.fallbackBlocks));o.push_back("");
    for(const auto& sk:structures_){const auto flat=StructuredControl::flattenRegions(sk.second.regions);o.push_back(functionName(sk.first)+"  $"+hex16(sk.first)+"  structural-blocks="+std::to_string(sk.second.graph.nodes.size())+" loops="+std::to_string(sk.second.loops.size())+" regions="+std::to_string(flat.size())+" fallback="+std::to_string(sk.second.fallbackBlocks.size()));for(const auto* r:flat){std::ostringstream x;x<<"  "<<StructuredControl::regionKindText(r->kind)<<" entry="<<blockName(r->entry)<<" condition@$"<<hex16(r->conditionAddress);if(!r->condition.empty())x<<" ["<<r->condition<<"]";if(r->join>=0)x<<" join="<<blockName(static_cast<std::uint16_t>(r->join));x<<" blocks={"<<addressSetText(r->blocks)<<"}";o.push_back(x.str());}if(!sk.second.graph.externalEntryBlocks.empty())o.push_back("  side-entry blocks excluded from unsafe regions: {"+addressSetText(sk.second.graph.externalEntryBlocks)+"}");o.push_back("");}return o;
}

std::vector<std::string> Decompiler::stackModelLines() const {
    std::vector<std::string> o;if(!ready_){o.push_back("Decompiler model not built.");return o;}o.push_back("PacRipper conservative stack model");o.push_back("Depth is relative to each inferred function entry. CALL/RST boundaries invalidate exact continuation stack state unless later evidence proves callee effects.");o.push_back("");
    for(const auto& sk:structures_){o.push_back(functionName(sk.first)+"  entry=$"+hex16(sk.first));for(auto b:sk.second.graph.nodes){const auto it=stackBlocks_.find(b);if(it==stackBlocks_.end()||!it->second.entryInitialized){o.push_back("  "+blockName(b)+"  entry=<unreached/ambiguous>");continue;}o.push_back("  "+blockName(b)+"  entry: "+StackModel::stateText(it->second.entryState));if(it->second.exitInitialized)o.push_back("    exit: "+StackModel::stateText(it->second.exitState));}o.push_back("");}return o;
}

std::vector<std::string> Decompiler::callReturnLines() const {
    std::vector<std::string> o;if(!ready_){o.push_back("Decompiler model not built.");return o;}o.push_back("PacRipper call / return evidence");o.push_back("Direct CALL continuations are static evidence. Concrete return destinations are dynamic evidence and remain labeled as observations.");o.push_back("");
    for(const auto& fk:functions_){o.push_back(functionName(fk.first)+"  $"+hex16(fk.first));const auto ei=callReturnEvidence_.find(fk.first);if(ei!=callReturnEvidence_.end()){o.push_back("  direct CALL callers: {"+addressSetText(ei->second.staticCallers)+"}");o.push_back("  static call continuations: {"+addressSetText(ei->second.staticContinuations)+"}");if(ei->second.observedReturnDestinations.empty())o.push_back("  observed returns: none in imported traces");else for(const auto& r:ei->second.observedReturnDestinations)o.push_back("  observed return -> $"+hex16(r.first)+"  transitions="+std::to_string(r.second)+(ei->second.staticContinuations.count(r.first)?"  MATCHES known continuation":"  dynamic/unmatched"));}o.push_back("");}
    if(!callSites_.empty()){o.push_back("Modeled direct CALL sites with unique caller ownership:");for(const auto& c:callSites_)o.push_back("  $"+hex16(c.callAddress)+"  "+functionName(c.callerFunction)+" -> "+functionName(c.calleeFunction)+"  continuation=$"+hex16(c.continuation));o.push_back("");}
    if(!returnMatches_.empty()){o.push_back("Observed concrete return edges:");for(const auto& m:returnMatches_){std::ostringstream x;x<<"  RET@$"<<hex16(m.observed.returnAddress)<<" -> $"<<hex16(m.observed.destination)<<" count="<<m.observed.count<<" owner=";if(m.observed.calleeFunction<0)x<<"<shared/unresolved>";else x<<functionName(static_cast<std::uint16_t>(m.observed.calleeFunction));x<<(m.matchesKnownContinuation?" MATCH":" dynamic/unmatched");if(!m.matchingCallSites.empty())x<<" call-sites={"<<addressSetText(m.matchingCallSites)<<"}";o.push_back(x.str());}}
    return o;
}

std::vector<std::string> Decompiler::conditionSemanticsLines() const {
    std::vector<std::string> o;if(!ready_){o.push_back("Decompiler model not built.");return o;}
    o.push_back("PacRipper condition-semantics analysis flag-producer / condition semantics");
    o.push_back("Flag-based conditional branches: "+std::to_string(stats_.conditionalFlagBranches)+"  exact producers: "+std::to_string(stats_.flagProducerResolvedBranches)+"  semantic expressions: "+std::to_string(stats_.semanticConditionBranches)+"  cross-block semantics: "+std::to_string(stats_.crossBlockSemanticConditions));
    o.push_back("Semantic candidates suppressed because a dependent value changed after the producer: "+std::to_string(stats_.semanticConditionsSuppressedByClobber));
    o.push_back("Expressions are emitted only when the tested Z80 flag has an unambiguous producer and every register/memory dependency remains unchanged to the branch. Raw Z/NZ/C/NC/PO/PE/P/M is retained otherwise.");o.push_back("");
    for(const auto& kv:conditionEvidence_){const auto& r=kv.second;std::ostringstream x;x<<"$"<<hex16(r.branchAddress)<<"  raw="<<r.rawCondition<<"  producer=";
        if(r.producerAddress<0)x<<"<ambiguous/unknown>";else{x<<"$"<<hex16(static_cast<std::uint16_t>(r.producerAddress))<<"  "<<r.producerInstruction;if(r.crossBlock)x<<"  [cross-block]";}
        if(!r.expression.empty())x<<"  => "<<r.expression;else x<<"  => <"<<r.semanticNote<<">";o.push_back(x.str());}
    return o;
}


std::vector<std::string> Decompiler::romClosureLines() const {
    std::vector<std::string> o;if(!ready_){o.push_back("Decompiler model not built.");return o;}
    const auto& s=stats_.romClosure;
    o.push_back("PacRipper ROM-closure analysis ROM byte-level closure");
    o.push_back("Hard code/data remains exclusive Analyzer truth; proven ROM data-use is deliberately non-exclusive so dual-use code/data stays representable.");
    o.push_back("Evidence-backed explained bytes: "+std::to_string(s.evidenceBackedExplainedBytes)+" / "+std::to_string(s.romBytes)+" (code, hard data, exact static reads, or dynamic non-fetch reads)");
    o.push_back("Explained when bounded static consumer spans are included: "+std::to_string(s.boundedExplainedBytes)+" / "+std::to_string(s.romBytes));
    o.push_back("Primary byte classes: code="+std::to_string(s.codeBytes)+", code+data-use="+std::to_string(s.codeAndDataUseBytes)+", hard-data="+std::to_string(s.hardDataBytes)+", proven-data-use="+std::to_string(s.provenDataUseBytes)+", bounded-consumer="+std::to_string(s.boundedConsumerBytes)+", candidate="+std::to_string(s.candidateBytes)+", pointer-target="+std::to_string(s.pointerTargetBytes)+", unresolved="+std::to_string(s.unresolvedBytes));
    o.push_back("Consumers: "+std::to_string(s.consumers)+" (exact-static="+std::to_string(s.exactStaticConsumers)+", bounded="+std::to_string(s.boundedConsumers)+", dynamic="+std::to_string(s.dynamicConsumers)+")  immediate ROM pointer seeds="+std::to_string(s.immediateRomPointerSeeds)+", derived pointer targets="+std::to_string(s.derivedRomPointerTargets));
    o.push_back("RAM 16-bit pairs: "+std::to_string(s.ramPairs)+"  pointer-like pairs="+std::to_string(s.pointerLikeRamPairs));o.push_back("");
    if(romClosureBytes_.empty())return o;
    std::size_t i=0;
    while(i<romClosureBytes_.size()){
        const auto kind=romClosureBytes_[i].primary;std::size_t j=i+1;
        while(j<romClosureBytes_.size()&&romClosureBytes_[j].primary==kind)++j;
        std::set<std::uint16_t> pcs;for(std::size_t a=i;a<j;++a)pcs.insert(romClosureBytes_[a].consumerPCs.begin(),romClosureBytes_[a].consumerPCs.end());
        std::ostringstream x;x<<"$"<<hex16(static_cast<std::uint16_t>(i))<<"-$"<<hex16(static_cast<std::uint16_t>(j-1))<<"  len="<<(j-i)<<"  "<<RomClosure::primaryText(kind);
        if(!pcs.empty()) x<<"  consumers={"<<addressSetText(pcs)<<"}";
        o.push_back(x.str());i=j;
    }
    return o;
}

std::vector<std::string> Decompiler::romConsumerLines() const {
    std::vector<std::string> o;if(!ready_){o.push_back("Decompiler model not built.");return o;}
    o.push_back("PacRipper ROM-closure analysis ROM pointer / consumer cross-links");
    o.push_back("exact = concrete statically resolved byte(s); bounded = proven address interval whose individual indices may depend on runtime input; dynamic = observed bus evidence.");o.push_back("");
    std::vector<RomConsumerRecord> rows=romConsumers_;std::sort(rows.begin(),rows.end(),[](const RomConsumerRecord&a,const RomConsumerRecord&b){if(a.start!=b.start)return a.start<b.start;if(a.pc!=b.pc)return a.pc<b.pc;return static_cast<int>(a.kind)<static_cast<int>(b.kind);});
    for(const auto& r:rows){std::ostringstream x;x<<"$"<<hex16(r.start);if(r.end>r.start+1)x<<"-$"<<hex16(static_cast<std::uint16_t>(r.end-1));x<<"  <- PC $"<<hex16(r.pc)<<"  "<<RomClosure::consumerKindText(r.kind);if(!r.pointerRegister.empty())x<<" ptr="<<r.pointerRegister;if(!r.indexRegister.empty())x<<" index="<<r.indexRegister;x<<"  ["<<(r.dynamic?"dynamic":r.exact?"exact-static":r.bounded?"bounded-static":"static")<<"]";if(!r.note.empty())x<<"  "<<r.note;o.push_back(x.str());}
    if(rows.empty()) o.push_back("No ROM consumers recovered.");
    return o;
}

std::vector<std::string> Decompiler::ramPairLines() const {
    std::vector<std::string> o;if(!ready_){o.push_back("Decompiler model not built.");return o;}
    o.push_back("PacRipper ROM-closure analysis 16-bit RAM pair evidence");
    o.push_back("Pairs are machine-level adjacent-byte facts from direct 16-bit Z80 accesses; pointer-like is added only when the loaded pair is then dereferenced in the same basic block.");o.push_back("");
    for(const auto& r:ramPairEvidence_){std::ostringstream x;x<<"$"<<hex16(r.address)<<"/$"<<hex16(static_cast<std::uint16_t>(r.address+1))<<"  pair="<<r.pairRegister<<"  access="<<(r.read&&r.write?"read/write":r.read?"read":"write")<<(r.pointerLike?"  POINTER-LIKE":"")<<"  PCs={"<<addressSetText(r.sourcePCs)<<"}";if(!r.note.empty())x<<"  "<<r.note;o.push_back(x.str());}
    if(ramPairEvidence_.empty()) o.push_back("No direct 16-bit RAM pair accesses recovered.");
    return o;
}

std::vector<std::string> Decompiler::valuePropagationLines() const{
    std::vector<std::string> o;if(!ready_){o.push_back("Decompiler model not built.");return o;}o.push_back("PacRipper abstract register/value propagation");o.push_back("Only constants that survive all known predecessor paths are retained.");o.push_back("");for(const auto&kv:blocks_){o.push_back(blockName(kv.first)+"  entry: "+stateText(kv.second.entryState));o.push_back("  exit: "+stateText(kv.second.exitState));}return o;
}



} // namespace pacripper
