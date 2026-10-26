// PacRipper system-root reachability analysis system-root reachability and indirect-address refinement
// Created by Jacob Hodgkins

#include "SystemRootAnalysis.h"

#include <algorithm>
#include <limits>
#include <queue>

namespace pacripper {
namespace {

struct WorkItem18 {
    std::uint16_t address=0;
    int predecessor=-1;
    SystemRootReachabilityEdgeKind edge=SystemRootReachabilityEdgeKind::Root;
};

bool independentStatic(const Analyzer& analyzer,std::uint16_t pc){
    return analyzer.hasStaticInstructionProof(pc)&&!analyzer.isTraceDiscoveredInstruction(pc);
}

bool hardTypedData(const std::vector<RomByteClosureRecord>& closure,std::uint16_t start,std::size_t length){
    for(std::size_t n=0;n<length;++n){
        const std::size_t a=static_cast<std::size_t>(start)+n;
        if(a>=closure.size())return true;
        const auto& b=closure[a];
        // Code+data overlaps remain legal. Reject only bytes that were already
        // independently hard-typed as data and have no code interpretation.
        if(b.hardData&&!b.code)return true;
    }
    return false;
}

std::uint16_t readWord(const std::vector<std::uint8_t>& p,std::size_t at){
    return static_cast<std::uint16_t>(p[at]|(static_cast<std::uint16_t>(p[at+1])<<8));
}

std::uint16_t pushedContinuationBefore(const std::map<std::uint16_t,Instruction>& ins,std::uint16_t rstAddress){
    auto it=ins.lower_bound(rstAddress);std::uint16_t cursor=rstAddress;std::vector<const Instruction*> prior;
    for(unsigned n=0;n<10&&it!=ins.begin();++n){
        const Instruction* found=nullptr;
        while(it!=ins.begin()){
            --it;
            const auto end=static_cast<std::uint32_t>(it->first)+it->second.length();
            if(end==cursor){found=&it->second;break;}
            if(end<cursor)break;
        }
        if(!found)break;
        prior.push_back(found);
        cursor=found->address;
    }
    for(std::size_t i=0;i+1<prior.size();++i){
        const Instruction& push=*prior[i];const Instruction& load=*prior[i+1];
        if(push.mnemonic=="PUSH"&&push.operands=="HL"&&load.bytes.size()==3&&load.bytes[0]==0x21)
            return static_cast<std::uint16_t>(load.bytes[1]|(static_cast<std::uint16_t>(load.bytes[2])<<8));
    }
    return 0xFFFF;
}

} // namespace

SystemRootReachabilityResult SystemRootAnalysis::discoverSystemRoots(
    const Analyzer& analyzer,
    const std::vector<RomByteClosureRecord>& frozenResidualReferenceClosure,
    const std::vector<SystemRomSemanticRecord>& systemSemantics){

    SystemRootReachabilityResult out;
    const auto& program=analyzer.program();
    if(program.empty())return out;

    for(const auto& semantic:systemSemantics){
        if(!semantic.staticProof||!semantic.exact||semantic.kind!=SystemRomSemanticKind::InterruptVectorWord)continue;
        if(semantic.target>=program.size()||semantic.targetStaticBeforeResidualReference)continue;
        SystemRootRecord root;root.id=out.roots.size();root.kind=SystemRootKind::InterruptVectorTarget;
        root.entry=semantic.target;root.systemSemanticId=semantic.id;root.vectorAddress=semantic.start;
        root.vectorByte=semantic.vectorByte;root.staticProof=true;root.targetStaticBeforeSystemRoot=independentStatic(analyzer,semantic.target);
        root.proofPCs=semantic.proofPCs;root.note="system-root reachability analysis additive system root: exact residual-reference analysis IM2 vector target; no the established analysis pipeline evidence is mutated.";
        out.roots.push_back(root);
    }

    Z80Disassembler dis;
    for(const auto& root:out.roots){
        std::map<std::uint16_t,Instruction> localInstructions;
        std::vector<bool> code(program.size(),false),data(program.size(),false);
        std::queue<WorkItem18> q;q.push({root.entry,-1,SystemRootReachabilityEdgeKind::Root});
        std::size_t guard=0;

        auto markInline=[&](SystemRootInlineDataKind kind,std::uint16_t source,std::uint16_t start,std::uint16_t end,const std::set<std::uint16_t>& targets,const std::string& note)->bool{
            if(start>=end||end>program.size())return false;
            for(std::uint16_t a=start;a<end;++a)if(code[a])return false;
            for(std::uint16_t a=start;a<end;++a)data[a]=true;
            SystemRootInlineDataRecord r;r.id=out.inlineData.size();r.rootId=root.id;r.kind=kind;r.sourcePC=source;r.start=start;r.end=end;r.dispatchTargets=targets;r.note=note;out.inlineData.push_back(r);return true;
        };

        auto queueTarget=[&](int target,int pred,SystemRootReachabilityEdgeKind edge){
            if(target>=0&&static_cast<std::size_t>(target)<program.size())q.push({static_cast<std::uint16_t>(target),pred,edge});
        };

        auto resolveRst20=[&](std::uint16_t rstAddress)->bool{
            const std::uint32_t base32=static_cast<std::uint32_t>(rstAddress)+1u;if(base32+1>=program.size())return false;
            const std::uint16_t base=static_cast<std::uint16_t>(base32);constexpr std::size_t maxEntries=256;
            std::vector<std::uint16_t> words;bool sawInvalid=false;std::size_t invalidIndex=0;
            for(std::size_t i=0;i<maxEntries;++i){
                const std::size_t p=static_cast<std::size_t>(base)+i*2u;if(p+1>=program.size()||data[p]||data[p+1]){sawInvalid=true;invalidIndex=i;break;}
                const auto target=readWord(program,p);if(target>=program.size()){sawInvalid=true;invalidIndex=i;break;}words.push_back(target);
            }
            struct Choice{std::size_t count=std::numeric_limits<std::size_t>::max();int priority=99;std::string reason;} choice;
            auto consider=[&](std::size_t count,int priority,const std::string& reason){if(count==0||count>words.size())return;if(count<choice.count||(count==choice.count&&priority<choice.priority))choice={count,priority,reason};};
            for(auto target:words)if(target>=base){const std::uint32_t diff=static_cast<std::uint32_t>(target)-base;if((diff&1u)==0)consider(diff/2u,1,"first aligned local handler target");}
            const auto continuation=pushedContinuationBefore(localInstructions,rstAddress);if(continuation!=0xFFFF&&continuation>=base){const std::uint32_t diff=static_cast<std::uint32_t>(continuation)-base;if((diff&1u)==0)consider(diff/2u,0,"caller-pushed continuation");}
            for(const auto& kv:analyzer.instructions())if(kv.first>base&&independentStatic(analyzer,kv.first)){const std::uint32_t diff=static_cast<std::uint32_t>(kv.first)-base;if((diff&1u)==0)consider(diff/2u,0,"verified independently-static code boundary");break;}
            if(sawInvalid&&invalidIndex>0)consider(invalidIndex,3,"first non-ROM pointer word");
            if(choice.count==std::numeric_limits<std::size_t>::max())return false;
            const std::uint32_t end32=base32+choice.count*2u;if(end32>program.size())return false;const auto end=static_cast<std::uint16_t>(end32);
            std::set<std::uint16_t> targets;
            for(std::size_t i=0;i<choice.count;++i){const auto t=words[i];if(t>=base&&t<end)return false;targets.insert(t);}
            if(!markInline(SystemRootInlineDataKind::Rst20DispatchTable,rstAddress,base,end,targets,"RST $20 table extent proven by dispatcher convention and finite boundary: "+choice.reason))return false;
            for(auto t:targets)queueTarget(t,rstAddress,SystemRootReachabilityEdgeKind::DispatchTarget);
            // A caller-pushed continuation is both a table-boundary proof and an
            // executable successor. Keep those facts coupled so reachability cannot
            // use the continuation to delimit data while omitting its code path.
            if(continuation!=0xFFFF&&continuation>=end&&continuation<program.size())
                queueTarget(continuation,rstAddress,SystemRootReachabilityEdgeKind::InlineContinuation);
            return true;
        };

        while(!q.empty()&&guard++<50000){
            WorkItem18 item=q.front();q.pop();std::uint32_t pc=item.address;int pred=item.predecessor;auto edge=item.edge;
            while(pc<program.size()){
                const auto a=static_cast<std::uint16_t>(pc);
                if(localInstructions.count(a))break;
                if(data[pc]||code[pc])break;
                Instruction in=dis.decode(program,a);if(in.bytes.empty()||in.mnemonic=="DB"||pc+in.length()>program.size())break;
                bool overlap=false;for(std::size_t n=0;n<in.length();++n)if(code[pc+n]||data[pc+n]){overlap=true;break;}if(overlap)break;
                if(hardTypedData(frozenResidualReferenceClosure,a,in.length())){++out.hardDataConflicts;break;}
                localInstructions[a]=in;for(std::size_t n=0;n<in.length();++n)code[pc+n]=true;

                if(out.reachablePCs.insert(a).second){
                    SystemRootReachabilityRecord r;r.id=out.reachability.size();r.rootId=root.id;r.pc=a;r.predecessorPc=pred;r.edgeKind=edge;r.length=in.length();
                    r.alreadyIndependentStatic=independentStatic(analyzer,a);r.traceDiscoveredBeforeSystemRoot=analyzer.isTraceDiscoveredInstruction(a);r.newlyIndependentStatic=!r.alreadyIndependentStatic;
                    for(std::size_t n=0;n<in.length();++n){r.byteAddresses.insert(static_cast<std::uint16_t>(pc+n));out.reachableBytes.insert(static_cast<std::uint16_t>(pc+n));}
                    if(r.newlyIndependentStatic)out.newlyIndependentPCs.insert(a);
                    r.note=r.alreadyIndependentStatic?"root reaches an instruction already independently static before system-root reachability analysis":"independent system-root path upgrades this instruction without rewriting verified analyzer provenance";
                    out.reachability.push_back(r);
                }

                if(in.target>=0&&in.target<static_cast<int>(program.size())){
                    const auto ek=in.flow==FlowKind::Restart?SystemRootReachabilityEdgeKind::RestartTarget:SystemRootReachabilityEdgeKind::BranchOrCallTarget;
                    queueTarget(in.target,a,ek);
                }
                const std::uint32_t next=pc+in.length();
                // Pac-Man $2BCD is a statically proven custom inline-call consumer:
                // it POPs the return address, reads exactly five bytes, advances HL,
                // PUSHes the advanced continuation, then RETs. Model this separately
                // so the five payload bytes are not mis-promoted to executable code.
                if(in.flow==FlowKind::Call&&in.target==0x2BCD){
                    const std::uint32_t after=next+5u;
                    if(after>program.size()||!markInline(SystemRootInlineDataKind::CallInlineFiveBytes,a,static_cast<std::uint16_t>(next),static_cast<std::uint16_t>(after),{},"CALL $2BCD consumes exactly five inline bytes via POP HL / five reads / PUSH advanced HL"))break;
                    pred=a;edge=SystemRootReachabilityEdgeKind::InlineContinuation;pc=after;continue;
                }
                if(in.flow==FlowKind::Restart&&in.target==0x20){if(!resolveRst20(a))out.unresolvedIndirectExitPCs.insert(a);break;}
                if(in.flow==FlowKind::Restart&&in.target==0x28){
                    if(next+2u>program.size()||!markInline(SystemRootInlineDataKind::Rst28InlineArgs,a,static_cast<std::uint16_t>(next),static_cast<std::uint16_t>(next+2u),{},"RST $28 pops its caller return and consumes exactly two inline argument bytes"))break;
                    pred=a;edge=SystemRootReachabilityEdgeKind::InlineContinuation;pc=next+2u;continue;
                }
                if(in.flow==FlowKind::Restart&&in.target==0x30){
                    if(next+3u>program.size()||!markInline(SystemRootInlineDataKind::Rst30InlinePayload,a,static_cast<std::uint16_t>(next),static_cast<std::uint16_t>(next+3u),{},"RST $30 consumes exactly three inline payload bytes before JP (HL) continuation"))break;
                    pred=a;edge=SystemRootReachabilityEdgeKind::InlineContinuation;pc=next+3u;continue;
                }
                if(in.flow==FlowKind::Return&&!in.conditional)break;
                if(in.indirect&&in.flow==FlowKind::Jump){if(a!=0x0027&&a!=0x0064)out.unresolvedIndirectExitPCs.insert(a);break;}
                if((in.flow==FlowKind::Jump||in.flow==FlowKind::RelativeJump)&&!in.conditional)break;
                pred=a;edge=SystemRootReachabilityEdgeKind::Fallthrough;pc=next;
            }
        }
    }
    return out;
}

bool SystemRootAnalysis::addressIntersectsRom(const AddressLatticeValue& value,std::size_t romSize){
    return addressIntersectsSpan(value,0,static_cast<std::uint16_t>(std::min<std::size_t>(romSize,0xFFFFu)));
}

bool SystemRootAnalysis::addressIntersectsSpan(const AddressLatticeValue& value,std::uint16_t start,std::uint16_t end){
    return ResidualReferenceAnalysis::addressValueIntersects(value,start,end);
}

bool SystemRootAnalysis::supportsUnused(const SystemRootNegativeReferenceRecord& record,bool leftBoundaryProven,bool rightBoundaryProven){
    return record.exhaustiveModeledStaticAbsence&&leftBoundaryProven&&rightBoundaryProven
        &&!record.inheritedPositiveReference
        &&record.remainingOriginalBlockerPCs.empty()
        &&record.newlyRootedUnknownBlockerPCs.empty()
        &&record.finiteRefinedHitPCs.empty()
        &&record.dynamicReadEvents==0;
}

std::string SystemRootAnalysis::rootKindText(SystemRootKind kind){switch(kind){case SystemRootKind::InterruptVectorTarget:return "interrupt-vector-target";}return "unknown";}
std::string SystemRootAnalysis::edgeKindText(SystemRootReachabilityEdgeKind kind){switch(kind){case SystemRootReachabilityEdgeKind::Root:return "root";case SystemRootReachabilityEdgeKind::Fallthrough:return "fallthrough";case SystemRootReachabilityEdgeKind::BranchOrCallTarget:return "branch/call";case SystemRootReachabilityEdgeKind::RestartTarget:return "restart";case SystemRootReachabilityEdgeKind::DispatchTarget:return "dispatch";case SystemRootReachabilityEdgeKind::InlineContinuation:return "inline-continuation";}return "unknown";}
std::string SystemRootAnalysis::inlineKindText(SystemRootInlineDataKind kind){switch(kind){case SystemRootInlineDataKind::Rst20DispatchTable:return "rst20-dispatch-table";case SystemRootInlineDataKind::Rst28InlineArgs:return "rst28-inline-args";case SystemRootInlineDataKind::Rst30InlinePayload:return "rst30-inline-payload";case SystemRootInlineDataKind::CallInlineFiveBytes:return "call-inline-five-bytes";}return "unknown";}
std::string SystemRootAnalysis::refinementKindText(IndirectAddressRefinementKind kind){switch(kind){case IndirectAddressRefinementKind::ExactSet:return "exact-set";case IndirectAddressRefinementKind::ContiguousRange:return "contiguous-range";case IndirectAddressRefinementKind::StridedRange:return "strided-range";case IndirectAddressRefinementKind::NonRomRange:return "non-rom-range";case IndirectAddressRefinementKind::ProvenSemanticUnion:return "proven-semantic-union";case IndirectAddressRefinementKind::InlineConvention:return "inline-convention";}return "unknown";}

} // namespace pacripper
