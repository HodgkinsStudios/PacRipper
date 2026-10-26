// PacRipper contract-aware value flow stable machine-value identities and call bindings
// Created by Jacob Hodgkins

#include "ValueFlow.h"

#include <algorithm>
#include <functional>
#include <limits>
#include <map>
#include <sstream>

namespace pacripper {
namespace {

const ExpressionRecord* expressionFor(std::size_t id,const std::map<std::size_t,const ExpressionRecord*>& m){auto i=m.find(id);return i==m.end()?nullptr:i->second;}

std::string valueName(std::size_t id){return "mv_d"+std::to_string(id);}
std::string originName(const std::set<std::size_t>& ids,bool entry,bool unknown){
    if(ids.size()==1&&!entry&&!unknown)return "origin_d"+std::to_string(*ids.begin());
    std::ostringstream o;o<<"origin_set{";std::size_t n=0;for(auto id:ids){if(n++)o<<",";o<<"d"<<id;}if(entry){if(n++)o<<",";o<<"entry";}if(unknown){if(n++)o<<",";o<<"unknown";}o<<"}";return o.str();
}

const RoutineContractRecord* contractFor(std::uint16_t fn,const std::map<std::uint16_t,const RoutineContractRecord*>& m){auto i=m.find(fn);return i==m.end()?nullptr:i->second;}

} // namespace

std::vector<MachineValueRecord> ValueFlow::buildMachineValues(const DefUseResult& defUse){
    std::map<std::size_t,const DefinitionRecord*> defs;
    for(const auto&d:defUse.definitions)defs[d.id]=&d;
    std::map<std::size_t,const ExpressionRecord*> exprs;
    for(const auto&e:defUse.expressions)exprs[e.definitionId]=&e;

    struct OriginFact{std::set<std::size_t> ids;bool entry=false;bool unknown=false;};
    std::map<std::size_t,OriginFact> memo;std::set<std::size_t> active;
    std::function<OriginFact(std::size_t)> roots=[&](std::size_t id)->OriginFact{
        auto mi=memo.find(id);if(mi!=memo.end())return mi->second;
        OriginFact out;auto di=defs.find(id);if(di==defs.end()||active.count(id)){out.ids.insert(id);return out;}
        const auto&d=*di->second;active.insert(id);
        bool copied=false;
        if(d.operation==DefExpressionKind::Copy&&d.operands.size()==1&&!d.operands[0].constant){
            auto ri=d.reachingOperands.find(d.operands[0].entity);
            if(ri!=d.reachingOperands.end()){
                const auto&f=ri->second;out.entry=f.includesEntryValue;out.unknown=f.includesClobberedUnknown;
                if(f.definitionIds.size()==1&&!f.includesEntryValue&&!f.includesClobberedUnknown){out=roots(*f.definitionIds.begin());copied=true;}
                else {for(auto sid:f.definitionIds){auto r=roots(sid);out.ids.insert(r.ids.begin(),r.ids.end());out.entry=out.entry||r.entry;out.unknown=out.unknown||r.unknown;}}
            }
        }
        if(!copied&&out.ids.empty()&&!out.entry&&!out.unknown)out.ids.insert(id);
        active.erase(id);memo[id]=out;return out;
    };

    std::vector<MachineValueRecord> out;
    for(const auto&d:defUse.definitions){
        if(!d.semanticExact||d.callBoundaryClobber||d.aliasInvalidation||d.operation==DefExpressionKind::Unknown)continue;
        MachineValueRecord r;r.id=d.id;r.definitionId=d.id;r.definitionPC=d.instructionAddress;r.entity=d.entity;r.bits=d.bits;r.localName=valueName(d.id);r.semanticExact=true;
        const auto root=roots(d.id);r.originDefinitionIds=root.ids;r.includesEntryOrigin=root.entry;r.includesUnknownOrigin=root.unknown;r.copyAlias=d.operation==DefExpressionKind::Copy&&r.originDefinitionIds.size()==1&&*r.originDefinitionIds.begin()!=d.id&&!r.includesEntryOrigin&&!r.includesUnknownOrigin;r.originName=originName(r.originDefinitionIds,r.includesEntryOrigin,r.includesUnknownOrigin);
        const auto*e=expressionFor(d.id,exprs);if(e){r.expression=e->text;r.provenancePCs=e->provenance;}if(r.provenancePCs.empty())r.provenancePCs.insert(d.instructionAddress);
        out.push_back(r);
    }
    return out;
}

std::vector<MergeValueRecord> ValueFlow::buildMergeValues(const DefUseResult& defUse){
    std::vector<MergeValueRecord> out;std::size_t id=0;
    for(const auto&pk:defUse.stateBeforeInstruction)for(const auto&ek:pk.second){const auto&f=ek.second;if(!f.ambiguous())continue;MergeValueRecord r;r.id=id++;r.pc=pk.first;r.entity=ek.first;r.definitionIds=f.definitionIds;r.includesEntryValue=f.includesEntryValue;r.includesClobberedUnknown=f.includesClobberedUnknown;r.unknownSourcePCs=f.unknownSourceAddresses;std::ostringstream s;s<<"phi{";std::size_t n=0;for(auto d:r.definitionIds){if(n++)s<<",";s<<valueName(d);}if(r.includesEntryValue){if(n++)s<<",";s<<"entry_"<<r.entity;}if(r.includesClobberedUnknown){if(n++)s<<",";s<<"clobbered_unknown";}s<<"}";r.phiText=s.str();out.push_back(r);}
    return out;
}

std::vector<CallBindingRecord> ValueFlow::buildCallBindings(const std::vector<CallSiteRecord>& callSites,const std::vector<RoutineContractRecord>& contracts,const std::map<std::uint16_t,FunctionRegisterSummary>& summaries,const DefUseResult& defUse,const std::vector<MachineValueRecord>& values){
    std::map<std::uint16_t,const RoutineContractRecord*> byFn;for(const auto&c:contracts)byFn[c.functionEntry]=&c;
    std::map<std::size_t,const ExpressionRecord*> exprs;for(const auto&e:defUse.expressions)exprs[e.definitionId]=&e;
    std::map<std::size_t,const MachineValueRecord*> byDef;for(const auto&v:values)byDef[v.definitionId]=&v;
    std::vector<CallBindingRecord> out;std::size_t id=0;
    for(const auto&cs:callSites){
        const auto*c=contractFor(cs.calleeFunction,byFn);if(!c)continue;
        auto si=defUse.stateBeforeInstruction.find(cs.callAddress);if(si==defUse.stateBeforeInstruction.end())continue;
        auto sm=summaries.find(cs.calleeFunction);const FunctionRegisterSummary*summary=sm==summaries.end()?nullptr:&sm->second;
        std::set<std::string> inputRegs;
        for(const auto&input:c->inputs){
            inputRegs.insert(input.reg);
            CallBindingRecord r;r.id=id++;r.callerFunction=cs.callerFunction;r.callPC=cs.callAddress;r.calleeFunction=cs.calleeFunction;r.reg=input.reg;r.inputCertainty=input.certainty;r.hasInputBinding=true;r.roles=input.roles;
            auto ri=si->second.find(input.reg);if(ri!=si->second.end()){r.definitionIds=ri->second.definitionIds;r.includesEntryValue=ri->second.includesEntryValue;r.includesClobberedUnknown=ri->second.includesClobberedUnknown;}
            for(auto did:r.definitionIds){auto vi=byDef.find(did);r.valueNames.push_back(vi==byDef.end()?valueName(did):vi->second->localName);auto ei=exprs.find(did);if(ei!=exprs.end()&&ei->second->exact)r.expressions.push_back(ei->second->text);}
            if(r.includesEntryValue)r.valueNames.push_back("entry_"+r.reg);
            if(r.includesClobberedUnknown)r.valueNames.push_back("clobbered_unknown");
            const RegisterContractFact*output=nullptr;for(const auto&o:c->outputs)if(o.reg==r.reg&&o.certainty==ContractCertainty::Definite&&!o.sourcePCs.empty()){output=&o;break;}
            r.provenReturningOutput=output!=nullptr;r.hasOutputBinding=r.provenReturningOutput;if(output){r.outputSourcePCs=output->sourcePCs;r.roles.insert(output->roles.begin(),output->roles.end());}
            r.provenPreserved=RoutineContracts::survivesDirectCall(r.reg,summary)&&!r.provenReturningOutput;
            if(r.provenReturningOutput){r.postValueKind=CallPostValueKind::ProducedOutput;r.postValueName="ret_"+std::to_string(cs.calleeFunction)+"_"+r.reg+"_at_"+std::to_string(cs.callAddress);}
            else if(r.provenPreserved){r.postValueKind=CallPostValueKind::PreservedInput;r.postValueName=r.valueNames.size()==1?r.valueNames.front():("preserved_"+r.reg+"_at_"+std::to_string(cs.callAddress));}
            else r.postValueKind=CallPostValueKind::None;
            out.push_back(r);
        }
        // A definite semantic return is still a post-call machine value even when
        // the register was not an input to the callee. Keep it as an explicit
        // output-only binding rather than silently losing that contract fact.
        for(const auto&output:c->outputs){
            if(output.certainty!=ContractCertainty::Definite||output.sourcePCs.empty()||inputRegs.count(output.reg))continue;
            CallBindingRecord r;r.id=id++;r.callerFunction=cs.callerFunction;r.callPC=cs.callAddress;r.calleeFunction=cs.calleeFunction;r.reg=output.reg;r.hasOutputBinding=true;r.provenReturningOutput=true;r.roles=output.roles;r.outputSourcePCs=output.sourcePCs;r.postValueKind=CallPostValueKind::ProducedOutput;r.postValueName="ret_"+std::to_string(cs.calleeFunction)+"_"+r.reg+"_at_"+std::to_string(cs.callAddress);out.push_back(r);
        }
    }
    return out;
}

ValueFlowStats ValueFlow::stats(const std::vector<MachineValueRecord>&values,const std::vector<MergeValueRecord>&merges,const std::vector<CallBindingRecord>&bindings){ValueFlowStats s;s.machineValues=values.size();s.mergeValues=merges.size();for(const auto&v:values){if(v.semanticExact)++s.exactMachineValues;if(v.copyAlias)++s.copyAliases;}s.callBindings=bindings.size();for(const auto&b:bindings){if(b.hasInputBinding){if(b.inputCertainty==ContractCertainty::Definite)++s.definiteCallBindings;else ++s.possibleCallBindings;}if(b.hasOutputBinding)++s.outputBindings;if(b.postValueKind==CallPostValueKind::PreservedInput)++s.preservedPostCallValues;else if(b.postValueKind==CallPostValueKind::ProducedOutput)++s.returnedPostCallValues;}return s;}

std::string ValueFlow::postValueKindText(CallPostValueKind kind){switch(kind){case CallPostValueKind::PreservedInput:return "preserved-input";case CallPostValueKind::ProducedOutput:return "produced-output";case CallPostValueKind::None:return "none";}return "none";}

} // namespace pacripper
