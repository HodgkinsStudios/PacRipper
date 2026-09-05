// PacRipper type/contract analysis routine machine contracts
// Created by Jacob Hodgkins

#include "RoutineContracts.h"

#include <algorithm>

namespace pacripper {

bool RoutineContracts::survivesDirectCall(const std::string& reg,const FunctionRegisterSummary* s){return s&&s->preserved.count(reg)!=0;}
bool RoutineContracts::classifyEntryInput(const ReachingDefinitionFact& f,ContractCertainty& c){if(!f.includesEntryValue)return false;c=f.exactEntryValue()?ContractCertainty::Definite:ContractCertainty::Possible;return true;}
bool RoutineContracts::isProducedReturnValue(const ReachingDefinitionFact& f){return !f.includesEntryValue&&!f.includesClobberedUnknown&&!f.definitionIds.empty();}
std::string RoutineContracts::certaintyText(ContractCertainty c){return c==ContractCertainty::Definite?"definite":"possible";}

void RoutineContracts::normalize(RoutineContractRecord& r){
    auto norm=[](std::vector<RegisterContractFact>& v){
        std::sort(v.begin(),v.end(),[](const RegisterContractFact&a,const RegisterContractFact&b){if(a.reg!=b.reg)return a.reg<b.reg;return static_cast<int>(a.certainty)<static_cast<int>(b.certainty);});
        std::vector<RegisterContractFact> out;
        for(const auto& f:v){
            auto it=std::find_if(out.begin(),out.end(),[&](const RegisterContractFact&q){return q.reg==f.reg;});
            if(it==out.end())out.push_back(f);
            else{
                if(f.certainty==ContractCertainty::Definite)it->certainty=ContractCertainty::Definite;
                it->sourcePCs.insert(f.sourcePCs.begin(),f.sourcePCs.end());it->roles.insert(f.roles.begin(),f.roles.end());
            }
        }
        v.swap(out);
    };
    norm(r.inputs);
    norm(r.outputs);
    for(auto a:r.definiteRamReads) r.possibleRamReads.erase(a);
    for(auto a:r.definiteRamWrites) r.possibleRamWrites.erase(a);
    for(auto d:r.definiteHardwareReads) r.possibleHardwareReads.erase(d);
    for(auto d:r.definiteHardwareWrites) r.possibleHardwareWrites.erase(d);
}

RoutineContractStats RoutineContracts::stats(const std::vector<RoutineContractRecord>& records){RoutineContractStats s;s.routines=records.size();for(const auto&r:records){for(const auto&f:r.inputs)(f.certainty==ContractCertainty::Definite?++s.definiteRegisterInputs:++s.possibleRegisterInputs);s.returningRegisterOutputs+=r.outputs.size();s.ramReadFacts+=r.definiteRamReads.size()+r.possibleRamReads.size();s.ramWriteFacts+=r.definiteRamWrites.size()+r.possibleRamWrites.size();s.hardwareReadFacts+=r.definiteHardwareReads.size()+r.possibleHardwareReads.size();s.hardwareWriteFacts+=r.definiteHardwareWrites.size()+r.possibleHardwareWrites.size();s.callInputLinks+=r.callInputLinks.size();for(const auto&l:r.callInputLinks)if(l.survivesCall)++s.preservedCallLinks;}return s;}

} // namespace pacripper
