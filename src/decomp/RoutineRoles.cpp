// PacRipper structured-expression analysis neutral routine role signatures, clustering and navigation
// Created by Jacob Hodgkins

#include "RoutineRoles.h"

#include <algorithm>
#include <map>
#include <sstream>

namespace pacripper {
namespace {
std::string join(const std::set<std::string>&s){std::ostringstream o;std::size_t n=0;for(const auto&v:s){if(n++)o<<"|";o<<v;}return o.str();}
void addRegs(std::set<std::string>&f,const std::set<std::string>&r,const std::string&p){for(const auto&x:r)f.insert(p+x);}
void addIds(std::set<std::string>&f,const std::set<std::size_t>&r,const std::string&p){for(auto x:r)f.insert(p+std::to_string(x));}
void addAddrs(std::set<std::string>&f,const std::set<std::uint16_t>&r,const std::string&p){for(auto x:r){std::ostringstream o;o<<p<<std::hex<<std::uppercase<<x;f.insert(o.str());}}
void addDevices(std::set<std::string>&f,const std::set<BoardDeviceKind>&r,const std::string&p){for(auto x:r)f.insert(p+HardwareSemantics::deviceText(x));}
bool subset(const std::set<std::string>&a,const std::set<std::string>&b){return std::includes(b.begin(),b.end(),a.begin(),a.end());}
std::set<std::string> intersection(const std::set<std::string>&a,const std::set<std::string>&b){std::set<std::string>o;std::set_intersection(a.begin(),a.end(),b.begin(),b.end(),std::inserter(o,o.end()));return o;}
std::set<std::string> difference(const std::set<std::string>&a,const std::set<std::string>&b){std::set<std::string>o;std::set_difference(a.begin(),a.end(),b.begin(),b.end(),std::inserter(o,o.end()));return o;}
}

RoutineRoleSignatureRecord RoutineRoles::makeSignature(std::size_t id,const RoutineRoleInput&i){
    RoutineRoleSignatureRecord r;static_cast<RoutineRoleInput&>(r)=i;r.id=id;auto&f=r.staticFacts;
    addRegs(f,i.definiteInputs,"in:def:");addRegs(f,i.possibleInputs,"in:poss:");addRegs(f,i.definiteOutputs,"out:def:");
    addAddrs(f,i.definiteRamReads,"ram_r:def:");addAddrs(f,i.possibleRamReads,"ram_r:poss:");addAddrs(f,i.definiteRamWrites,"ram_w:def:");addAddrs(f,i.possibleRamWrites,"ram_w:poss:");
    addIds(f,i.readSchemaIds,"schema_r:");addIds(f,i.writeSchemaIds,"schema_w:");
    addDevices(f,i.definiteHardwareReads,"hw_r:def:");addDevices(f,i.possibleHardwareReads,"hw_r:poss:");addDevices(f,i.definiteHardwareWrites,"hw_w:def:");addDevices(f,i.possibleHardwareWrites,"hw_w:poss:");
    addAddrs(f,i.directCallees,"callee:");
    f.insert("loops:"+std::to_string(i.loopCount));f.insert("if:"+std::to_string(i.ifCount));f.insert("ifelse:"+std::to_string(i.ifElseCount));f.insert("while:"+std::to_string(i.whileCount));f.insert("dowhile:"+std::to_string(i.doWhileCount));
    f.insert("call_in_def:"+std::to_string(i.definiteCallInputs));f.insert("call_in_poss:"+std::to_string(i.possibleCallInputs));f.insert("call_preserved:"+std::to_string(i.preservedCallValues));f.insert("call_returned:"+std::to_string(i.returnedCallValues));
    addDevices(r.dynamicOnlyFacts,i.dynamicOnlyHardwareReads,"dynamic_hw_r:");addDevices(r.dynamicOnlyFacts,i.dynamicOnlyHardwareWrites,"dynamic_hw_w:");
    r.canonicalSignature=join(f);
    std::set<std::string>labels;
    for(auto d:i.definiteHardwareReads){if(d==BoardDeviceKind::InputIN0||d==BoardDeviceKind::InputIN1||d==BoardDeviceKind::InputDSW1||d==BoardDeviceKind::InputDSW2)labels.insert("input_reader");else labels.insert("hardware_reader");}
    for(auto d:i.definiteHardwareWrites){if(d==BoardDeviceKind::VideoRam||d==BoardDeviceKind::ColorRam||d==BoardDeviceKind::SpriteRam||d==BoardDeviceKind::SpriteCoordinate)labels.insert("video_writer");else if(d==BoardDeviceKind::NamcoWSG)labels.insert("audio_writer");else if(d==BoardDeviceKind::Watchdog)labels.insert("watchdog_writer");else labels.insert("hardware_writer");}
    if(!i.definiteRamReads.empty()) labels.insert("ram_reader");
    if(!i.definiteRamWrites.empty()) labels.insert("ram_writer");
    if(!i.readSchemaIds.empty()) labels.insert("schema_reader");
    if(!i.writeSchemaIds.empty()) labels.insert("schema_writer");
    if(i.loopCount) labels.insert("looping");
    if(!i.directCallees.empty()) labels.insert("caller");
    if(labels.empty()) labels.insert("machine_routine");
    std::ostringstream l;l<<"role_";std::size_t n=0;for(const auto&x:labels){if(n++)l<<"+";l<<x;}r.neutralLabel=l.str();return r;
}

RoutineSimilarityRecord RoutineRoles::compare(const RoutineRoleSignatureRecord&a,const RoutineRoleSignatureRecord&b){RoutineSimilarityRecord r;r.first=a.functionEntry;r.second=b.functionEntry;r.sharedFacts=intersection(a.staticFacts,b.staticFacts);r.firstOnlyFacts=difference(a.staticFacts,b.staticFacts);r.secondOnlyFacts=difference(b.staticFacts,a.staticFacts);if(a.canonicalSignature==b.canonicalSignature)r.kind=RoutineSimilarityKind::ExactSignature;else if(subset(a.staticFacts,b.staticFacts)||subset(b.staticFacts,a.staticFacts))r.kind=RoutineSimilarityKind::CompatibleAdditionalEffects;else r.kind=RoutineSimilarityKind::MateriallyDifferent;return r;}

std::vector<RoutineClusterRecord> RoutineRoles::exactClusters(const std::vector<RoutineRoleSignatureRecord>&records){std::map<std::string,std::vector<const RoutineRoleSignatureRecord*>>groups;for(const auto&r:records)groups[r.canonicalSignature].push_back(&r);std::vector<RoutineClusterRecord>out;for(const auto&g:groups){if(g.second.size()<2)continue;RoutineClusterRecord c;c.id=out.size();c.kind=RoutineSimilarityKind::ExactSignature;c.sharedFacts=g.second.front()->staticFacts;for(const auto*r:g.second)c.members.push_back(r->functionEntry);out.push_back(c);}return out;}
std::string RoutineRoles::similarityText(RoutineSimilarityKind k){switch(k){case RoutineSimilarityKind::ExactSignature:return"exact-signature";case RoutineSimilarityKind::CompatibleAdditionalEffects:return"compatible-additional-effects";case RoutineSimilarityKind::MateriallyDifferent:return"materially-different";}return"unknown";}
RoutineRoleStats RoutineRoles::stats(const std::vector<RoutineRoleSignatureRecord>&sigs,const std::vector<RoutineSimilarityRecord>&sim,const std::vector<RoutineClusterRecord>&clusters,const std::vector<RoutineNavigationRecord>&nav){RoutineRoleStats s;s.signatures=sigs.size();s.exactClusters=clusters.size();s.navigationRecords=nav.size();for(const auto&r:sigs){if(r.dynamicCorroborated)++s.dynamicallyCorroborated;if(!r.dynamicOnlyFacts.empty())++s.signaturesWithDynamicOnlyEffects;}for(const auto&c:clusters)s.exactClusteredRoutines+=c.members.size();for(const auto&r:sim){if(r.kind==RoutineSimilarityKind::CompatibleAdditionalEffects)++s.compatiblePairs;else if(r.kind==RoutineSimilarityKind::MateriallyDifferent)++s.materiallyDifferentPairs;}return s;}

} // namespace pacripper
