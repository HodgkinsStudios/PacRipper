// PacRipper contract-aware value flow contract-aware value flow + typed source lifting
// Created by Jacob Hodgkins

#include "Decompiler.h"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <functional>
#include <map>
#include <set>
#include <sstream>

namespace pacripper {
namespace {
std::string h16p12(std::uint16_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(4)<<std::setfill('0')<<(unsigned)v;return o.str();}
std::string sizeSetP12(const std::set<std::size_t>&s){std::ostringstream o;o<<"{";std::size_t n=0;for(auto v:s){if(n++)o<<",";o<<v;}o<<"}";return o.str();}
std::string pcSetP12(const std::set<std::uint16_t>&s){std::ostringstream o;o<<"{";std::size_t n=0;for(auto v:s){if(n++)o<<",";o<<"$"<<h16p12(v);}o<<"}";return o.str();}
std::string roleSetP12(const std::set<TypeRoleKind>&s){std::ostringstream o;o<<"{";std::size_t n=0;for(auto v:s){if(n++)o<<",";o<<TypeEvidence::roleText(v);}o<<"}";return o.str();}
std::string deviceSetP12(const std::set<BoardDeviceKind>&s){std::ostringstream o;o<<"{";std::size_t n=0;for(auto v:s){if(n++)o<<",";o<<HardwareSemantics::deviceText(v);}o<<"}";return o.str();}
bool isHexP12(char c){return std::isxdigit(static_cast<unsigned char>(c))!=0;}
bool linePCP12(const std::string&line,std::uint16_t&pc){auto p=line.rfind("$",line.size());if(p==std::string::npos||p+5>line.size())return false;for(std::size_t i=1;i<=4;++i)if(!isHexP12(line[p+i]))return false;unsigned v=0;for(std::size_t i=1;i<=4;++i){char c=line[p+i];unsigned d=c>='0'&&c<='9'?static_cast<unsigned>(c-'0'):c>='A'&&c<='F'?static_cast<unsigned>(10+c-'A'):static_cast<unsigned>(10+c-'a');v=(v<<4)|d;}pc=static_cast<std::uint16_t>(v);return true;}
std::string indentP12(const std::string&line){std::size_t n=0;while(n<line.size()&&std::isspace(static_cast<unsigned char>(line[n])))++n;return line.substr(0,n);}
bool ordinaryLiftDestination(BoardDeviceKind d){return d==BoardDeviceKind::WorkRam||d==BoardDeviceKind::VideoRam||d==BoardDeviceKind::ColorRam||d==BoardDeviceKind::SpriteRam||d==BoardDeviceKind::SpriteCoordinate||d==BoardDeviceKind::None;}
std::string destinationP12(const MemoryXrefRecord&x){std::ostringstream o;switch(x.device){case BoardDeviceKind::VideoRam:o<<"video_ram";break;case BoardDeviceKind::ColorRam:o<<"color_ram";break;case BoardDeviceKind::SpriteRam:o<<"sprite_ram";break;case BoardDeviceKind::SpriteCoordinate:o<<"sprite_coord";break;default:o<<"RAM";break;}o<<"[$"<<h16p12(x.start)<<"]";return o.str();}
const TableFieldEvidence* fieldAtP12(const TableSchemaRecord&s,std::size_t off){for(const auto&f:s.fields)if(f.offset==off)return &f;return nullptr;}
}

void Decompiler::buildContractValue(){
    machineValues_.clear();mergeValues_.clear();callBindings_.clear();typedValues_.clear();indexedExpressions_.clear();liftedStatements_.clear();routineBehaviors_.clear();stats_.contractValue={};if(!analyzer_)return;
    machineValues_=ValueFlow::buildMachineValues(defUseResult_);
    mergeValues_=ValueFlow::buildMergeValues(defUseResult_);
    callBindings_=ValueFlow::buildCallBindings(callSites_,routineContracts_,functionRegisterSummaries_,defUseResult_,machineValues_);
    stats_.contractValue.valueFlow=ValueFlow::stats(machineValues_,mergeValues_,callBindings_);

    std::map<std::size_t,const ExpressionRecord*> exprById;for(const auto&e:defUseResult_.expressions)exprById[e.definitionId]=&e;
    std::vector<PointerBoundEvidence> pointerBounds;
    for(const auto&e:defUseResult_.expressions){if(!e.exact||!e.memoryAddressKnown)continue;bool ptrSeed=false;for(const auto&t:typeEvidence_)if(t.staticProof&&!t.dynamicOnly&&t.role==TypeRoleKind::Pointer16&&((t.targetKind==TypeTargetKind::RomObject&&e.romObjectIds.count(t.romObjectId))||(t.targetKind==TypeTargetKind::RamRange&&e.memoryAddress>=t.start&&e.memoryAddress<t.end))){ptrSeed=true;break;}if(!ptrSeed)continue;for(const auto&l:romPointerLinks_)if(l.entryAddress==e.memoryAddress&&l.pointeeExtentProven){PointerBoundEvidence b;b.definitionId=e.definitionId;b.baseValueKnown=true;b.baseValue=l.target;b.start=l.pointeeStart;b.end=l.pointeeEnd;pointerBounds.push_back(b);break;}}
    typedValues_=TypedLifting::propagateTypes(defUseResult_,typeEvidence_,hardwareAccesses_,pointerBounds);

    std::map<std::size_t,const HardwareAccessRecord*> hwById;for(const auto&h:hardwareAccesses_)hwById[h.id]=&h;
    std::size_t indexedId=0;
    for(const auto&x:memoryXrefs_){if(!x.staticProof||x.addressResolution!=AddressResolutionKind::ExactStatic||x.end<=x.start)continue;std::size_t width=1;auto hi=hwById.find(x.hardwareAccessId);if(hi!=hwById.end())width=std::max<std::size_t>(1,hi->second->width);for(const auto&s:tableSchemas_){if(!s.staticProof||s.stride==0||s.elementCount==0||x.start<s.start||x.start>=s.end)continue;const std::size_t off=static_cast<std::size_t>(x.start-s.start),index=off/s.stride,field=off%s.stride;const auto*f=fieldAtP12(s,field);if(!f||width>f->width)continue;IndexedExpressionInput in;in.pc=x.pc;in.schemaId=s.id;in.schemaStart=s.start;in.schemaEnd=s.end;in.stride=s.stride;in.elementCount=s.elementCount;in.fieldOffset=field;in.fieldWidth=width;in.staticProof=true;in.finiteBounds=s.end>s.start&&s.elementCount>0;in.indexExact=true;in.indexMinKnown=true;in.indexMaxKnown=true;in.indexMin=index;in.indexMax=index;in.indexExpression=std::to_string(index);in.indexDefinitionIds=x.addressDefinitionIds;in.provenancePCs.insert(x.pc);IndexedExpressionRecord r;if(TypedLifting::buildIndexedExpression(in,r)){r.id=indexedId++;indexedExpressions_.push_back(r);}break;}}

    std::map<std::size_t,const DefinitionRecord*> defById;for(const auto&d:defUseResult_.definitions)defById[d.id]=&d;
    std::map<std::size_t,std::size_t> useCount;for(const auto&u:defUseResult_.uses)for(auto id:u.reaching.definitionIds)++useCount[id];
    std::map<std::uint16_t,const HardwareAccessRecord*> staticHwAt;for(const auto&h:hardwareAccesses_)if(h.staticProof)staticHwAt[h.pc]=&h;
    std::map<std::uint16_t,const IndexedExpressionRecord*> indexedAt;for(const auto&i:indexedExpressions_)indexedAt[i.pc]=&i;
    std::set<std::uint16_t> liftedSinks;std::size_t liftId=0;
    for(const auto&x:memoryXrefs_){if(liftedSinks.count(x.pc)||!x.staticProof||x.access==MemoryAccessKind::Read||x.access==MemoryAccessKind::Unknown||x.addressResolution!=AddressResolutionKind::ExactStatic||x.valueDefinitionIds.size()!=1||!ordinaryLiftDestination(x.device))continue;auto hh=staticHwAt.find(x.pc);if(hh!=staticHwAt.end()&&(hh->second->volatileAccess||hh->second->sideEffecting))continue;const std::size_t sinkDef=*x.valueDefinitionIds.begin();auto ei=exprById.find(sinkDef);if(ei==exprById.end()||!ei->second->exact)continue;
        StatementLiftInput in;in.sinkPC=x.pc;in.staticProof=true;in.expressionExact=true;in.expression=ei->second->text;auto ix=indexedAt.find(x.pc);in.destination=ix==indexedAt.end()?destinationP12(x):ix->second->text;auto bi=instructionToBlock_.find(x.pc);if(bi==instructionToBlock_.end())continue;const auto blockStart=bi->second;auto bb=blocks_.find(blockStart);if(bb==blocks_.end()||bb->second.functionOwners.size()!=1)continue;in.functionEntry=*bb->second.functionOwners.begin();
        std::set<std::size_t> visiting;bool chainOk=true,hasMemoryRead=false;std::function<void(std::size_t)> collect=[&](std::size_t id){if(!chainOk||visiting.count(id))return;auto di=defById.find(id);if(di==defById.end()){chainOk=false;return;}const auto&d=*di->second;if(!d.semanticExact||d.callBoundaryClobber||d.aliasInvalidation){chainOk=false;return;}auto pb=instructionToBlock_.find(d.instructionAddress);if(pb==instructionToBlock_.end()||pb->second!=blockStart){chainOk=false;return;}if(useCount[id]!=1){chainOk=false;return;}visiting.insert(id);in.consumedDefinitionIds.insert(id);in.consumedPCs.insert(d.instructionAddress);if(d.operation==DefExpressionKind::DirectMemoryRead||d.operation==DefExpressionKind::IndirectMemoryRead)hasMemoryRead=true;for(auto sid:d.sourceDefinitionIds)collect(sid);};collect(sinkDef);in.consumedPCs.insert(x.pc);if(!chainOk||!hasMemoryRead)continue;in.singleConsumerChain=true;
        std::uint16_t lo=*in.consumedPCs.begin(),hi=*in.consumedPCs.rbegin();for(auto pc:bb->second.instructions)if(pc>=lo&&pc<=hi){auto h=staticHwAt.find(pc);if(h!=staticHwAt.end()&&(h->second->volatileAccess||h->second->sideEffecting)){in.crossesVolatileOrSideEffect=true;break;}auto ii=analyzer_->instructions().find(pc);if(ii!=analyzer_->instructions().end()&&(ii->second.flow==FlowKind::Call||ii->second.flow==FlowKind::Restart)){in.crossesUnknownCall=true;break;}}
        for(auto did:in.consumedDefinitionIds){auto di=defById.find(did);if(di==defById.end())continue;for(const auto&rp:di->second->reachingOperands)if(rp.second.ambiguous()){in.crossesAmbiguousMerge=true;break;}if(in.crossesAmbiguousMerge)break;}
        for(const auto&ce:conditionEvidence_)if(ce.second.producerAddress>=0&&in.consumedPCs.count(static_cast<std::uint16_t>(ce.second.producerAddress)))in.flagProducerPCs.insert(static_cast<std::uint16_t>(ce.second.producerAddress));
        for(auto pc:in.consumedPCs){auto ii=analyzer_->instructions().find(pc);if(ii!=analyzer_->instructions().end())in.rawFallback.push_back("$"+h16p12(pc)+" "+ii->second.text());}
        if(!TypedLifting::canLiftStatement(in))continue;
        liftedStatements_.push_back(TypedLifting::makeLiftedStatement(liftId++,in));liftedSinks.insert(x.pc);
    }
    stats_.contractValue.lifting=TypedLifting::stats(typedValues_,indexedExpressions_,liftedStatements_);
    routineBehaviors_=RoutineBehavior::build(routineContracts_,tableSchemas_);stats_.contractValue.behavior=RoutineBehavior::stats(routineBehaviors_);
    stats_.contractValue.newlyExplainedBytes=0;stats_.contractValue.unresolvedAfterContractValue=stats_.typeContract.unresolvedAfterTypeContract;
}

std::vector<std::string> Decompiler::valueFlowLines() const{
    std::vector<std::string>o;if(!ready_){o.push_back("Decompiler model not built.");return o;}o.push_back("PacRipper contract-aware value flow stable machine-value flow");o.push_back("Synthetic mv_d IDs identify proven machine definitions; they are not recovered original source locals.");{std::ostringstream s;s<<"machine-values="<<stats_.contractValue.valueFlow.machineValues<<" exact="<<stats_.contractValue.valueFlow.exactMachineValues<<" copy-aliases="<<stats_.contractValue.valueFlow.copyAliases<<" merge/phi sets="<<stats_.contractValue.valueFlow.mergeValues;o.push_back(s.str());}o.push_back("");for(const auto&v:machineValues_){std::ostringstream s;s<<v.localName<<" @ $"<<h16p12(v.definitionPC)<<" "<<v.entity<<":"<<v.bits<<" origin="<<v.originName;if(v.copyAlias)s<<" [same-value copy]";s<<" expr="<<v.expression<<" provenance="<<pcSetP12(v.provenancePCs);o.push_back(s.str());}o.push_back("");o.push_back("Explicit merge alternatives:");for(const auto&m:mergeValues_){std::ostringstream s;s<<"$"<<h16p12(m.pc)<<" "<<m.entity<<" = "<<m.phiText;o.push_back(s.str());}return o;
}

std::vector<std::string> Decompiler::callBindingLines() const{
    std::vector<std::string>o;if(!ready_){o.push_back("Decompiler model not built.");return o;}o.push_back("PacRipper contract-aware value flow contract-aware direct-call bindings");o.push_back("Bindings are machine-register facts only; no compiler ABI or source signature is inferred.");{std::ostringstream s;s<<"bindings="<<stats_.contractValue.valueFlow.callBindings<<" inputs definite/possible="<<stats_.contractValue.valueFlow.definiteCallBindings<<"/"<<stats_.contractValue.valueFlow.possibleCallBindings<<" outputs="<<stats_.contractValue.valueFlow.outputBindings<<" preserved/returned post-call="<<stats_.contractValue.valueFlow.preservedPostCallValues<<"/"<<stats_.contractValue.valueFlow.returnedPostCallValues;o.push_back(s.str());}o.push_back("");for(const auto&b:callBindings_){std::ostringstream s;s<<"$"<<h16p12(b.callPC)<<" $"<<h16p12(b.callerFunction)<<" -> $"<<h16p12(b.calleeFunction)<<" "<<b.reg;if(b.hasInputBinding)s<<":"<<RoutineContracts::certaintyText(b.inputCertainty)<<" defs="<<sizeSetP12(b.definitionIds);else s<<":output-only";if(b.includesEntryValue)s<<" +entry";if(b.includesClobberedUnknown)s<<" +unknown";s<<" post="<<ValueFlow::postValueKindText(b.postValueKind);if(!b.postValueName.empty())s<<":"<<b.postValueName;if(!b.roles.empty()){s<<" roles={";std::size_t n=0;for(const auto&r:b.roles){if(n++)s<<",";s<<r;}s<<"}";}o.push_back(s.str());for(const auto&e:b.expressions)o.push_back("  input-expr: "+e);}return o;
}

std::vector<std::string> Decompiler::typedPseudocodeLines() const{
    if(!ready_)return {"Decompiler model not built."};
    std::vector<std::string>base=structuredPseudocodeLines(),out;out.push_back("// PacRipper contract-aware value flow typed structured pseudocode");out.push_back("// contract-aware value flow lifts are additive evidence annotations; raw the earlier semantic analyses statements remain visible below them.");out.push_back("");std::map<std::uint16_t,std::vector<std::string>> comments;
    for(const auto&v:typedValues_){std::ostringstream s;s<<"contract-aware value flow typed "<<"mv_d"<<v.definitionId<<" "<<roleSetP12(v.roles);if(!v.devices.empty())s<<" devices="<<deviceSetP12(v.devices);if(v.pointerOffsetBounded)s<<" bounded-pointer-offset";s<<" := "<<v.expression<<" provenance="<<pcSetP12(v.provenancePCs);comments[v.pc].push_back(s.str());}
    for(const auto&i:indexedExpressions_){std::ostringstream s;s<<"contract-aware value flow indexed: "<<i.text<<" bounds=["<<i.indexMin<<","<<i.indexMax<<"]/"<<i.elementCount<<" stride="<<i.stride<<" provenance="<<pcSetP12(i.provenancePCs);comments[i.pc].push_back(s.str());}
    for(const auto&b:callBindings_){std::ostringstream s;s<<"contract-aware value flow call-bind $"<<h16p12(b.calleeFunction)<<" "<<(b.hasInputBinding?"input ":"output ")<<b.reg;if(b.hasInputBinding)s<<" <- ";else s<<" -> ";if(b.hasInputBinding){if(b.valueNames.empty())s<<"unresolved";else for(std::size_t n=0;n<b.valueNames.size();++n){if(n)s<<" | ";s<<b.valueNames[n];}}else s<<b.postValueName;s<<"; post="<<ValueFlow::postValueKindText(b.postValueKind);comments[b.callPC].push_back(s.str());}
    for(const auto&l:liftedStatements_){std::ostringstream s;s<<"contract-aware value flow lifted: "<<l.text<<" proving-pcs="<<pcSetP12(l.consumedPCs);if(!l.flagProducerPCs.empty())s<<" flags-retained-from="<<pcSetP12(l.flagProducerPCs);comments[l.sinkPC].push_back(s.str());}
    for(const auto&line:base){std::uint16_t pc=0;if(linePCP12(line,pc)){auto ci=comments.find(pc);if(ci!=comments.end()){const std::string ind=indentP12(line);for(const auto&c:ci->second)out.push_back(ind+"// "+c);}}out.push_back(line);}return out;
}

std::vector<std::string> Decompiler::routineBehaviorLines() const{
    std::vector<std::string>o;if(!ready_){o.push_back("Decompiler model not built.");return o;}o.push_back("PacRipper contract-aware value flow neutral routine behavior summaries");o.push_back("Summaries describe proven machine-visible behavior and synthetic schema IDs, not inferred gameplay names.");{std::ostringstream s;s<<"routines="<<stats_.contractValue.behavior.routines<<" schema-aware="<<stats_.contractValue.behavior.schemaAwareRoutines<<" hardware-aware="<<stats_.contractValue.behavior.hardwareAwareRoutines;o.push_back(s.str());}o.push_back("");for(const auto&r:routineBehaviors_){std::ostringstream s;s<<"function $"<<h16p12(r.functionEntry)<<" inputs={";std::size_t n=0;for(const auto&f:r.machineInputs){if(n++)s<<",";s<<f.reg<<":"<<RoutineContracts::certaintyText(f.certainty);}s<<"} outputs={";n=0;for(const auto&f:r.machineOutputs){if(n++)s<<",";s<<f.reg<<":"<<RoutineContracts::certaintyText(f.certainty);}s<<"}";o.push_back(s.str());std::ostringstream q;q<<"  RAM definite R/W="<<r.definiteRamReads.size()<<"/"<<r.definiteRamWrites.size()<<" possible R/W="<<r.possibleRamReads.size()<<"/"<<r.possibleRamWrites.size()<<" schemas R/W="<<sizeSetP12(r.readSchemaIds)<<"/"<<sizeSetP12(r.writeSchemaIds);o.push_back(q.str());std::ostringstream h;h<<"  hardware definite R/W="<<deviceSetP12(r.definiteHardwareReads)<<"/"<<deviceSetP12(r.definiteHardwareWrites)<<" possible R/W="<<deviceSetP12(r.possibleHardwareReads)<<"/"<<deviceSetP12(r.possibleHardwareWrites)<<" calls="<<r.directCallees.size();if(r.unknownCallEffects)h<<" unknown-call-effects";if(r.unknownMemoryWrite)h<<" unknown-memory-write";if(r.nonReturningOrUnknownExit)h<<" nonreturn/unknown-exit";o.push_back(h.str());}return o;
}

} // namespace pacripper
