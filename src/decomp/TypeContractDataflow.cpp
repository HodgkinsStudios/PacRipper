// PacRipper type/contract analysis type/schema/routine-contract integration
// Created by Jacob Hodgkins

#include "Decompiler.h"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>

namespace pacripper {
namespace {

std::string h16p11(std::uint16_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(4)<<std::setfill('0')<<(unsigned)v;return o.str();}
bool isReadP11(MemoryAccessKind a){return a==MemoryAccessKind::Read||a==MemoryAccessKind::ReadWrite;}
bool isWriteP11(MemoryAccessKind a){return a==MemoryAccessKind::Write||a==MemoryAccessKind::ReadWrite;}
bool isRamAddressP11(std::uint16_t a){return (a>=0x4000&&a<0x4800)||(a>=0x4C00&&a<0x5000);}
bool isSemanticDeviceP11(BoardDeviceKind d){return d!=BoardDeviceKind::None&&d!=BoardDeviceKind::MixedOrUnknown&&d!=BoardDeviceKind::OpenBus&&d!=BoardDeviceKind::WorkRam;}

bool parseRamEntityP11(const std::string& e,std::uint16_t& address,unsigned& bits){
    bits=0;std::size_t p=std::string::npos;
    if(e.rfind("RAM8:$",0)==0){bits=8;p=6;}
    else if(e.rfind("RAM16:$",0)==0){bits=16;p=7;}
    else return false;
    if(p+4>e.size()) return false;
    unsigned v=0;
    for(std::size_t i=0;i<4;++i){
        const char c=e[p+i];
        unsigned d=0;
        if(c>='0'&&c<='9') d=static_cast<unsigned>(c-'0');
        else if(c>='A'&&c<='F') d=static_cast<unsigned>(10+c-'A');
        else if(c>='a'&&c<='f') d=static_cast<unsigned>(10+c-'a');
        else return false;
        v=(v<<4)|d;
    }
    address=static_cast<std::uint16_t>(v);
    return true;
}

bool parseBitNumberP11(const Instruction& in,unsigned& bit){
    if(in.mnemonic!="BIT"&&in.mnemonic!="RES"&&in.mnemonic!="SET")return false;
    std::size_t comma=in.operands.find(',');std::string s=comma==std::string::npos?in.operands:in.operands.substr(0,comma);while(!s.empty()&&std::isspace(static_cast<unsigned char>(s.front())))s.erase(s.begin());
    if(s.size()!=1||s[0]<'0'||s[0]>'7') return false;
    bit=static_cast<unsigned>(s[0]-'0');
    return true;
}

struct SourceTargetP11 {TypeTargetKind kind=TypeTargetKind::RamRange;std::uint16_t start=0,end=0;std::size_t objectId=0;unsigned bits=0;};

bool factDominatesAllExitsP11(const std::map<std::uint16_t,StructureAnalysis>& structures,std::uint16_t fn,std::uint16_t block){
    auto si=structures.find(fn);if(si==structures.end()||si->second.graph.exits.empty())return false;
    for(auto ex:si->second.graph.exits)if(!StructuredControl::dominates(si->second.dominators,block,ex))return false;
    return true;
}

RegisterContractFact* findRegFactP11(std::vector<RegisterContractFact>& facts,const std::string& reg){for(auto&f:facts)if(f.reg==reg)return &f;return nullptr;}

} // namespace

void Decompiler::buildTypeContract(){
    typeEvidence_.clear();tableSchemas_.clear();routineContracts_.clear();stats_.typeContract={};if(!analyzer_)return;
    std::vector<TypeEvidenceInput> typeInputs;

    // def-use analysis RAM objects prove machine width; pointer-like words retain that independent role.
    for(const auto&r:ramObjects_){
        TypeEvidenceInput x;x.targetKind=TypeTargetKind::RamRange;x.start=r.start;x.end=r.end;x.staticProof=r.staticProof;x.dynamicOnly=r.dynamicOnly;x.exact=true;x.sourcePCs=r.sourcePCs;x.bits=static_cast<unsigned>(r.elementSize*8);
        x.role=r.kind==RamObjectKind::WordField?TypeRoleKind::LittleEndianWord:TypeRoleKind::ByteWidth;x.note="def-use analysis RAM object machine access width";typeInputs.push_back(x);
        if(r.pointerLike){auto p=x;p.role=TypeRoleKind::Pointer16;p.bits=16;p.note="ROM closure and def-use analysis direct word load followed by dereference proves pointer-valued use";typeInputs.push_back(p);}
    }

    // object/pointer dataflow ROM object structure proves lookup/pointer-table element width without naming contents.
    for(const auto&o:romObjects_){if(o.dynamicOnly)continue;
        if(o.entrySize==1){TypeEvidenceInput x;x.targetKind=TypeTargetKind::RomObject;x.romObjectId=o.id;x.start=o.start;x.end=o.end;x.role=TypeRoleKind::ByteWidth;x.bits=8;x.staticProof=true;x.exact=o.exactBoundary;x.sourcePCs=o.consumerPCs;x.note="consumer-backed ROM object has one-byte elements";typeInputs.push_back(x);}
        if(o.entrySize==2){TypeEvidenceInput x;x.targetKind=TypeTargetKind::RomObject;x.romObjectId=o.id;x.start=o.start;x.end=o.end;x.role=TypeRoleKind::LittleEndianWord;x.bits=16;x.staticProof=true;x.exact=o.exactBoundary;x.sourcePCs=o.consumerPCs;x.note="consumer-backed ROM object has two-byte little-endian elements";typeInputs.push_back(x);if(o.kind==RomObjectKind::WordPointerTable){auto p=x;p.role=TypeRoleKind::Pointer16;p.note="decoded little-endian entries are consumed as ROM addresses";typeInputs.push_back(p);}}
    }

    // Board xrefs prove hardware-value roles; dynamic-only records remain dynamic-only.
    for(const auto&h:hardwareAccesses_){if(!isSemanticDeviceP11(h.device))continue;TypeEvidenceInput x;x.targetKind=TypeTargetKind::RamRange;x.start=h.start;x.end=h.end;x.role=TypeRoleKind::HardwareValue;x.bits=h.width*8;x.staticProof=h.staticProof;x.dynamicOnly=!h.staticProof&&h.dynamicObserved;x.exact=h.addressResolution==AddressResolutionKind::ExactStatic||h.addressResolution==AddressResolutionKind::DynamicObserved;x.device=h.device;x.sourcePCs=h.provenancePCs;x.sourcePCs.insert(h.pc);x.note="hardware-semantics analysis access proves transfer to/from "+HardwareSemantics::deviceText(h.device);typeInputs.push_back(x);}

    std::map<std::size_t,ExpressionRecord> exprById;
    for(const auto&e:defUseResult_.expressions) exprById[e.definitionId]=e;
    std::map<std::size_t,const DefinitionRecord*> definitionById;
    for(const auto&d:defUseResult_.definitions) definitionById[d.id]=&d;
    std::map<std::size_t,std::vector<SourceTargetP11>> sourcesByDef;
    for(const auto&d:defUseResult_.definitions){
        std::vector<SourceTargetP11> src;
        if(d.operation==DefExpressionKind::DirectMemoryRead){for(const auto&op:d.operands){if(op.constant)continue;std::uint16_t a=0;unsigned bits=0;if(parseRamEntityP11(op.entity,a,bits)){SourceTargetP11 q;q.start=a;q.end=static_cast<std::uint16_t>(a+(bits==16?2:1));q.bits=bits;src.push_back(q);}}}
        auto ei=exprById.find(d.id);if(ei!=exprById.end()&&ei->second.exact){const auto&e=ei->second;if(e.memoryAddressKnown&&isRamAddressP11(e.memoryAddress)){SourceTargetP11 q;q.start=e.memoryAddress;q.end=static_cast<std::uint16_t>(e.memoryAddress+(e.bits==16?2:1));q.bits=e.bits;src.push_back(q);}for(auto oid:e.romObjectIds){if(oid>=romObjects_.size())continue;SourceTargetP11 q;q.kind=TypeTargetKind::RomObject;q.objectId=oid;q.start=romObjects_[oid].start;q.end=romObjects_[oid].end;q.bits=e.bits;src.push_back(q);}}
        if(!src.empty())sourcesByDef[d.id]=src;
    }
    auto addRoleForUse=[&](const UseRecord&u,TypeRoleKind role,std::uint16_t pc,bool maskKnown=false,std::uint16_t mask=0,BoardDeviceKind device=BoardDeviceKind::None,const std::string&note=std::string(),bool rangeMinKnown=false,std::uint16_t rangeMin=0,bool rangeMaxKnown=false,std::uint16_t rangeMax=0,const std::string&pathCondition=std::string()){
        if(!u.staticProof) return;
        for(auto did:u.reaching.definitionIds){
            auto si=sourcesByDef.find(did);
            if(si==sourcesByDef.end()) continue;
            for(const auto&t:si->second){
                TypeEvidenceInput x;
                x.targetKind=t.kind;x.start=t.start;x.end=t.end;x.romObjectId=t.objectId;
                x.role=role;x.bits=t.bits?t.bits:8;x.staticProof=true;x.maskKnown=maskKnown;x.mask=mask;
                x.rangeMinKnown=rangeMinKnown;x.rangeMin=rangeMin;x.rangeMaxKnown=rangeMaxKnown;x.rangeMax=rangeMax;x.pathCondition=pathCondition;
                x.device=device;x.sourcePCs.insert(pc);x.note=note;
                if(role==TypeRoleKind::MaskedUse&&maskKnown){x.postMaskMaxKnown=true;x.postMaskMax=mask;}
                typeInputs.push_back(x);
            }
        }
    };

    std::map<std::uint16_t,std::vector<const UseRecord*>> usesAt;for(const auto&u:defUseResult_.uses)usesAt[u.instructionAddress].push_back(&u);
    for(const auto&kv:analyzer_->instructions()){
        const auto&in=kv.second;if(!analyzer_->hasStaticInstructionProof(in.address))continue;
        unsigned bit=0;if(parseBitNumberP11(in,bit)){auto it=usesAt.find(in.address);if(it!=usesAt.end())for(const auto*u:it->second)addRoleForUse(*u,TypeRoleKind::BitFieldUse,in.address,true,static_cast<std::uint16_t>(1u<<bit),BoardDeviceKind::None,"BIT/RES/SET establishes a bit-oriented use; it does not name the bit");
        }
        if(in.mnemonic=="AND"&&in.bytes.size()>=2&&in.bytes[0]==0xE6){auto it=usesAt.find(in.address);if(it!=usesAt.end())for(const auto*u:it->second)if(u->entity=="A")addRoleForUse(*u,TypeRoleKind::MaskedUse,in.address,true,in.bytes[1],BoardDeviceKind::None,"immediate AND proves a masked consumption; the stored source domain itself is not narrowed");}
    }
    for(const auto&cek:conditionEvidence_){const auto&ce=cek.second;if(ce.producerAddress<0)continue;auto ui=usesAt.find(static_cast<std::uint16_t>(ce.producerAddress));if(ui==usesAt.end())continue;
        if(ce.rawCondition=="M"||ce.rawCondition=="P")for(const auto*u:ui->second)addRoleForUse(*u,TypeRoleKind::Signed8Use,ce.branchAddress,false,0,BoardDeviceKind::None,"branch consumes the sign flag, proving a sign-bit-oriented 8-bit use");
        if(ce.rawCondition=="C"||ce.rawCondition=="NC"){
            auto ii=analyzer_->instructions().find(static_cast<std::uint16_t>(ce.producerAddress));
            if(ii!=analyzer_->instructions().end()&&ii->second.mnemonic=="CP"){
                for(const auto*u:ui->second) addRoleForUse(*u,TypeRoleKind::Unsigned8Use,ce.branchAddress,false,0,BoardDeviceKind::None,"CP carry/no-carry branch proves an unsigned ordering use");
                if(ii->second.bytes.size()>=2&&ii->second.bytes[0]==0xFE){
                    const std::uint16_t threshold=ii->second.bytes[1];
                    for(const auto*u:ui->second){
                        if(u->entity!="A") continue;
                        if(ce.rawCondition=="C"&&threshold>0) addRoleForUse(*u,TypeRoleKind::RangeCheckUse,ce.branchAddress,false,0,BoardDeviceKind::None,"taken carry edge proves only the path-local unsigned bound A < immediate; source storage is not globally narrowed",true,0,true,static_cast<std::uint16_t>(threshold-1),"C/taken");
                        else if(ce.rawCondition=="NC") addRoleForUse(*u,TypeRoleKind::RangeCheckUse,ce.branchAddress,false,0,BoardDeviceKind::None,"taken no-carry edge proves only the path-local unsigned bound A >= immediate; source storage is not globally narrowed",true,threshold,false,0,"NC/taken");
                    }
                }
            }
        }
    }
    typeEvidence_=TypeEvidence::reconstruct(typeInputs);stats_.typeContract.types=TypeEvidence::stats(typeEvidence_);

    // Proven element schemas. Lookup helpers prove stable field offset 0; block RAM shapes prove finite stride/bounds.
    std::vector<TableSchemaEvidence> schemaEvidence;
    for(const auto&o:romObjects_){if(o.dynamicOnly||o.entrySize==0||o.entryCount<2)continue;if(o.kind!=RomObjectKind::ByteLookupTable&&o.kind!=RomObjectKind::WordPointerTable)continue;TableSchemaEvidence e;e.targetKind=SchemaTargetKind::RomObject;e.targetId=o.id;e.start=o.start;e.end=o.end;e.stride=o.entrySize;e.elementCount=o.entryCount;e.exactBounds=o.exactBoundary;e.staticProof=true;e.sourcePCs=o.consumerPCs;e.note="object/pointer dataflow indexed lookup semantics prove repeated elements and stable offset 0";TableFieldEvidence f;f.offset=0;f.width=o.entrySize;f.repeatedAccessCount=o.entryCount;f.sourcePCs=o.consumerPCs;f.roles.insert(o.entrySize==2?TypeRoleKind::LittleEndianWord:TypeRoleKind::ByteWidth);if(o.kind==RomObjectKind::WordPointerTable)f.roles.insert(TypeRoleKind::Pointer16);f.note="stable lookup element field";e.fields.push_back(f);schemaEvidence.push_back(e);}
    for(const auto&r:ramShapes_){if(!r.staticProof||r.elementCount<2||r.stride==0)continue;TableSchemaEvidence e;e.targetKind=SchemaTargetKind::RamShape;e.targetId=r.id;e.start=r.start;e.end=r.end;e.stride=r.stride;e.elementCount=r.elementCount;e.exactBounds=true;e.staticProof=true;e.sourcePCs=r.sourcePCs;e.note="hardware-semantics analysis exact finite stride/bounds evidence proves repeated RAM elements";TableFieldEvidence f;f.offset=0;f.width=r.elementSize;f.repeatedAccessCount=r.elementCount;f.sourcePCs=r.sourcePCs;f.roles.insert(r.elementSize==2?TypeRoleKind::LittleEndianWord:TypeRoleKind::ByteWidth);f.note="repeated element payload at offset 0";e.fields.push_back(f);schemaEvidence.push_back(e);}
    tableSchemas_=TableSchemas::reconstruct(schemaEvidence);stats_.typeContract.schemas=TableSchemas::stats(tableSchemas_);

    // Build unique ownership indexes for machine contracts.
    std::map<std::uint16_t,std::uint16_t> uniqueOwner,pcBlock;
    for(const auto&bk:blocks_)for(auto pc:bk.second.instructions){pcBlock[pc]=bk.first;if(bk.second.functionOwners.size()==1)uniqueOwner[pc]=*bk.second.functionOwners.begin();}
    std::map<std::uint16_t,RoutineContractRecord> contracts;for(const auto&f:functions_){RoutineContractRecord r;r.functionEntry=f.first;r.directCallees=f.second.callees;auto si=functionRegisterSummaries_.find(f.first);if(si!=functionRegisterSummaries_.end()){r.preservedRegisters=si->second.preserved;r.clobberedRegisters=si->second.transitiveMayWrite;r.unknownCallEffects=si->second.hasUnknownCallEffects;r.unknownMemoryWrite=si->second.transitiveUnknownMemoryWrite;r.nonReturningOrUnknownExit=si->second.hasNonReturnExit;}contracts[f.first]=r;}

    for(const auto&u:defUseResult_.uses){auto oi=uniqueOwner.find(u.instructionAddress);if(oi==uniqueOwner.end()||!DefUseAnalysis::isTrackedRegister(u.entity))continue;RegisterContractFact f;f.reg=u.entity;f.certainty=u.reaching.exactEntryValue()?ContractCertainty::Definite:ContractCertainty::Possible;if(!u.reaching.includesEntryValue)continue;f.sourcePCs.insert(u.instructionAddress);contracts[oi->second].inputs.push_back(f);}

    // Return-state outputs: definite only when every static returning exit contains a produced, non-entry, non-clobbered value.
    for(auto&ck:contracts){const auto fn=ck.first;std::vector<std::uint16_t> returns;for(const auto&bk:blocks_)if(bk.second.functionOwners.size()==1&&*bk.second.functionOwners.begin()==fn)for(auto pc:bk.second.instructions){auto ii=analyzer_->instructions().find(pc);if(ii!=analyzer_->instructions().end()&&(ii->second.mnemonic=="RET"||ii->second.mnemonic=="RETI"||ii->second.mnemonic=="RETN"))returns.push_back(pc);}if(returns.empty()){ck.second.nonReturningOrUnknownExit=true;continue;}
        for(const auto&reg:DefUseAnalysis::trackedRegisters()){if(ck.second.preservedRegisters.count(reg))continue;std::size_t produced=0;RegisterContractFact f;f.reg=reg;for(auto pc:returns){auto st=defUseResult_.stateBeforeInstruction.find(pc);if(st==defUseResult_.stateBeforeInstruction.end())continue;auto ri=st->second.find(reg);if(ri==st->second.end())continue;const auto&fact=ri->second;
                bool semanticProduced=!fact.includesEntryValue&&!fact.includesClobberedUnknown&&!fact.definitionIds.empty();
                if(semanticProduced){for(auto id:fact.definitionIds){auto di=definitionById.find(id);if(di==definitionById.end()||!di->second->semanticExact||di->second->aliasInvalidation||di->second->callBoundaryClobber){semanticProduced=false;break;}}}
                if(semanticProduced){++produced;f.sourcePCs.insert(pc);}}
            if(produced){f.certainty=produced==returns.size()?ContractCertainty::Definite:ContractCertainty::Possible;ck.second.outputs.push_back(f);}
        }
    }

    for(const auto&x:memoryXrefs_){if(!x.staticProof)continue;for(auto fn:x.functionOwners){auto ci=contracts.find(fn);if(ci==contracts.end())continue;bool definite=false;auto pb=pcBlock.find(x.pc);if(pb!=pcBlock.end())definite=factDominatesAllExitsP11(structures_,fn,pb->second);
            for(std::uint32_t a=x.start;a<x.end&&a<0x10000u;++a)if(isRamAddressP11(static_cast<std::uint16_t>(a))){if(isReadP11(x.access))(definite?ci->second.definiteRamReads:ci->second.possibleRamReads).insert(static_cast<std::uint16_t>(a));if(isWriteP11(x.access))(definite?ci->second.definiteRamWrites:ci->second.possibleRamWrites).insert(static_cast<std::uint16_t>(a));}
            if(isSemanticDeviceP11(x.device)){if(isReadP11(x.access))(definite?ci->second.definiteHardwareReads:ci->second.possibleHardwareReads).insert(x.device);if(isWriteP11(x.access))(definite?ci->second.definiteHardwareWrites:ci->second.possibleHardwareWrites).insert(x.device);}
        }}

    // Attach direct hardware roles to entry-register inputs only when the instruction proves
    // that exact entry value is consumed as the address or write payload.
    for(const auto&h:hardwareAccesses_){
        if(!h.staticProof) continue;
        auto oi=uniqueOwner.find(h.pc);
        if(oi==uniqueOwner.end()) continue;
        auto&c=contracts[oi->second];
        auto st=defUseResult_.stateBeforeInstruction.find(h.pc);
        if(st==defUseResult_.stateBeforeInstruction.end()) continue;
        std::set<std::string> exactEntryUses;
        auto ui=usesAt.find(h.pc);
        if(ui!=usesAt.end()) for(const auto*u:ui->second) if(u->reaching.exactEntryValue()) exactEntryUses.insert(u->entity);
        for(auto&f:c.inputs){
            auto ri=st->second.find(f.reg);
            if(ri==st->second.end()||!ri->second.exactEntryValue()) continue;
            if(h.addressEntity==f.reg&&exactEntryUses.count(f.reg)) f.roles.insert("address-of:"+HardwareSemantics::deviceText(h.device));
            else if(isWriteP11(h.access)&&exactEntryUses.count(f.reg)&&h.addressEntity!=f.reg) f.roles.insert("write-value-to:"+HardwareSemantics::deviceText(h.device));
        }
    }
    for(auto&kv:contracts)RoutineContracts::normalize(kv.second);

    // Direct-call links and conservative cross-routine role propagation. A callee role is
    // propagated back to a caller entry register only when the callee is proven to preserve it.
    for(const auto&cs:callSites_){auto caller=contracts.find(cs.callerFunction),callee=contracts.find(cs.calleeFunction);if(caller==contracts.end()||callee==contracts.end())continue;auto st=defUseResult_.stateBeforeInstruction.find(cs.callAddress);if(st==defUseResult_.stateBeforeInstruction.end())continue;auto sm=functionRegisterSummaries_.find(cs.calleeFunction);const FunctionRegisterSummary* summary=sm==functionRegisterSummaries_.end()?nullptr:&sm->second;
        for(const auto&input:callee->second.inputs)if(input.certainty==ContractCertainty::Definite){auto ri=st->second.find(input.reg);if(ri==st->second.end())continue;CallInputLink l;l.callPC=cs.callAddress;l.callee=cs.calleeFunction;l.reg=input.reg;l.definitionIds=ri->second.definitionIds;l.callerEntryAlternative=ri->second.includesEntryValue;l.survivesCall=RoutineContracts::survivesDirectCall(input.reg,summary);caller->second.callInputLinks.push_back(l);
            if(l.survivesCall&&ri->second.exactEntryValue()){auto*f=findRegFactP11(caller->second.inputs,input.reg);if(f){for(const auto&role:input.roles)f->roles.insert("via-$"+h16p11(cs.calleeFunction)+":"+role);}}
        }
    }
    for(auto&kv:contracts){RoutineContracts::normalize(kv.second);routineContracts_.push_back(kv.second);}stats_.typeContract.contracts=RoutineContracts::stats(routineContracts_);
    stats_.typeContract.newlyExplainedBytes=0;stats_.typeContract.unresolvedAfterTypeContract=stats_.hardwareSemantic.unresolvedAfterHardwareSemantic;
}

void Decompiler::appendTypeContractTypeComments(std::vector<std::string>&out,std::uint16_t pc,const std::string&indent)const{
    for(const auto&r:typeEvidence_){if(!r.staticProof||!r.sourcePCs.count(pc))continue;if(r.role==TypeRoleKind::ByteWidth||r.role==TypeRoleKind::LittleEndianWord||r.role==TypeRoleKind::HardwareValue)continue;std::ostringstream s;s<<indent<<"// type/contract analysis type: "<<TypeEvidence::roleText(r.role)<<" ";if(r.targetKind==TypeTargetKind::RomObject)s<<"romobj#"<<r.romObjectId;else{s<<"$"<<h16p11(r.start);if(r.end>r.start+1)s<<"-$"<<h16p11(static_cast<std::uint16_t>(r.end-1));}if(r.maskKnown)s<<" mask=$"<<std::uppercase<<std::hex<<r.mask;if(r.rangeMinKnown)s<<" min="<<std::dec<<r.rangeMin;if(r.rangeMaxKnown)s<<" max="<<std::dec<<r.rangeMax;if(!r.pathCondition.empty())s<<" path="<<r.pathCondition;if(r.role==TypeRoleKind::HardwareValue)s<<" device="<<HardwareSemantics::deviceText(r.device);s<<" [static-proof]";out.push_back(s.str());}
}

std::vector<std::string> Decompiler::typeEvidenceLines() const{
    std::vector<std::string>o;if(!ready_){o.push_back("Decompiler model not built.");return o;}o.push_back("PacRipper type/contract analysis evidence-backed value/type roles");o.push_back("Conflicting width/signedness roles remain separate alternatives; masked use narrows only the consumed post-mask value, not the stored source domain.");{std::ostringstream s;s<<"Records="<<stats_.typeContract.types.records<<" static="<<stats_.typeContract.types.staticRecords<<" dynamic-only="<<stats_.typeContract.types.dynamicOnlyRecords<<" ambiguous-targets="<<stats_.typeContract.types.ambiguousTargets;o.push_back(s.str());}o.push_back("");for(const auto&r:typeEvidence_){std::ostringstream s;s<<"type#"<<r.id<<" ";if(r.targetKind==TypeTargetKind::RomObject)s<<"romobj#"<<r.romObjectId<<" $"<<h16p11(r.start)<<"-$"<<h16p11(static_cast<std::uint16_t>(r.end-1));else{s<<"$"<<h16p11(r.start);if(r.end>r.start+1)s<<"-$"<<h16p11(static_cast<std::uint16_t>(r.end-1));}s<<" "<<TypeEvidence::roleText(r.role)<<" bits="<<r.bits<<" ["<<(r.staticProof?"static-proof":"dynamic-only")<<(r.exact?", exact":" ,bounded")<<"]";if(r.maskKnown)s<<" mask=$"<<std::uppercase<<std::hex<<r.mask;if(r.rangeMinKnown)s<<" min="<<std::dec<<r.rangeMin;if(r.rangeMaxKnown)s<<" max="<<std::dec<<r.rangeMax;if(!r.pathCondition.empty())s<<" path="<<r.pathCondition;if(r.device!=BoardDeviceKind::None)s<<" device="<<HardwareSemantics::deviceText(r.device);o.push_back(s.str());if(!r.note.empty())o.push_back("  "+r.note);}return o;
}

std::vector<std::string> Decompiler::tableSchemaLines() const{
    std::vector<std::string>o;if(!ready_){o.push_back("Decompiler model not built.");return o;}o.push_back("PacRipper type/contract analysis proven table/record schemas");o.push_back("A schema requires finite static stride/bounds and repeated stable field offsets; visual adjacency is insufficient.");{std::ostringstream s;s<<"Schemas="<<stats_.typeContract.schemas.schemas<<" ROM="<<stats_.typeContract.schemas.romSchemas<<" RAM="<<stats_.typeContract.schemas.ramSchemas<<" fields="<<stats_.typeContract.schemas.fields;o.push_back(s.str());}o.push_back("");for(const auto&r:tableSchemas_){std::ostringstream s;s<<"schema#"<<r.id<<" "<<TableSchemas::targetKindText(r.targetKind)<<"#"<<r.targetId<<" $"<<h16p11(r.start)<<"-$"<<h16p11(static_cast<std::uint16_t>(r.end-1))<<" stride="<<r.stride<<" count="<<r.elementCount<<" [static-proof"<<(r.exactBounds?", exact-bounds":", bounded")<<"]";o.push_back(s.str());for(const auto&f:r.fields){std::ostringstream q;q<<"  +"<<f.offset<<" width="<<f.width<<" repeated="<<f.repeatedAccessCount<<" roles={";std::size_t n=0;for(auto role:f.roles){if(n++)q<<",";q<<TypeEvidence::roleText(role);}q<<"}";o.push_back(q.str());}if(!r.note.empty())o.push_back("  "+r.note);}if(tableSchemas_.empty())o.push_back("No repeated layout met the type/contract analysis proof threshold.");return o;
}

std::vector<std::string> Decompiler::routineContractLines() const{
    std::vector<std::string>o;if(!ready_){o.push_back("Decompiler model not built.");return o;}o.push_back("PacRipper type/contract analysis routine machine contracts");o.push_back("Register facts are machine inputs/outputs, not invented source parameters. Direct-call role propagation requires proven callee preservation.");{std::ostringstream s;s<<"Routines="<<stats_.typeContract.contracts.routines<<" definite-inputs="<<stats_.typeContract.contracts.definiteRegisterInputs<<" possible-inputs="<<stats_.typeContract.contracts.possibleRegisterInputs<<" returning-outputs="<<stats_.typeContract.contracts.returningRegisterOutputs<<" call-links="<<stats_.typeContract.contracts.callInputLinks;o.push_back(s.str());}o.push_back("");for(const auto&r:routineContracts_){std::ostringstream s;s<<"function $"<<h16p11(r.functionEntry)<<" inputs={";std::size_t n=0;for(const auto&f:r.inputs){if(n++)s<<", ";s<<f.reg<<":"<<RoutineContracts::certaintyText(f.certainty);if(!f.roles.empty()){s<<"[";std::size_t m=0;for(const auto&role:f.roles){if(m++)s<<"|";s<<role;}s<<"]";}}s<<"} outputs={";n=0;for(const auto&f:r.outputs){if(n++)s<<", ";s<<f.reg<<":"<<RoutineContracts::certaintyText(f.certainty);}s<<"}";o.push_back(s.str());std::ostringstream q;q<<"  RAM definite R/W="<<r.definiteRamReads.size()<<"/"<<r.definiteRamWrites.size()<<" possible R/W="<<r.possibleRamReads.size()<<"/"<<r.possibleRamWrites.size()<<" HW definite R/W="<<r.definiteHardwareReads.size()<<"/"<<r.definiteHardwareWrites.size()<<" possible R/W="<<r.possibleHardwareReads.size()<<"/"<<r.possibleHardwareWrites.size()<<" callees="<<r.directCallees.size()<<" preserved="<<r.preservedRegisters.size()<<" clobbered="<<r.clobberedRegisters.size();if(r.unknownCallEffects)q<<" unknown-call-effects";if(r.unknownMemoryWrite)q<<" unknown-memory-write";if(r.nonReturningOrUnknownExit)q<<" nonreturn/unknown-exit";o.push_back(q.str());for(const auto&l:r.callInputLinks){std::ostringstream z;z<<"  call $"<<h16p11(l.callPC)<<" -> $"<<h16p11(l.callee)<<" input "<<l.reg<<" defs="<<l.definitionIds.size()<<(l.callerEntryAlternative?" +entry":"")<<" survives="<<(l.survivesCall?"yes":"no");o.push_back(z.str());}}
    return o;
}

} // namespace pacripper
