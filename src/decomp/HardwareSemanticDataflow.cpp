// PacRipper hardware-semantics analysis hardware semantics / xrefs / RAM shapes
// Created by Jacob Hodgkins

#include "Decompiler.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <tuple>

namespace pacripper {
namespace {

std::string h16(std::uint16_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(4)<<std::setfill('0')<<(unsigned)v;return o.str();}

MemoryAccessKind convertAccess(RefAccess a){switch(a){case RefAccess::Read:return MemoryAccessKind::Read;case RefAccess::Write:return MemoryAccessKind::Write;case RefAccess::ReadWrite:return MemoryAccessKind::ReadWrite;case RefAccess::Address:return MemoryAccessKind::Unknown;}return MemoryAccessKind::Unknown;}

std::vector<std::string> splitOps(const std::string& text){std::vector<std::string> out;std::string cur;int depth=0;for(char c:text){if(c=='(')++depth;else if(c==')')--depth;if(c==','&&depth==0){out.push_back(cur);cur.clear();}else cur+=c;}if(!cur.empty()||!text.empty())out.push_back(cur);for(auto& s:out){while(!s.empty()&&std::isspace(static_cast<unsigned char>(s.front())))s.erase(s.begin());while(!s.empty()&&std::isspace(static_cast<unsigned char>(s.back())))s.pop_back();}return out;}

bool memoryOperand(const std::string& s){return s.size()>=3&&s.front()=='('&&s.back()==')';}
bool indirectMemoryOperand(const std::string& s){if(!memoryOperand(s))return false;return s.find("HL")!=std::string::npos||s.find("BC")!=std::string::npos||s.find("DE")!=std::string::npos||s.find("IX")!=std::string::npos||s.find("IY")!=std::string::npos||s.find("SP")!=std::string::npos;}

bool parsePointerOperand(const std::string& s,std::string& reg,int& displacement){
    reg.clear();displacement=0;if(!memoryOperand(s))return false;
    std::string inner=s.substr(1,s.size()-2);if(inner.rfind("HL",0)==0)reg="HL";else if(inner.rfind("BC",0)==0)reg="BC";else if(inner.rfind("DE",0)==0)reg="DE";else if(inner.rfind("IX",0)==0)reg="IX";else if(inner.rfind("IY",0)==0)reg="IY";else if(inner.rfind("SP",0)==0)reg="SP";else return false;
    std::string tail=inner.substr(reg.size());if(tail.empty())return true;char* e=nullptr;long v=std::strtol(tail.c_str(),&e,10);if(!e||*e!='\0'||v<-32768||v>32767)return false;displacement=static_cast<int>(v);return true;
}

unsigned directWidth(const Instruction& in){
    const auto& b=in.bytes;if(b.empty())return 1;
    std::size_t p=0;while(p<b.size()&&(b[p]==0xDD||b[p]==0xFD))++p;if(p>=b.size())return 1;
    if(b[p]==0xED){if(p+1<b.size()){const auto op=b[p+1];if(op==0x43||op==0x4B||op==0x53||op==0x5B||op==0x63||op==0x6B||op==0x73||op==0x7B)return 2;}return 1;}
    if(b[p]==0x22||b[p]==0x2A)return 2;
    return 1;
}

struct Intent {MemoryAccessKind access=MemoryAccessKind::Unknown;unsigned width=1;bool direct=false;std::uint16_t directAddress=0;std::string addressEntity;int displacement=0;std::string valueEntity;bool repeated=false;std::string countEntity;bool decrement=false;};

std::vector<Intent> intentsFor(const Instruction& in){
    std::vector<Intent> out;
    if(!in.memoryRefs.empty()){
        const unsigned w=directWidth(in);const auto ops=splitOps(in.operands);
        for(const auto& mr:in.memoryRefs){if(mr.access==RefAccess::Address)continue;Intent x;x.access=convertAccess(mr.access);x.width=w;x.direct=true;x.directAddress=mr.address;if(x.access==MemoryAccessKind::Write&&ops.size()>=2)x.valueEntity=ops[1];out.push_back(x);}return out;
    }
    const auto ops=splitOps(in.operands);
    if(in.mnemonic=="LD"&&ops.size()>=2){
        if(indirectMemoryOperand(ops[1])){Intent x;x.access=MemoryAccessKind::Read;x.width=1;parsePointerOperand(ops[1],x.addressEntity,x.displacement);out.push_back(x);}
        if(indirectMemoryOperand(ops[0])){Intent x;x.access=MemoryAccessKind::Write;x.width=1;parsePointerOperand(ops[0],x.addressEntity,x.displacement);x.valueEntity=ops[1];out.push_back(x);}
        return out;
    }
    if((in.mnemonic=="INC"||in.mnemonic=="DEC")&&!ops.empty()&&indirectMemoryOperand(ops[0])){Intent x;x.access=MemoryAccessKind::ReadWrite;x.width=1;parsePointerOperand(ops[0],x.addressEntity,x.displacement);out.push_back(x);return out;}
    if((in.mnemonic=="BIT"||in.mnemonic=="RES"||in.mnemonic=="SET"||in.mnemonic=="RLC"||in.mnemonic=="RRC"||in.mnemonic=="RL"||in.mnemonic=="RR"||in.mnemonic=="SLA"||in.mnemonic=="SRA"||in.mnemonic=="SLL"||in.mnemonic=="SRL")){
        for(const auto& op:ops){if(indirectMemoryOperand(op)){Intent x;x.access=in.mnemonic=="BIT"?MemoryAccessKind::Read:MemoryAccessKind::ReadWrite;x.width=1;parsePointerOperand(op,x.addressEntity,x.displacement);out.push_back(x);break;}}
        return out;
    }
    if(in.mnemonic=="ADD"||in.mnemonic=="ADC"||in.mnemonic=="SUB"||in.mnemonic=="SBC"||in.mnemonic=="AND"||in.mnemonic=="XOR"||in.mnemonic=="OR"||in.mnemonic=="CP"){
        for(const auto& op:ops){if(indirectMemoryOperand(op)){Intent x;x.access=MemoryAccessKind::Read;x.width=1;parsePointerOperand(op,x.addressEntity,x.displacement);out.push_back(x);break;}}
        return out;
    }
    if(in.mnemonic=="RRD"||in.mnemonic=="RLD"){Intent x;x.access=MemoryAccessKind::ReadWrite;x.addressEntity="HL";out.push_back(x);return out;}
    if(in.mnemonic=="EX"&&!ops.empty()&&ops[0]=="(SP)"){Intent x;x.access=MemoryAccessKind::ReadWrite;x.width=2;x.addressEntity="SP";out.push_back(x);return out;}
    if(in.mnemonic=="LDI"||in.mnemonic=="LDD"||in.mnemonic=="LDIR"||in.mnemonic=="LDDR"){
        Intent r;r.access=MemoryAccessKind::Read;r.addressEntity="HL";r.repeated=(in.mnemonic=="LDIR"||in.mnemonic=="LDDR");r.countEntity=r.repeated?"BC":"";r.decrement=(in.mnemonic=="LDD"||in.mnemonic=="LDDR");out.push_back(r);
        Intent w;w.access=MemoryAccessKind::Write;w.addressEntity="DE";w.repeated=r.repeated;w.countEntity=r.countEntity;w.decrement=r.decrement;out.push_back(w);return out;
    }
    if(in.mnemonic=="CPI"||in.mnemonic=="CPD"||in.mnemonic=="CPIR"||in.mnemonic=="CPDR"){
        Intent r;r.access=MemoryAccessKind::Read;r.addressEntity="HL";r.repeated=(in.mnemonic=="CPIR"||in.mnemonic=="CPDR");r.countEntity=r.repeated?"BC":"";r.decrement=(in.mnemonic=="CPD"||in.mnemonic=="CPDR");out.push_back(r);return out;
    }
    return out;
}

bool readAccess(MemoryAccessKind a){return a==MemoryAccessKind::Read||a==MemoryAccessKind::ReadWrite;}
bool writeAccess(MemoryAccessKind a){return a==MemoryAccessKind::Write||a==MemoryAccessKind::ReadWrite;}

} // namespace

void Decompiler::buildHardwareSemantic(){
    hardwareAccesses_.clear();memoryXrefs_.clear();ramShapes_.clear();stats_.hardwareSemantic={};if(!analyzer_)return;

    std::map<std::size_t,ExpressionRecord> exprById;for(const auto& e:defUseResult_.expressions)exprById[e.definitionId]=e;
    std::map<std::uint16_t,std::vector<const DefinitionRecord*>> defsAt;for(const auto& d:defUseResult_.definitions)defsAt[d.instructionAddress].push_back(&d);
    std::map<std::uint16_t,std::vector<const UseRecord*>> usesAt;for(const auto& u:defUseResult_.uses)usesAt[u.instructionAddress].push_back(&u);

    auto resolveEntity=[&](std::uint16_t pc,const std::string& entity,int disp)->ResolvedAddressFact{
        auto si=defUseResult_.stateBeforeInstruction.find(pc);if(si==defUseResult_.stateBeforeInstruction.end())return {};auto ei=si->second.find(entity);if(ei==si->second.end())return {};return HardwareSemantics::resolveAddressFact(ei->second,exprById,disp);
    };
    auto exactConstant=[&](std::uint16_t pc,const std::string& entity,std::uint16_t& value,std::set<std::size_t>* ids=nullptr)->bool{
        const auto r=resolveEntity(pc,entity,0);if(r.resolution!=AddressResolutionKind::ExactStatic||r.end!=static_cast<std::uint16_t>(r.start+1))return false;value=r.start;if(ids)*ids=r.definitionIds;return true;
    };
    auto dynamicObservedAt=[&](std::uint16_t pc,std::uint16_t start,std::uint16_t end,MemoryAccessKind access)->bool{
        for(std::uint32_t a=start;a<end;++a){auto it=analyzer_->boardUsage().find(static_cast<std::uint16_t>(a));if(it==analyzer_->boardUsage().end())continue;if(readAccess(access)&&it->second.dynamicReaders.count(pc))return true;if(writeAccess(access)&&it->second.dynamicWriters.count(pc))return true;}return false;
    };
    auto definitionIdsForWriteValue=[&](std::uint16_t pc,const std::string& addressEntity)->std::set<std::size_t>{
        std::set<std::size_t> ids;auto it=usesAt.find(pc);if(it==usesAt.end())return ids;for(const auto* u:it->second){if(!addressEntity.empty()&&u->entity==addressEntity)continue;ids.insert(u->reaching.definitionIds.begin(),u->reaching.definitionIds.end());}return ids;
    };
    auto definitionsForReadResult=[&](std::uint16_t pc)->std::set<std::size_t>{
        std::set<std::size_t> ids;auto it=defsAt.find(pc);if(it==defsAt.end())return ids;for(const auto* d:it->second){if(d->aliasInvalidation||d->callBoundaryClobber)continue;if(DefUseAnalysis::isTrackedRegister(d->entity))ids.insert(d->id);}return ids;
    };

    std::vector<HardwareAccessRecord> records;
    std::vector<RamShapeEvidence> shapeEvidence;
    for(const auto& ik:analyzer_->instructions()){
        const auto& in=ik.second;const bool staticInstruction=analyzer_->hasStaticInstructionProof(in.address);const auto intents=intentsFor(in);
        for(const auto& intent:intents){
            HardwareAccessInput x;x.pc=in.address;x.instructionLength=in.length();x.access=intent.access;x.width=intent.width;x.rawInstruction=in.text();x.addressEntity=intent.addressEntity;x.staticProof=staticInstruction;x.provenancePCs.insert(in.address);
            if(intent.direct){x.start=intent.directAddress;x.end=static_cast<std::uint16_t>(static_cast<std::uint32_t>(x.start)+x.width);x.addressResolution=staticInstruction?AddressResolutionKind::ExactStatic:AddressResolutionKind::DynamicObserved;}
            else{
                auto resolved=resolveEntity(in.address,intent.addressEntity,intent.displacement);x.addressDefinitionIds=resolved.definitionIds;x.provenancePCs.insert(resolved.provenancePCs.begin(),resolved.provenancePCs.end());
                if(resolved.resolution==AddressResolutionKind::ExactStatic||resolved.resolution==AddressResolutionKind::BoundedStatic){
                    x.addressResolution=resolved.resolution;x.start=resolved.start;x.end=resolved.end;
                    if(intent.repeated){
                        std::uint16_t count=0;if(exactConstant(in.address,intent.countEntity,count)&&count>0){
                            const std::uint32_t base=resolved.start;if(intent.decrement){const std::uint32_t n=static_cast<std::uint32_t>(count);const std::uint32_t lo=base>=n-1u?base-(n-1u):0x10000u;const std::uint32_t hi=base+1;if(lo<0x10000u&&hi<=0x10000u){x.start=static_cast<std::uint16_t>(lo);x.end=static_cast<std::uint16_t>(hi);x.addressResolution=count==1?AddressResolutionKind::ExactStatic:AddressResolutionKind::BoundedStatic;}}
                            else{const std::uint32_t hi=base+count;if(hi<=0x10000u){x.start=resolved.start;x.end=static_cast<std::uint16_t>(hi);x.addressResolution=count==1?AddressResolutionKind::ExactStatic:AddressResolutionKind::BoundedStatic;}}
                        }else x.addressResolution=AddressResolutionKind::Unresolved;
                    }else if(x.addressResolution==AddressResolutionKind::ExactStatic)x.end=static_cast<std::uint16_t>(static_cast<std::uint32_t>(x.start)+x.width);else x.end=static_cast<std::uint16_t>(static_cast<std::uint32_t>(x.end)+x.width-1);
                }
            }
            if(x.addressResolution==AddressResolutionKind::Unresolved)continue;
            if(x.end<=x.start)continue;
            bool touchesBoard=false;for(std::uint32_t a=x.start;a<x.end;++a)if(HardwareSemantics::isBoardMapped(static_cast<std::uint16_t>(a))){touchesBoard=true;break;}if(!touchesBoard)continue;
            x.dynamicObserved=dynamicObservedAt(in.address,x.start,x.end,x.access);
            if(!staticInstruction&&x.addressResolution==AddressResolutionKind::DynamicObserved&&!x.dynamicObserved)continue;
            if(writeAccess(x.access))x.valueDefinitionIds=definitionIdsForWriteValue(in.address,x.addressEntity);
            if(readAccess(x.access))x.readResultDefinitionIds=definitionsForReadResult(in.address);
            auto r=HardwareSemantics::classify(x);records.push_back(r);

            // Exact block-operation bounds are stronger than adjacency: the Z80
            // instruction itself proves stride=1 and BC proves the finite extent.
            if(intent.repeated&&staticInstruction){
                std::uint16_t count=0;auto base=resolveEntity(in.address,intent.addressEntity,intent.displacement);if(base.resolution==AddressResolutionKind::ExactStatic&&exactConstant(in.address,intent.countEntity,count)&&count>=2){
                    std::uint32_t s=base.start;const std::uint32_t n=static_cast<std::uint32_t>(count);if(intent.decrement){if(s<n-1u)continue;s-=n-1u;}const std::uint32_t e=s+count;if(e>0x10000u)continue;const auto start=static_cast<std::uint16_t>(s),end=static_cast<std::uint16_t>(e);
                    const bool allRam=(start>=0x4000&&end<=0x4800)||(start>=0x4C00&&end<=0x5000);if(allRam){RamShapeEvidence ev;ev.start=start;ev.elementSize=1;ev.elementCount=count;ev.stride=1;ev.boundsExact=true;ev.staticProof=true;ev.dynamicObserved=x.dynamicObserved;ev.kind=(in.mnemonic=="CPIR"||in.mnemonic=="CPDR")?RamShapeEvidenceKind::BlockScan:RamShapeEvidenceKind::BlockTransfer;ev.sourcePCs.insert(in.address);ev.note=in.mnemonic+" with exact "+intent.addressEntity+" base and BC count proves a finite byte stride/range; no gameplay semantic name inferred";shapeEvidence.push_back(ev);}
                }
            }
        }
    }

    // Merge exact dynamic bus evidence into static/bounded records, and preserve
    // dynamic-only addresses as dynamic-only records without promoting them.
    for(const auto& bk:analyzer_->boardUsage()){
        const auto address=bk.first;const auto& usage=bk.second;
        auto mergeOrAdd=[&](std::uint16_t pc,MemoryAccessKind access){
            for(auto& r:records)if(r.pc==pc&&(r.access==access||r.access==MemoryAccessKind::ReadWrite)&&address>=r.start&&address<r.end){r.dynamicObserved=true;return;}
            HardwareAccessInput x;x.pc=pc;x.access=access;x.width=1;x.addressResolution=AddressResolutionKind::DynamicObserved;x.start=address;x.end=static_cast<std::uint16_t>(address+1);x.dynamicObserved=true;x.staticProof=false;x.provenancePCs.insert(pc);auto ii=analyzer_->instructions().find(pc);if(ii!=analyzer_->instructions().end()){x.instructionLength=ii->second.length();x.rawInstruction=ii->second.text();}x.note="exact bus address observed in imported trace; retained as dynamic-only evidence";records.push_back(HardwareSemantics::classify(x));
        };
        for(auto pc:usage.dynamicReaders)mergeOrAdd(pc,MemoryAccessKind::Read);
        for(auto pc:usage.dynamicWriters)mergeOrAdd(pc,MemoryAccessKind::Write);
    }

    std::sort(records.begin(),records.end(),[](const HardwareAccessRecord& a,const HardwareAccessRecord& b){if(a.pc!=b.pc)return a.pc<b.pc;if(a.start!=b.start)return a.start<b.start;if(a.access!=b.access)return static_cast<int>(a.access)<static_cast<int>(b.access);return static_cast<int>(a.addressResolution)<static_cast<int>(b.addressResolution);});
    for(std::size_t i=0;i<records.size();++i)records[i].id=i;
    hardwareAccesses_=std::move(records);

    ramShapes_=RamShapes::reconstruct(ramObjects_,shapeEvidence);
    std::map<std::uint16_t,std::set<std::uint16_t>> owners;for(const auto& bk:blocks_)for(auto pc:bk.second.instructions)owners[pc]=bk.second.functionOwners;
    memoryXrefs_=MemoryXrefs::build(hardwareAccesses_,defUseResult_,owners,ramObjects_);
    stats_.hardwareSemantic.hardware=HardwareSemantics::stats(hardwareAccesses_);stats_.hardwareSemantic.memoryXrefs=MemoryXrefs::stats(memoryXrefs_);stats_.hardwareSemantic.ramShapes=RamShapes::stats(ramShapes_);
    // hardware-semantics analysis annotates memory semantics only; no new ROM-byte consumer proof is
    // manufactured by board naming or RAM shape refinement.
    stats_.hardwareSemantic.newlyExplainedBytes=0;stats_.hardwareSemantic.unresolvedAfterHardwareSemantic=stats_.defUse.unresolvedAfterDefUse;
}

std::vector<std::string> Decompiler::hardwareLines() const{
    std::vector<std::string> o;if(!ready_){o.push_back("Decompiler model not built.");return o;}o.push_back("PacRipper hardware-semantics analysis Pac-Man board hardware semantics");o.push_back("Read/write identities are access-direction-aware. Dynamic-only bus observations never become static proof.");{std::ostringstream s;s<<"Records="<<stats_.hardwareSemantic.hardware.records<<" exact-static="<<stats_.hardwareSemantic.hardware.exactStatic<<" bounded-static="<<stats_.hardwareSemantic.hardware.boundedStatic<<" dynamic-only="<<stats_.hardwareSemantic.hardware.dynamicOnly<<" dynamic-corroborated="<<stats_.hardwareSemantic.hardware.corroboratedDynamic;o.push_back(s.str());}o.push_back("");
    for(const auto& r:hardwareAccesses_){std::ostringstream s;s<<"hw#"<<r.id<<" PC $"<<h16(r.pc)<<" "<<HardwareSemantics::accessText(r.access)<<" ";if(r.addressResolution==AddressResolutionKind::Unresolved)s<<"<unresolved>";else{s<<"$"<<h16(r.start);if(r.end>r.start+1)s<<"-$"<<h16(static_cast<std::uint16_t>(r.end-1));}s<<" "<<HardwareSemantics::deviceText(r.device)<<" ["<<HardwareSemantics::resolutionText(r.addressResolution)<<", "<<HardwareSemantics::effectText(r.effect);if(r.dynamicObserved)s<<", observed";s<<"]";o.push_back(s.str());std::ostringstream q;q<<"  raw="<<r.rawInstruction;if(!r.readIdentity.empty())q<<" read="<<r.readIdentity;if(!r.writeIdentity.empty())q<<" write="<<r.writeIdentity;if(!r.intrinsic.empty())q<<" intrinsic="<<r.intrinsic;o.push_back(q.str());if(!r.note.empty())o.push_back("  "+r.note);}return o;
}

std::vector<std::string> Decompiler::memoryXrefLines() const{
    std::vector<std::string> o;if(!ready_){o.push_back("Decompiler model not built.");return o;}o.push_back("PacRipper hardware-semantics analysis semantic memory xref index");o.push_back("Stable xref IDs link exact/bounded addresses, board devices, function owners, write-value definitions, read-result uses and def-use analysis RAM objects.");{std::ostringstream s;s<<"Records="<<stats_.hardwareSemantic.memoryXrefs.records<<" exact-address="<<stats_.hardwareSemantic.memoryXrefs.exactAddressRecords<<" hardware="<<stats_.hardwareSemantic.memoryXrefs.hardwareRecords<<" RAM="<<stats_.hardwareSemantic.memoryXrefs.ramRecords<<" write-def-links="<<stats_.hardwareSemantic.memoryXrefs.writeValueLinks<<" read-use-links="<<stats_.hardwareSemantic.memoryXrefs.readUseLinks;o.push_back(s.str());}o.push_back("");
    for(const auto& r:memoryXrefs_){std::ostringstream s;s<<"xref#"<<r.id<<" hw#"<<r.hardwareAccessId<<" PC $"<<h16(r.pc)<<" "<<HardwareSemantics::accessText(r.access)<<" $"<<h16(r.start);if(r.end>r.start+1)s<<"-$"<<h16(static_cast<std::uint16_t>(r.end-1));s<<" "<<HardwareSemantics::deviceText(r.device);o.push_back(s.str());std::ostringstream q;q<<"  owners={";std::size_t n=0;for(auto v:r.functionOwners){if(n++)q<<",";q<<"$"<<h16(v);}q<<"} address-defs={";n=0;for(auto id:r.addressDefinitionIds){if(n++)q<<",";q<<"def#"<<id;}q<<"} value-def-PCs={";n=0;for(auto v:r.valueDefinitionPCs){if(n++)q<<",";q<<"$"<<h16(v);}q<<"} downstream-use-PCs={";n=0;for(auto v:r.downstreamUsePCs){if(n++)q<<",";q<<"$"<<h16(v);}q<<"}";if(!r.ramObjectIds.empty()){q<<" ramobjs={";n=0;for(auto id:r.ramObjectIds){if(n++)q<<",";q<<"ramobj#"<<id;}q<<"}";}o.push_back(q.str());}
    o.push_back("");o.push_back("Existing object/pointer and def-use analysis ROM-object/pointer links remain available in --xrefs / --pointer-chains; residual ROM closure is unchanged by semantic board naming.");return o;
}

std::vector<std::string> Decompiler::ramShapeLines() const{
    std::vector<std::string> o;if(!ready_){o.push_back("Decompiler model not built.");return o;}o.push_back("PacRipper hardware-semantics analysis conservative RAM shape refinement");o.push_back("Arrays require exact finite stride/bounds evidence (for example LDIR/CPIR with exact base/count). Adjacency alone never forms a shape.");{std::ostringstream s;s<<"Shapes="<<stats_.hardwareSemantic.ramShapes.shapes<<" arrays="<<stats_.hardwareSemantic.ramShapes.arrays<<" record-candidates="<<stats_.hardwareSemantic.ramShapes.records;o.push_back(s.str());}o.push_back("");for(const auto& r:ramShapes_){std::ostringstream s;s<<"ramshape#"<<r.id<<" $"<<h16(r.start)<<"-$"<<h16(static_cast<std::uint16_t>(r.end-1))<<" "<<RamShapes::kindText(r.kind)<<" elements="<<r.elementCount<<" size="<<r.elementSize<<" stride="<<r.stride<<" evidence="<<RamShapes::evidenceKindText(r.evidenceKind)<<" [static-proof"<<(r.dynamicObserved?", observed":"")<<"]";o.push_back(s.str());o.push_back("  "+r.note);}if(ramShapes_.empty())o.push_back("No RAM array/record candidate met the hardware-semantics analysis stride+bounds proof threshold.");return o;
}

} // namespace pacripper
