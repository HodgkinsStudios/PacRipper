// PacRipper indirect-address analysis bounded indirect-memory address proof
// Created by Jacob Hodgkins

#include "IndirectAddressAnalysis.h"
#include "ConditionSemantics.h"

#include <algorithm>
#include <cstdlib>
#include <functional>
#include <limits>
#include <map>
#include <queue>
#include <sstream>
#include <tuple>

namespace pacripper {
namespace {

constexpr std::size_t kInternalStateMaxValues=16;
constexpr std::size_t kEvidenceSetCap=16;

struct Fact {
    bool known=false;
    bool unknownAlternative=true;
    bool wraparound=false;
    std::set<std::uint16_t> values;
    std::set<std::size_t> originDefinitionIds;
    std::set<std::uint16_t> provenancePCs;
    std::set<std::uint16_t> ramOriginAddresses;
    std::set<std::uint16_t> callEvidencePCs;
    bool fromRam=false;
    bool fromStack=false;
    bool acrossCall=false;
    bool fromReturn=false;
    bool widened=false;
    std::string chain;
};

struct StackSlot {
    Fact pair;
    Fact high;
    Fact low;
};

struct State {
    std::map<std::string,Fact> regs;
    std::map<std::uint16_t,Fact> ramPairs;
    bool stackKnown=true;
    std::vector<StackSlot> stack;
};

struct AccessAggregate {
    std::uint16_t pc=0;
    std::string operand;
    std::string reg;
    int displacement=0;
    IndirectMemoryDirection direction=IndirectMemoryDirection::Read;
    Fact addresses;
    bool initialized=false;
    bool pathBounded=false;
    bool throughRam=false;
    bool throughStack=false;
    bool acrossCall=false;
    bool fromReturn=false;
};

std::vector<std::string> splitOps(const std::string& text){
    std::vector<std::string> out;std::string cur;int depth=0;
    auto trim=[](std::string s){while(!s.empty()&&s.front()==' ')s.erase(s.begin());while(!s.empty()&&s.back()==' ')s.pop_back();return s;};
    for(char c:text){if(c=='(')++depth;else if(c==')')--depth;if(c==','&&depth==0){out.push_back(trim(cur));cur.clear();}else cur+=c;}
    if(!cur.empty()) out.push_back(trim(cur));
    return out;
}

bool isPair(const std::string& r){return r=="BC"||r=="DE"||r=="HL"||r=="IX"||r=="IY"||r=="SP";}
bool isByte(const std::string& r){return r=="A"||r=="B"||r=="C"||r=="D"||r=="E"||r=="H"||r=="L"||r=="IXH"||r=="IXL"||r=="IYH"||r=="IYL";}
std::pair<std::string,std::string> pairBytes(const std::string& r){if(r=="BC")return{"B","C"};if(r=="DE")return{"D","E"};if(r=="HL")return{"H","L"};if(r=="IX")return{"IXH","IXL"};if(r=="IY")return{"IYH","IYL"};return{};}
std::string bytePair(const std::string& r){if(r=="B"||r=="C")return"BC";if(r=="D"||r=="E")return"DE";if(r=="H"||r=="L")return"HL";if(r=="IXH"||r=="IXL")return"IX";if(r=="IYH"||r=="IYL")return"IY";return{};}

Fact unknown(){return Fact{};}
Fact exactFact(std::uint16_t v,std::uint16_t pc=0){Fact f;f.known=true;f.unknownAlternative=false;f.values.insert(v);if(pc)f.provenancePCs.insert(pc);return f;}
Fact get(const State&s,const std::string&r){auto i=s.regs.find(r);return i==s.regs.end()?unknown():i->second;}

bool sameFact(const Fact&a,const Fact&b){return a.known==b.known&&a.unknownAlternative==b.unknownAlternative&&a.wraparound==b.wraparound&&a.values==b.values&&a.originDefinitionIds==b.originDefinitionIds&&a.provenancePCs==b.provenancePCs&&a.ramOriginAddresses==b.ramOriginAddresses&&a.callEvidencePCs==b.callEvidencePCs&&a.fromRam==b.fromRam&&a.fromStack==b.fromStack&&a.acrossCall==b.acrossCall&&a.fromReturn==b.fromReturn&&a.widened==b.widened&&a.chain==b.chain;}

Fact mergeFact(Fact a,const Fact& b,std::size_t maxValues=512){
    a.unknownAlternative=a.unknownAlternative||b.unknownAlternative;
    a.wraparound=a.wraparound||b.wraparound;
    auto boundedUnion=[](auto& dst,const auto& src){for(const auto& v:src){if(dst.size()>=kEvidenceSetCap)break;dst.insert(v);}};
    boundedUnion(a.originDefinitionIds,b.originDefinitionIds);
    boundedUnion(a.provenancePCs,b.provenancePCs);
    boundedUnion(a.ramOriginAddresses,b.ramOriginAddresses);
    boundedUnion(a.callEvidencePCs,b.callEvidencePCs);
    a.fromRam=a.fromRam||b.fromRam;a.fromStack=a.fromStack||b.fromStack;a.acrossCall=a.acrossCall||b.acrossCall;a.fromReturn=a.fromReturn||b.fromReturn;
    if(a.widened||b.widened){a.widened=true;a.values.clear();a.known=false;a.unknownAlternative=true;a.chain="widened after cyclic-state growth";return a;}
    if(a.chain.empty())a.chain=b.chain;else if(!b.chain.empty()&&a.chain!=b.chain)a.chain="merged static alternatives";
    a.values.insert(b.values.begin(),b.values.end());
    if(a.values.size()>maxValues){a.values.clear();a.known=false;a.unknownAlternative=true;return a;}
    a.known=!a.values.empty();return a;
}

void widenFact(Fact& f){
    if(f.widened)return;
    if(f.unknownAlternative||f.values.size()>1){f.values.clear();f.known=false;f.unknownAlternative=true;f.widened=true;f.chain="widened after cyclic-state growth";}
}
void widenState(State& s){
    for(auto& kv:s.regs)widenFact(kv.second);
    for(auto& kv:s.ramPairs)widenFact(kv.second);
    if(s.stackKnown)for(auto& slot:s.stack){widenFact(slot.pair);widenFact(slot.high);widenFact(slot.low);}
}

bool mergeState(State&dst,const State&src,bool initialized){
    if(!initialized){dst=src;return true;}bool changed=false;
    static const std::vector<std::string> regs={"A","B","C","D","E","H","L","BC","DE","HL","IX","IY","IXH","IXL","IYH","IYL","SP"};
    for(const auto&r:regs){Fact d=get(dst,r),s=get(src,r),m=mergeFact(d,s,kInternalStateMaxValues);if(!sameFact(d,m)){dst.regs[r]=m;changed=true;}}
    for(auto it=dst.ramPairs.begin();it!=dst.ramPairs.end();){auto si=src.ramPairs.find(it->first);if(si==src.ramPairs.end()){it=dst.ramPairs.erase(it);changed=true;continue;}Fact m=mergeFact(it->second,si->second,kInternalStateMaxValues);if(!sameFact(m,it->second)){it->second=m;changed=true;}++it;}
    if(dst.stackKnown&&src.stackKnown&&dst.stack.size()==src.stack.size()){
        for(std::size_t i=0;i<dst.stack.size();++i){
            Fact mp=mergeFact(dst.stack[i].pair,src.stack[i].pair,kInternalStateMaxValues);
            Fact mh=mergeFact(dst.stack[i].high,src.stack[i].high,kInternalStateMaxValues);
            Fact ml=mergeFact(dst.stack[i].low,src.stack[i].low,kInternalStateMaxValues);
            if(!sameFact(mp,dst.stack[i].pair)){dst.stack[i].pair=mp;changed=true;}
            if(!sameFact(mh,dst.stack[i].high)){dst.stack[i].high=mh;changed=true;}
            if(!sameFact(ml,dst.stack[i].low)){dst.stack[i].low=ml;changed=true;}
        }
    }else if(dst.stackKnown){dst.stackKnown=false;dst.stack.clear();changed=true;}
    return changed;
}

Fact shiftFact(const Fact&f,int delta,unsigned bits){
    Fact o=f;if(!f.known)return o;o.values.clear();const std::uint32_t modulus=bits==8?256u:65536u;
    for(auto v:f.values){const long raw=static_cast<long>(v)+delta;long n=raw%static_cast<long>(modulus);if(n<0)n+=modulus;if(raw<0||raw>=static_cast<long>(modulus))o.wraparound=true;o.values.insert(static_cast<std::uint16_t>(n));}
    o.known=!o.values.empty();o.chain=f.chain.empty()?(delta>=0?"offset +"+std::to_string(delta):"offset "+std::to_string(delta)):(f.chain+(delta>=0?" + ":" - ")+std::to_string(std::abs(delta)));return o;
}

Fact mapByteFact(const Fact&f,const std::string&chain,const std::function<std::uint8_t(std::uint8_t)>&fn){
    Fact o=f;o.values.clear();o.chain=chain;if(!f.known)return o;
    for(auto v:f.values)o.values.insert(fn(static_cast<std::uint8_t>(v)));
    o.known=!o.values.empty();return o;
}

Fact binaryByteFact(const Fact&a,const Fact&b,const std::string&chain,const std::function<std::uint8_t(std::uint8_t,std::uint8_t)>&fn,std::size_t maxValues=kInternalStateMaxValues){
    Fact o;o.unknownAlternative=a.unknownAlternative||b.unknownAlternative;o.wraparound=a.wraparound||b.wraparound;
    o.originDefinitionIds=a.originDefinitionIds;o.provenancePCs=a.provenancePCs;o.ramOriginAddresses=a.ramOriginAddresses;o.callEvidencePCs=a.callEvidencePCs;
    auto boundedUnion=[](auto&dst,const auto&src){for(const auto&v:src){if(dst.size()>=kEvidenceSetCap)break;dst.insert(v);}};
    boundedUnion(o.originDefinitionIds,b.originDefinitionIds);boundedUnion(o.provenancePCs,b.provenancePCs);boundedUnion(o.ramOriginAddresses,b.ramOriginAddresses);boundedUnion(o.callEvidencePCs,b.callEvidencePCs);
    o.fromRam=a.fromRam||b.fromRam;o.fromStack=a.fromStack||b.fromStack;o.acrossCall=a.acrossCall||b.acrossCall;o.fromReturn=a.fromReturn||b.fromReturn;o.chain=chain;
    if(!a.known||!b.known){o.known=false;o.unknownAlternative=true;return o;}
    for(auto x:a.values)for(auto y:b.values){o.values.insert(fn(static_cast<std::uint8_t>(x),static_cast<std::uint8_t>(y)));if(o.values.size()>maxValues){o.values.clear();o.known=false;o.unknownAlternative=true;return o;}}
    o.known=!o.values.empty();return o;
}

Fact maskedByteFact(const Fact&f,std::uint8_t mask,std::uint16_t pc){
    Fact o=f;o.values.clear();o.provenancePCs.insert(pc);o.chain="AND mask $"+Z80Disassembler::hex8(mask);
    if(f.known){for(auto v:f.values)o.values.insert(static_cast<std::uint8_t>(v)&mask);o.known=!o.values.empty();return o;}
    // Even with an otherwise unknown source, AND with a mask whose finite image fits
    // the internal set cap yields an exact set of all possible post-mask values.
    std::set<std::uint16_t> image;for(unsigned v=0;v<256;++v)image.insert(static_cast<std::uint8_t>(v)&mask);
    if(image.size()<=kInternalStateMaxValues){o.values=image;o.known=true;o.unknownAlternative=false;o.widened=false;}
    return o;
}

Fact filterByteEquality(Fact f,std::uint8_t constant,bool equal){
    if(!f.known)return f;
    for(auto it=f.values.begin();it!=f.values.end();){const bool matches=static_cast<std::uint8_t>(*it)==constant;if(matches!=equal)it=f.values.erase(it);else ++it;}
    if(f.values.empty()){f.known=false;f.unknownAlternative=true;}
    else f.known=true;
    f.chain=equal?"branch-local equality filter":"branch-local inequality filter";return f;
}

Fact addFact(const Fact&a,const Fact&b,unsigned bits,std::size_t maxValues=512){
    Fact o;o.unknownAlternative=a.unknownAlternative||b.unknownAlternative;o.wraparound=a.wraparound||b.wraparound;o.originDefinitionIds=a.originDefinitionIds;o.originDefinitionIds.insert(b.originDefinitionIds.begin(),b.originDefinitionIds.end());o.provenancePCs=a.provenancePCs;o.provenancePCs.insert(b.provenancePCs.begin(),b.provenancePCs.end());o.ramOriginAddresses=a.ramOriginAddresses;o.ramOriginAddresses.insert(b.ramOriginAddresses.begin(),b.ramOriginAddresses.end());o.callEvidencePCs=a.callEvidencePCs;o.callEvidencePCs.insert(b.callEvidencePCs.begin(),b.callEvidencePCs.end());o.fromRam=a.fromRam||b.fromRam;o.fromStack=a.fromStack||b.fromStack;o.acrossCall=a.acrossCall||b.acrossCall;o.fromReturn=a.fromReturn||b.fromReturn;o.chain="proven modular add";
    if(!a.known||!b.known){o.known=false;o.unknownAlternative=true;return o;}const std::uint32_t modulus=bits==8?256u:65536u;
    for(auto x:a.values)for(auto y:b.values){const std::uint32_t raw=static_cast<std::uint32_t>(x)+y;if(raw>=modulus)o.wraparound=true;o.values.insert(static_cast<std::uint16_t>(raw%modulus));if(o.values.size()>maxValues){o.values.clear();o.known=false;o.unknownAlternative=true;return o;}}
    o.known=!o.values.empty();return o;
}

Fact combineFact(const Fact&h,const Fact&l,std::size_t maxValues=512){
    Fact o;o.unknownAlternative=h.unknownAlternative||l.unknownAlternative;o.wraparound=h.wraparound||l.wraparound;o.originDefinitionIds=h.originDefinitionIds;o.originDefinitionIds.insert(l.originDefinitionIds.begin(),l.originDefinitionIds.end());o.provenancePCs=h.provenancePCs;o.provenancePCs.insert(l.provenancePCs.begin(),l.provenancePCs.end());o.ramOriginAddresses=h.ramOriginAddresses;o.ramOriginAddresses.insert(l.ramOriginAddresses.begin(),l.ramOriginAddresses.end());o.callEvidencePCs=h.callEvidencePCs;o.callEvidencePCs.insert(l.callEvidencePCs.begin(),l.callEvidencePCs.end());o.fromRam=h.fromRam||l.fromRam;o.fromStack=h.fromStack||l.fromStack;o.acrossCall=h.acrossCall||l.acrossCall;o.fromReturn=h.fromReturn||l.fromReturn;o.chain="proven high/low byte construction";
    if(!h.known||!l.known){o.known=false;o.unknownAlternative=true;return o;}for(auto hi:h.values)for(auto lo:l.values){o.values.insert(static_cast<std::uint16_t>(((hi&0xFFu)<<8)|(lo&0xFFu)));if(o.values.size()>maxValues){o.values.clear();o.known=false;o.unknownAlternative=true;return o;}}o.known=!o.values.empty();return o;
}

void setPair(State&s,const std::string&r,const Fact&f){s.regs[r]=f;auto c=pairBytes(r);if(c.first.empty())return;Fact hi=f,lo=f;hi.values.clear();lo.values.clear();for(auto v:f.values){hi.values.insert(static_cast<std::uint8_t>(v>>8));lo.values.insert(static_cast<std::uint8_t>(v));}hi.known=f.known&&!hi.values.empty();lo.known=f.known&&!lo.values.empty();hi.chain="high byte of "+r;lo.chain="low byte of "+r;s.regs[c.first]=hi;s.regs[c.second]=lo;}
void setByte(State&s,const std::string&r,const Fact&f){s.regs[r]=f;const auto p=bytePair(r);if(p.empty())return;const auto c=pairBytes(p);s.regs[p]=combineFact(get(s,c.first),get(s,c.second),kInternalStateMaxValues);}
void invalidatePair(State&s,const std::string&r){Fact u=unknown();setPair(s,r,u);}
void invalidateByte(State&s,const std::string&r){s.regs[r]=unknown();const auto p=bytePair(r);if(!p.empty())s.regs[p]=unknown();}

bool physicalRam(std::uint16_t a){return (a>=0x4000&&a<=0x47FF)||(a>=0x4C00&&a<=0x4FFF);}

bool decodeDirectPairMemory(const Instruction& in,std::uint16_t& address,std::string& pair,bool& read,bool& write){
    const auto&b=in.bytes;read=write=false;
    if(b.size()>=3&&(b[0]==0x2A||b[0]==0x22)){address=static_cast<std::uint16_t>(b[1]|(static_cast<std::uint16_t>(b[2])<<8));pair="HL";read=b[0]==0x2A;write=!read;return true;}
    if(b.size()>=4&&b[0]==0xED&&(b[1]==0x4B||b[1]==0x5B||b[1]==0x6B||b[1]==0x7B||b[1]==0x43||b[1]==0x53||b[1]==0x63||b[1]==0x73)){
        address=static_cast<std::uint16_t>(b[2]|(static_cast<std::uint16_t>(b[3])<<8));const auto op=b[1];pair=(op==0x4B||op==0x43)?"BC":(op==0x5B||op==0x53)?"DE":(op==0x6B||op==0x63)?"HL":"SP";read=(op&0x08)!=0;write=!read;return true;}
    if(b.size()>=4&&(b[0]==0xDD||b[0]==0xFD)&&(b[1]==0x2A||b[1]==0x22)){address=static_cast<std::uint16_t>(b[2]|(static_cast<std::uint16_t>(b[3])<<8));pair=b[0]==0xDD?"IX":"IY";read=b[1]==0x2A;write=!read;return true;}return false;
}

std::map<std::pair<std::uint16_t,std::string>,std::set<std::size_t>> definitionIds(const DefUseResult&du){std::map<std::pair<std::uint16_t,std::string>,std::set<std::size_t>> out;for(const auto&d:du.definitions)out[{d.instructionAddress,d.entity}].insert(d.id);return out;}
void attachDefIds(Fact&f,std::uint16_t pc,const std::string&entity,const std::map<std::pair<std::uint16_t,std::string>,std::set<std::size_t>>&ids){auto i=ids.find({pc,entity});if(i!=ids.end())f.originDefinitionIds.insert(i->second.begin(),i->second.end());f.provenancePCs.insert(pc);}

std::vector<std::tuple<std::string,int,IndirectMemoryDirection,std::string>> indirectAccesses(const Instruction&in){
    std::vector<std::tuple<std::string,int,IndirectMemoryDirection,std::string>> out;const auto ops=splitOps(in.operands);auto add=[&](const std::string&o,IndirectMemoryDirection d){std::string r;int disp=0;if(IndirectAddressAnalysis::parseIndirectOperand(o,r,disp))out.push_back({r,disp,d,o});};
    if(in.mnemonic=="JP"||in.mnemonic=="CALL"||in.mnemonic=="RET"||in.mnemonic=="RST")return out;
    if(in.mnemonic=="LD"&&ops.size()>=2){add(ops[0],IndirectMemoryDirection::Write);add(ops[1],IndirectMemoryDirection::Read);return out;}
    if((in.mnemonic=="INC"||in.mnemonic=="DEC"||in.mnemonic=="RLC"||in.mnemonic=="RRC"||in.mnemonic=="RL"||in.mnemonic=="RR"||in.mnemonic=="SLA"||in.mnemonic=="SRA"||in.mnemonic=="SLL"||in.mnemonic=="SRL"||in.mnemonic=="RES"||in.mnemonic=="SET")&&!ops.empty()){add(ops.back(),IndirectMemoryDirection::ReadWrite);return out;}
    if(in.mnemonic=="BIT"&&!ops.empty()){add(ops.back(),IndirectMemoryDirection::Read);return out;}
    if(in.mnemonic=="ADD"||in.mnemonic=="ADC"||in.mnemonic=="SUB"||in.mnemonic=="SBC"||in.mnemonic=="AND"||in.mnemonic=="XOR"||in.mnemonic=="OR"||in.mnemonic=="CP"){for(const auto&o:ops)add(o,IndirectMemoryDirection::Read);return out;}
    return out;
}

Fact filterByte(const Fact&f,bool nonzero){Fact o=f;if(!f.known)return o;o.values.clear();for(auto v:f.values)if(((v&0xFFu)!=0)==nonzero)o.values.insert(static_cast<std::uint8_t>(v));o.known=!o.values.empty();if(!o.known&&!o.unknownAlternative)o.unknownAlternative=false;return o;}

void invalidateWritten(State&s,const Instruction&in){
    const auto wr=ConditionSemantics::writtenRegisters(in);static const std::vector<std::string>pairs={"BC","DE","HL","IX","IY","SP"};
    for(const auto&p:pairs)if(wr.count(p)){invalidatePair(s,p);}
    for(const auto&r:std::vector<std::string>{"A","B","C","D","E","H","L","IXH","IXL","IYH","IYL"})if(wr.count(r))invalidateByte(s,r);
}

AddressLatticeValue toAddressValue(const Fact&f){AddressLatticeValue v;v.values=f.values;v.hasUnknownAlternative=f.unknownAlternative;v.wraparound=f.wraparound;v.staticProof=true;v.dynamicOnly=false;v.originDefinitionIds=f.originDefinitionIds;v.provenancePCs=f.provenancePCs;v.ramOriginAddresses=f.ramOriginAddresses;v.callEvidencePCs=f.callEvidencePCs;v.note=f.chain;return IndirectAddressAnalysis::classifyKnownValues(v);}

const Instruction* instructionAt(const std::map<std::uint16_t,Instruction>& ins,std::uint16_t pc){
    auto it=ins.find(pc);return it==ins.end()?nullptr:&it->second;
}
const Instruction* nextInstruction(const std::map<std::uint16_t,Instruction>& ins,const Instruction* in){
    if(!in)return nullptr;
    const auto next=static_cast<std::uint16_t>(in->address+in->length());
    return instructionAt(ins,next);
}
const Instruction* previousInstruction(const std::map<std::uint16_t,Instruction>& ins,std::uint16_t pc){
    const Instruction* out=nullptr;for(const auto& kv:ins){const auto& in=kv.second;if(static_cast<std::uint32_t>(in.address)+in.length()==pc)out=&in;if(in.address>=pc)break;}return out;
}
bool isLd(const Instruction* in,const std::string& dst,const std::string& src){if(!in||in->mnemonic!="LD")return false;const auto o=splitOps(in->operands);return o.size()==2&&o[0]==dst&&o[1]==src;}
bool isInc(const Instruction* in,const std::string& reg){if(!in||in->mnemonic!="INC")return false;const auto o=splitOps(in->operands);return o.size()==1&&o[0]==reg;}
bool immediate8(const Instruction* in,std::uint8_t opcode,std::uint8_t& value){if(!in||in->bytes.size()<2||in->bytes[0]!=opcode)return false;value=in->bytes[1];return true;}
bool isBranchTo(const Instruction* in,const std::string& cond,std::uint16_t target){if(!in||!in->conditional||in->target<0||static_cast<std::uint16_t>(in->target)!=target)return false;const auto o=splitOps(in->operands);return !o.empty()&&o[0]==cond;}
bool safePrelude(const std::map<std::uint16_t,Instruction>& ins,std::uint16_t start,std::uint16_t end){
    auto pc=start;std::size_t guard=0;while(pc<end&&guard++<32){const auto* in=instructionAt(ins,pc);if(!in)return false;if(in->flow==FlowKind::Call||in->flow==FlowKind::Restart||in->flow==FlowKind::Return||in->flow==FlowKind::Halt)return false;const auto w=ConditionSemantics::writtenRegisters(*in);if(w.count("H")||w.count("L")||w.count("HL")||w.count("B")||w.count("BC"))return false;pc=static_cast<std::uint16_t>(pc+in->length());}return pc==end;
}

// Recognize the ROM self-check style nested modular sweep without hard-coding PCs.
// The proof requires the complete counter/guard shape, no external branches into the
// loop headers, a divisor-of-256 low-byte step, a finite high-page limit, and a static
// checksum of zero for every guarded chunk in the supplied ROM bytes.  The resulting
// range is deliberately BOUNDED evidence even though this pattern enumerates every
// member, preserving indirect-address analysis's conservative range-vs-exact closure policy.
bool proveGuardedModuloChecksumSweep(const std::map<std::uint16_t,Instruction>& ins,
                                     std::uint16_t accessPC,const std::vector<std::uint8_t>& program,
                                     const std::map<std::pair<std::uint16_t,std::string>,std::set<std::size_t>>& defIds,
                                     AddressLatticeValue& proof){
    const auto* access=instructionAt(ins,accessPC);if(!access)return false;
    const auto* innerHead=previousInstruction(ins,accessPC);if(!isLd(innerHead,"A","C"))return false;
    const auto* saveC=nextInstruction(ins,access);if(!isLd(saveC,"C","A"))return false;
    const auto* loadL=nextInstruction(ins,saveC);if(!isLd(loadL,"A","L"))return false;
    const auto* addStep=nextInstruction(ins,loadL);std::uint8_t step=0;if(!immediate8(addStep,0xC6,step)||step==0||256u%step!=0)return false;
    const auto* storeL=nextInstruction(ins,addStep);if(!isLd(storeL,"L","A"))return false;
    const auto* cpStep=nextInstruction(ins,storeL);std::uint8_t cpLow=0;if(!immediate8(cpStep,0xFE,cpLow)||cpLow!=step)return false;
    const auto* innerBranch=nextInstruction(ins,cpStep);if(!isBranchTo(innerBranch,"NC",innerHead->address))return false;
    const auto* incH=nextInstruction(ins,innerBranch);if(!isInc(incH,"H"))return false;
    const auto* djnz=nextInstruction(ins,incH);if(!djnz||djnz->mnemonic!="DJNZ"||djnz->target<0)return false;const auto outerHead=static_cast<std::uint16_t>(djnz->target);
    if(outerHead>=innerHead->address||!safePrelude(ins,outerHead,innerHead->address))return false;

    // Exact checksum guard: LD A,C / AND A / branch NZ error.
    const auto* checkC=nextInstruction(ins,djnz);if(!isLd(checkC,"A","C"))return false;
    const auto* andA=nextInstruction(ins,checkC);if(!andA||andA->mnemonic!="AND"||splitOps(andA->operands)!=std::vector<std::string>{"A"})return false;
    const auto* checksumFail=nextInstruction(ins,andA);if(!checksumFail||!checksumFail->conditional)return false;const auto cfops=splitOps(checksumFail->operands);if(cfops.empty()||cfops[0]!="NZ")return false;

    // Allow a small side-effect-only success prelude before the high-byte guard.
    const Instruction* loadH=nullptr;const Instruction* cursor=nextInstruction(ins,checksumFail);for(int i=0;i<5&&cursor;++i){if(isLd(cursor,"A","H")){loadH=cursor;break;}const auto w=ConditionSemantics::writtenRegisters(*cursor);if(cursor->flow==FlowKind::Call||cursor->flow==FlowKind::Restart||w.count("H")||w.count("L")||w.count("HL")||w.count("B")||w.count("BC"))return false;cursor=nextInstruction(ins,cursor);}if(!loadH)return false;
    const auto* cpHigh=nextInstruction(ins,loadH);std::uint8_t highLimit=0;if(!immediate8(cpHigh,0xFE,highLimit)||highLimit==0)return false;
    const auto* highBranch=nextInstruction(ins,cpHigh);if(!highBranch||!highBranch->conditional||highBranch->target<0)return false;const auto hbops=splitOps(highBranch->operands);if(hbops.empty()||hbops[0]!="NZ")return false;const auto resetHead=static_cast<std::uint16_t>(highBranch->target);
    const auto* reset=instructionAt(ins,resetHead);if(!reset||reset->bytes.size()<3||reset->bytes[0]!=0x01||reset->bytes[1]!=0x00)return false;const std::uint8_t pageCount=reset->bytes[2];if(pageCount==0||highLimit%pageCount!=0)return false;
    const auto* initial=previousInstruction(ins,resetHead);if(!initial||initial->bytes.size()<3||initial->bytes[0]!=0x21||initial->bytes[1]!=0x00||initial->bytes[2]!=0x00)return false;
    if(static_cast<std::uint32_t>(highLimit)*256u>program.size())return false;

    // Final residue-step phase: H=0; ++L; if (L < step) restart the high sweep.
    const auto* zeroH=nextInstruction(ins,highBranch);if(!zeroH||zeroH->bytes.size()<2||zeroH->bytes[0]!=0x26||zeroH->bytes[1]!=0x00)return false;
    const auto* incL=nextInstruction(ins,zeroH);if(!isInc(incL,"L"))return false;
    const auto* reloadL=nextInstruction(ins,incL);if(!isLd(reloadL,"A","L"))return false;
    const auto* cpResidue=nextInstruction(ins,reloadL);std::uint8_t cpResidueN=0;if(!immediate8(cpResidue,0xFE,cpResidueN)||cpResidueN!=step)return false;
    const auto* residueBranch=nextInstruction(ins,cpResidue);if(!isBranchTo(residueBranch,"C",resetHead))return false;

    // The reset instruction must flow through a safe prelude to the outer head.
    const auto resetEnd=static_cast<std::uint16_t>(reset->address+reset->length());if(resetEnd>outerHead||!safePrelude(ins,resetEnd,outerHead))return false;

    // Reject external static branch entries that could inject arbitrary counter state.
    std::map<std::uint16_t,std::set<std::uint16_t>> targetSources;for(const auto& kv:ins)if(kv.second.target>=0)targetSources[static_cast<std::uint16_t>(kv.second.target)].insert(kv.first);
    const auto allowedReset=std::set<std::uint16_t>{highBranch->address,residueBranch->address};
    const auto allowedInner=std::set<std::uint16_t>{innerBranch->address};
    const auto allowedOuter=std::set<std::uint16_t>{djnz->address};
    if(targetSources[resetHead]!=allowedReset||targetSources[innerHead->address]!=allowedInner||targetSources[outerHead]!=allowedOuter)return false;

    // Statically validate every checksum-success branch against the loaded ROM bytes.
    // C is reset to zero by LD BC,nn.  Each chunk covers pageCount high-byte pages at
    // one low-byte residue modulo step.
    for(unsigned residue=0;residue<step;++residue){
        for(unsigned highBase=0;highBase<highLimit;highBase+=pageCount){
            std::uint8_t sum=0;for(unsigned h=highBase;h<highBase+pageCount;++h)for(unsigned l=residue;l<256;l+=step){const auto a=(h<<8)|l;if(a>=program.size())return false;sum=static_cast<std::uint8_t>(sum+program[a]);}
            if(sum!=0)return false;
        }
    }

    proof=AddressLatticeValue{};proof.kind=AddressValueKind::ContiguousRange;proof.rangeStart=0;proof.rangeEnd=static_cast<std::uint16_t>(static_cast<unsigned>(highLimit)*256u-1u);proof.stride=1;proof.staticProof=true;proof.dynamicOnly=false;proof.compressedRange=true;proof.hasUnknownAlternative=false;proof.wraparound=false;
    const std::vector<const Instruction*> evidence={initial,reset,access,addStep,storeL,cpStep,innerBranch,incH,djnz,checkC,andA,checksumFail,loadH,cpHigh,highBranch,zeroH,incL,reloadL,cpResidue,residueBranch};
    for(const auto* e:evidence)if(e)proof.provenancePCs.insert(e->address);
    for(const auto* e:evidence)if(e)for(const auto& entity:std::vector<std::string>{"HL","H","L","BC","B","C"}){auto di=defIds.find({e->address,entity});if(di!=defIds.end())proof.originDefinitionIds.insert(di->second.begin(),di->second.end());}
    proof.note="guarded modular checksum sweep: exact counter/branch structure plus static zero-checksum validation proves contiguous address bound $0000-$"+Z80Disassembler::hex16(proof.rangeEnd);
    return true;
}

} // namespace

AddressLatticeValue IndirectAddressAnalysis::exact(std::uint16_t value,std::uint16_t provenancePC){AddressLatticeValue v;v.values.insert(value);v.kind=AddressValueKind::Exact;if(provenancePC)v.provenancePCs.insert(provenancePC);return v;}
AddressLatticeValue IndirectAddressAnalysis::finiteSet(const std::set<std::uint16_t>&values,bool unknownAlternative){AddressLatticeValue v;v.values=values;v.hasUnknownAlternative=unknownAlternative;return classifyKnownValues(v);}

AddressLatticeValue IndirectAddressAnalysis::classifyKnownValues(AddressLatticeValue v){
    if(v.values.empty()){v.kind=AddressValueKind::Unknown;return v;}
    if(v.hasUnknownAlternative){v.kind=AddressValueKind::AmbiguousAlternatives;v.rangeStart=*v.values.begin();v.rangeEnd=*v.values.rbegin();return v;}
    if(v.values.size()==1){v.kind=AddressValueKind::Exact;v.rangeStart=v.rangeEnd=*v.values.begin();v.stride=0;return v;}
    v.rangeStart=*v.values.begin();v.rangeEnd=*v.values.rbegin();if(v.wraparound){v.kind=AddressValueKind::FiniteSet;return v;}
    std::uint16_t prev=*v.values.begin();std::uint16_t stride=0;bool first=true,regular=true;for(auto x:v.values){if(first){first=false;continue;}const std::uint16_t d=static_cast<std::uint16_t>(x-prev);if(stride==0)stride=d;else if(d!=stride)regular=false;prev=x;}
    if(regular&&stride==1){v.kind=AddressValueKind::ContiguousRange;v.stride=1;}
    else if(regular&&stride>1){v.kind=AddressValueKind::StridedRange;v.stride=stride;}
    else v.kind=AddressValueKind::FiniteSet;
    return v;
}

AddressLatticeValue IndirectAddressAnalysis::merge(const AddressLatticeValue&a,const AddressLatticeValue&b,std::size_t maxValues){Fact x;x.known=!a.values.empty();x.unknownAlternative=a.hasUnknownAlternative;x.wraparound=a.wraparound;x.values=a.values;x.originDefinitionIds=a.originDefinitionIds;x.provenancePCs=a.provenancePCs;x.ramOriginAddresses=a.ramOriginAddresses;x.callEvidencePCs=a.callEvidencePCs;Fact y;y.known=!b.values.empty();y.unknownAlternative=b.hasUnknownAlternative;y.wraparound=b.wraparound;y.values=b.values;y.originDefinitionIds=b.originDefinitionIds;y.provenancePCs=b.provenancePCs;y.ramOriginAddresses=b.ramOriginAddresses;y.callEvidencePCs=b.callEvidencePCs;auto m=mergeFact(x,y,maxValues);return toAddressValue(m);}
AddressLatticeValue IndirectAddressAnalysis::shifted(const AddressLatticeValue&v,int delta,unsigned bits){Fact f;f.known=!v.values.empty();f.unknownAlternative=v.hasUnknownAlternative;f.wraparound=v.wraparound;f.values=v.values;f.originDefinitionIds=v.originDefinitionIds;f.provenancePCs=v.provenancePCs;f.ramOriginAddresses=v.ramOriginAddresses;f.callEvidencePCs=v.callEvidencePCs;return toAddressValue(shiftFact(f,delta,bits));}
AddressLatticeValue IndirectAddressAnalysis::added(const AddressLatticeValue&a,const AddressLatticeValue&b,unsigned bits,std::size_t maxValues){Fact x;x.known=!a.values.empty();x.unknownAlternative=a.hasUnknownAlternative;x.wraparound=a.wraparound;x.values=a.values;x.originDefinitionIds=a.originDefinitionIds;x.provenancePCs=a.provenancePCs;Fact y;y.known=!b.values.empty();y.unknownAlternative=b.hasUnknownAlternative;y.wraparound=b.wraparound;y.values=b.values;y.originDefinitionIds=b.originDefinitionIds;y.provenancePCs=b.provenancePCs;return toAddressValue(addFact(x,y,bits,maxValues));}
AddressLatticeValue IndirectAddressAnalysis::combineBytes(const AddressLatticeValue&h,const AddressLatticeValue&l,std::size_t maxValues){Fact x;x.known=!h.values.empty();x.unknownAlternative=h.hasUnknownAlternative;x.values=h.values;x.originDefinitionIds=h.originDefinitionIds;x.provenancePCs=h.provenancePCs;Fact y;y.known=!l.values.empty();y.unknownAlternative=l.hasUnknownAlternative;y.values=l.values;y.originDefinitionIds=l.originDefinitionIds;y.provenancePCs=l.provenancePCs;return toAddressValue(combineFact(x,y,maxValues));}

bool IndirectAddressAnalysis::parseIndirectOperand(const std::string&operand,std::string&reg,int&displacement){
    reg.clear();displacement=0;if(operand=="(HL)"||operand=="(DE)"||operand=="(BC)"){reg=operand.substr(1,2);return true;}if(operand.size()<4||operand.front()!='('||operand.back()!=')')return false;if(operand.rfind("(IX",0)!=0&&operand.rfind("(IY",0)!=0)return false;reg=operand.substr(1,2);const std::string d=operand.substr(3,operand.size()-4);if(d.empty())return true;char*end=nullptr;long v=std::strtol(d.c_str(),&end,10);if(!end||*end!='\0'||v<-128||v>127){reg.clear();return false;}displacement=static_cast<int>(v);return true;
}

std::vector<IndirectMemoryAccessRecord> IndirectAddressAnalysis::analyze(
    const std::map<std::uint16_t,Instruction>&instructions,const std::vector<AddressBlockInput>&blocks,const std::set<std::uint16_t>&rootBlocks,const std::map<std::uint16_t,std::set<std::uint16_t>>&blockOwners,const std::map<std::uint16_t,FunctionRegisterSummary>&functionSummaries,const DefUseResult&defUse,const std::vector<CallBindingRecord>&callBindings,const std::vector<std::uint8_t>&program){
    std::map<std::uint16_t,AddressBlockInput> blockMap;for(const auto&b:blocks)blockMap[b.start]=b;const auto defIds=definitionIds(defUse);

    // Definite returned pointer outputs may seed a caller continuation only when every
    // machine-output source represented by the contract has an exact constant expression.
    std::map<std::pair<std::uint16_t,std::string>,Fact> returned;
    std::map<std::size_t,const ExpressionRecord*> exprByDef;for(const auto&e:defUse.expressions)exprByDef[e.definitionId]=&e;
    for(const auto&cb:callBindings){if(!cb.hasOutputBinding||!cb.provenReturningOutput||cb.postValueKind!=CallPostValueKind::ProducedOutput||!isPair(cb.reg)||cb.outputSourcePCs.empty())continue;Fact f;f.unknownAlternative=false;bool ok=true;for(auto pc:cb.outputSourcePCs){bool found=false;for(const auto&d:defUse.definitions)if(d.instructionAddress==pc&&d.entity==cb.reg){auto ei=exprByDef.find(d.id);if(ei!=exprByDef.end()&&ei->second->exact&&ei->second->constantKnown){f.values.insert(ei->second->constantValue);f.originDefinitionIds.insert(d.id);f.provenancePCs.insert(pc);found=true;}}if(!found){ok=false;break;}}if(ok&&!f.values.empty()){f.known=true;f.fromReturn=true;f.callEvidencePCs.insert(cb.callPC);f.chain="definite routine-contract returned pointer output";returned[{cb.callPC,cb.reg}]=f;}}

    auto attach=[&](Fact&f,std::uint16_t pc,const std::string&r){attachDefIds(f,pc,r,defIds);};
    auto transfer=[&](const Instruction&in,State&s){const auto&b=in.bytes;const auto ops=splitOps(in.operands);
        if(b.size()>=3&&(b[0]==0x01||b[0]==0x11||b[0]==0x21||b[0]==0x31)){const std::string r=b[0]==0x01?"BC":b[0]==0x11?"DE":b[0]==0x21?"HL":"SP";Fact f=exactFact(static_cast<std::uint16_t>(b[1]|(static_cast<std::uint16_t>(b[2])<<8)),in.address);f.chain="LD "+r+",nn";attach(f,in.address,r);setPair(s,r,f);return;}
        if(b.size()>=4&&(b[0]==0xDD||b[0]==0xFD)&&b[1]==0x21){const std::string r=b[0]==0xDD?"IX":"IY";Fact f=exactFact(static_cast<std::uint16_t>(b[2]|(static_cast<std::uint16_t>(b[3])<<8)),in.address);f.chain="LD "+r+",nn";attach(f,in.address,r);setPair(s,r,f);return;}
        std::uint16_t ma=0;std::string mr;bool rd=false,wr=false;if(decodeDirectPairMemory(in,ma,mr,rd,wr)&&isPair(mr)){
            if(rd){if(static_cast<std::size_t>(ma)+1u<program.size()){Fact f=exactFact(static_cast<std::uint16_t>(program[ma]|(static_cast<std::uint16_t>(program[ma+1])<<8)),in.address);f.provenancePCs.insert(ma);f.provenancePCs.insert(static_cast<std::uint16_t>(ma+1));f.chain="direct little-endian ROM pointer load";attach(f,in.address,mr);setPair(s,mr,f);}else if(physicalRam(ma)&&ma!=0xFFFF&&physicalRam(static_cast<std::uint16_t>(ma+1))){auto ri=s.ramPairs.find(ma);if(ri!=s.ramPairs.end()){Fact f=ri->second;f.fromRam=true;f.ramOriginAddresses.insert(ma);f.provenancePCs.insert(in.address);f.chain="direct 16-bit RAM pointer reload";attach(f,in.address,mr);setPair(s,mr,f);}else invalidatePair(s,mr);}else invalidatePair(s,mr);}else if(wr){Fact f=get(s,mr);if(physicalRam(ma)&&ma!=0xFFFF&&physicalRam(static_cast<std::uint16_t>(ma+1))&&f.known){f.ramOriginAddresses.insert(ma);f.provenancePCs.insert(in.address);s.ramPairs[ma]=f;}else if(physicalRam(ma)){s.ramPairs.erase(ma);if(ma>0)s.ramPairs.erase(static_cast<std::uint16_t>(ma-1));}}return;}
        static const std::map<std::uint8_t,std::string> imm8={{0x06,"B"},{0x0E,"C"},{0x16,"D"},{0x1E,"E"},{0x26,"H"},{0x2E,"L"},{0x3E,"A"}};if(!b.empty()){auto ii=imm8.find(b[0]);if(ii!=imm8.end()&&b.size()>=2){Fact f=exactFact(b[1],in.address);f.chain="LD "+ii->second+",n";attach(f,in.address,ii->second);setByte(s,ii->second,f);return;}}
        if(in.mnemonic=="LD"&&ops.size()>=2){const auto&dst=ops[0];const auto&src=ops[1];if(isByte(dst)&&isByte(src)){Fact f=get(s,src);f.provenancePCs.insert(in.address);f.chain="register copy "+src+" -> "+dst;attach(f,in.address,dst);setByte(s,dst,f);return;}if(isPair(dst)&&isPair(src)){Fact f=get(s,src);f.provenancePCs.insert(in.address);f.chain="pair copy "+src+" -> "+dst;attach(f,in.address,dst);setPair(s,dst,f);return;}if(isByte(dst)&&src.size()&&src.front()=='('){invalidateByte(s,dst);return;}}
        if(!b.empty()&&b[0]==0xF9){Fact f=get(s,"HL");f.provenancePCs.insert(in.address);attach(f,in.address,"SP");setPair(s,"SP",f);return;}
        if((in.mnemonic=="INC"||in.mnemonic=="DEC")&&!ops.empty()){const int delta=in.mnemonic=="INC"?1:-1;const auto&r=ops[0];if(isPair(r)){Fact f=shiftFact(get(s,r),delta,16);f.provenancePCs.insert(in.address);attach(f,in.address,r);setPair(s,r,f);return;}if(isByte(r)){Fact f=shiftFact(get(s,r),delta,8);f.provenancePCs.insert(in.address);attach(f,in.address,r);setByte(s,r,f);return;}}
        // Conservative 8-bit value transforms used by real pointer-index construction.
        // These are exact finite-set transforms only; carry-dependent forms widen unless
        // the operation itself is independent of incoming carry.
        if(in.mnemonic=="XOR"&&ops.size()==1&&ops[0]=="A"){Fact f=exactFact(0,in.address);f.chain="XOR A zero idiom";attach(f,in.address,"A");setByte(s,"A",f);return;}
        if(in.mnemonic=="AND"&&ops.size()==1&&ops[0]=="A"){Fact f=get(s,"A");f.provenancePCs.insert(in.address);f.chain="AND A preserves A";setByte(s,"A",f);return;}
        if(!b.empty()&&b[0]==0xE6&&b.size()>=2){Fact f=maskedByteFact(get(s,"A"),b[1],in.address);attach(f,in.address,"A");setByte(s,"A",f);return;}
        if((in.mnemonic=="RLCA"||in.mnemonic=="RRCA")){Fact f=get(s,"A");if(in.mnemonic=="RLCA")f=mapByteFact(f,"RLCA exact rotate",[](std::uint8_t v){return static_cast<std::uint8_t>((v<<1)|(v>>7));});else f=mapByteFact(f,"RRCA exact rotate",[](std::uint8_t v){return static_cast<std::uint8_t>((v>>1)|(v<<7));});f.provenancePCs.insert(in.address);attach(f,in.address,"A");setByte(s,"A",f);return;}
        if(in.mnemonic=="CPL"){Fact f=mapByteFact(get(s,"A"),"CPL exact complement",[](std::uint8_t v){return static_cast<std::uint8_t>(~v);});f.provenancePCs.insert(in.address);attach(f,in.address,"A");setByte(s,"A",f);return;}
        if(in.mnemonic=="ADD"&&ops.size()==2&&ops[0]=="A"){Fact rhs;if(ops[1]=="A")rhs=get(s,"A");else if(isByte(ops[1]))rhs=get(s,ops[1]);else if(!b.empty()&&b[0]==0xC6&&b.size()>=2)rhs=exactFact(b[1],in.address);else rhs=unknown();Fact f=binaryByteFact(get(s,"A"),rhs,"exact finite-set ADD A",[](std::uint8_t x,std::uint8_t y){return static_cast<std::uint8_t>(x+y);});f.provenancePCs.insert(in.address);attach(f,in.address,"A");setByte(s,"A",f);return;}
        if(in.mnemonic=="SUB"&&ops.size()==1){Fact rhs;if(ops[0]=="A")rhs=get(s,"A");else if(isByte(ops[0]))rhs=get(s,ops[0]);else if(!b.empty()&&b[0]==0xD6&&b.size()>=2)rhs=exactFact(b[1],in.address);else rhs=unknown();Fact f=binaryByteFact(get(s,"A"),rhs,"exact finite-set SUB",[](std::uint8_t x,std::uint8_t y){return static_cast<std::uint8_t>(x-y);});f.provenancePCs.insert(in.address);attach(f,in.address,"A");setByte(s,"A",f);return;}
        if(in.mnemonic=="DJNZ"){Fact f=shiftFact(get(s,"B"),-1,8);f.provenancePCs.insert(in.address);attach(f,in.address,"B");setByte(s,"B",f);return;}
        if(in.mnemonic=="EX"&&ops.size()>=2&&((ops[0]=="DE"&&ops[1]=="HL")||(ops[0]=="HL"&&ops[1]=="DE"))){Fact de=get(s,"DE"),hl=get(s,"HL");de.provenancePCs.insert(in.address);hl.provenancePCs.insert(in.address);setPair(s,"DE",hl);setPair(s,"HL",de);return;}
        if(in.mnemonic=="ADD"&&ops.size()==2&&isPair(ops[0])&&isPair(ops[1])){Fact f=addFact(get(s,ops[0]),get(s,ops[1]),16,kInternalStateMaxValues);f.provenancePCs.insert(in.address);attach(f,in.address,ops[0]);setPair(s,ops[0],f);return;}
        if(in.mnemonic=="PUSH"){
            if(s.stackKnown){
                StackSlot slot;
                if(!ops.empty()&&isPair(ops[0])){
                    slot.pair=get(s,ops[0]);
                    const auto bytes=pairBytes(ops[0]);
                    if(!bytes.first.empty()){slot.high=get(s,bytes.first);slot.low=get(s,bytes.second);}
                }
                s.stack.push_back(slot);
            }
            s.ramPairs.clear();return;
        }
        if(in.mnemonic=="POP"){
            if(!ops.empty()&&isPair(ops[0])){
                if(s.stackKnown&&!s.stack.empty()){
                    StackSlot slot=s.stack.back();s.stack.pop_back();
                    slot.pair.fromStack=true;slot.pair.provenancePCs.insert(in.address);slot.pair.chain="proven PUSH/POP pointer restoration";
                    slot.high.fromStack=true;slot.high.provenancePCs.insert(in.address);slot.high.chain="proven PUSH/POP high-byte restoration";
                    slot.low.fromStack=true;slot.low.provenancePCs.insert(in.address);slot.low.chain="proven PUSH/POP low-byte restoration";
                    attach(slot.pair,in.address,ops[0]);
                    if(slot.pair.known){setPair(s,ops[0],slot.pair);}
                    else{
                        const auto bytes=pairBytes(ops[0]);
                        invalidatePair(s,ops[0]);
                        if(!bytes.first.empty()){setByte(s,bytes.first,slot.high);setByte(s,bytes.second,slot.low);}
                    }
                }else invalidatePair(s,ops[0]);
            }else if(s.stackKnown&&!s.stack.empty())s.stack.pop_back();
            return;
        }
        if(in.mnemonic=="LDI"||in.mnemonic=="LDD"){const int d=in.mnemonic=="LDI"?1:-1;setPair(s,"HL",shiftFact(get(s,"HL"),d,16));setPair(s,"DE",shiftFact(get(s,"DE"),d,16));setPair(s,"BC",shiftFact(get(s,"BC"),-1,16));return;}
        if(in.mnemonic=="LDIR"||in.mnemonic=="LDDR"){const int d=in.mnemonic=="LDIR"?1:-1;Fact count=get(s,"BC"),hl=get(s,"HL"),de=get(s,"DE");if(count.known&&count.values.size()==1){const auto n=*count.values.begin();setPair(s,"HL",shiftFact(hl,d*static_cast<int>(n),16));setPair(s,"DE",shiftFact(de,d*static_cast<int>(n),16));setPair(s,"BC",exactFact(0,in.address));}else{invalidatePair(s,"HL");invalidatePair(s,"DE");invalidatePair(s,"BC");}return;}
        if(in.mnemonic=="CPI"||in.mnemonic=="CPD"){const int d=in.mnemonic=="CPI"?1:-1;setPair(s,"HL",shiftFact(get(s,"HL"),d,16));setPair(s,"BC",shiftFact(get(s,"BC"),-1,16));return;}
        if(in.mnemonic=="CPIR"||in.mnemonic=="CPDR"){invalidatePair(s,"HL");invalidatePair(s,"BC");return;}
        invalidateWritten(s,in);
        if(ConditionSemantics::writesMemory(in)){bool direct=false;for(const auto&ref:in.memoryRefs)if(ref.access==RefAccess::Write||ref.access==RefAccess::ReadWrite){direct=true;if(physicalRam(ref.address)){s.ramPairs.erase(ref.address);if(ref.address>0)s.ramPairs.erase(static_cast<std::uint16_t>(ref.address-1));}}if(!direct)s.ramPairs.clear();}
    };

    auto callResult=[&](const Instruction&in,const State&before)->State{State after=before;const auto target=in.target>=0?static_cast<std::uint16_t>(in.target):0;auto si=functionSummaries.find(target);if(in.target<0||si==functionSummaries.end()){for(const auto&p:std::vector<std::string>{"BC","DE","HL","IX","IY","SP"})invalidatePair(after,p);for(const auto&r:std::vector<std::string>{"A"})invalidateByte(after,r);after.ramPairs.clear();after.stackKnown=false;after.stack.clear();return after;}const auto&sum=si->second;for(const auto&p:std::vector<std::string>{"BC","DE","HL","IX","IY","SP"}){if(sum.preserved.count(p)){Fact f=get(after,p);if(f.known){f.acrossCall=true;f.callEvidencePCs.insert(in.address);f.chain="proven callee preservation";setPair(after,p,f);}}else{auto ro=returned.find({in.address,p});if(ro!=returned.end()){Fact f=ro->second;f.provenancePCs.insert(in.address);setPair(after,p,f);}else invalidatePair(after,p);}}if(!sum.preserved.count("A"))invalidateByte(after,"A");if(sum.transitiveUnknownMemoryWrite)after.ramPairs.clear();else for(auto a:sum.transitiveRamMayWrite){after.ramPairs.erase(a);if(a>0)after.ramPairs.erase(static_cast<std::uint16_t>(a-1));}if(!sum.stackBalanced){after.stackKnown=false;after.stack.clear();}return after;};

    std::map<std::uint16_t,State> entry;std::map<std::uint16_t,bool> initialized;std::map<std::uint16_t,std::size_t> updateCounts;std::queue<std::uint16_t>q;auto seed=[&](std::uint16_t b,const State&s){if(!blockMap.count(b))return;const bool was=initialized[b];bool changed=mergeState(entry[b],s,was);if(!was){initialized[b]=true;changed=true;}if(changed){auto& n=updateCounts[b];++n;if(n>8)widenState(entry[b]);q.push(b);}};State root;for(auto b:rootBlocks)seed(b,root);if(q.empty()&&!blocks.empty())seed(blocks.front().start,root);

    std::map<std::tuple<std::uint16_t,std::string,int,int>,AccessAggregate> agg;
    auto record=[&](const Instruction&in,const std::string&operand,const std::string&reg,int disp,IndirectMemoryDirection dir,const Fact&base,bool pathBounded){Fact a=shiftFact(base,disp,16);a.provenancePCs.insert(in.address);auto key=std::make_tuple(in.address,reg,disp,static_cast<int>(dir));auto&x=agg[key];if(!x.initialized){x.pc=in.address;x.operand=operand;x.reg=reg;x.displacement=disp;x.direction=dir;x.addresses=a;x.initialized=true;}else x.addresses=mergeFact(x.addresses,a,kInternalStateMaxValues);x.pathBounded=x.pathBounded||pathBounded;x.throughRam=x.throughRam||a.fromRam;x.throughStack=x.throughStack||a.fromStack;x.acrossCall=x.acrossCall||a.acrossCall;x.fromReturn=x.fromReturn||a.fromReturn;};

    std::size_t guard=0;while(!q.empty()&&guard++<1000000){const auto ba=q.front();q.pop();const auto bi=blockMap.find(ba);if(bi==blockMap.end())continue;State s=entry[ba];State beforeTerminal=s;bool terminalCall=false;const Instruction*terminal=nullptr;
        for(auto pc:bi->second.instructions){auto ii=instructions.find(pc);if(ii==instructions.end())continue;const auto&in=ii->second;for(const auto&t:indirectAccesses(in)){const auto&reg=std::get<0>(t);record(in,std::get<3>(t),reg,std::get<1>(t),std::get<2>(t),get(s,reg),false);}
            if(in.mnemonic=="LDI"||in.mnemonic=="LDD")record(in,"(HL)","HL",0,IndirectMemoryDirection::Read,get(s,"HL"),false);
            if(in.mnemonic=="LDIR"||in.mnemonic=="LDDR"||in.mnemonic=="CPIR"||in.mnemonic=="CPDR"){
                const Fact base=get(s,"HL"),count=get(s,"BC");if(base.known&&count.known&&base.values.size()==1&&count.values.size()==1&&!base.unknownAlternative&&!count.unknownAlternative){const auto n=*count.values.begin();if(n>0&&n<=512){Fact addresses;addresses.known=true;addresses.unknownAlternative=false;addresses.originDefinitionIds=base.originDefinitionIds;addresses.originDefinitionIds.insert(count.originDefinitionIds.begin(),count.originDefinitionIds.end());addresses.provenancePCs=base.provenancePCs;addresses.provenancePCs.insert(count.provenancePCs.begin(),count.provenancePCs.end());addresses.provenancePCs.insert(in.address);const int d=(in.mnemonic=="LDIR"||in.mnemonic=="CPIR")?1:-1;for(std::uint32_t k=0;k<n;++k){const long raw=static_cast<long>(*base.values.begin())+d*static_cast<long>(k);if(raw<0||raw>65535)addresses.wraparound=true;addresses.values.insert(static_cast<std::uint16_t>(raw&0xFFFF));}addresses.chain="bounded block repeat from exact BC count";record(in,"(HL repeated)","HL",0,IndirectMemoryDirection::Read,addresses,true);}else record(in,"(HL repeated)","HL",0,IndirectMemoryDirection::Read,base,false);}
            }
            if(in.flow==FlowKind::Call||in.flow==FlowKind::Restart){beforeTerminal=s;terminalCall=true;terminal=&in;break;}transfer(in,s);terminal=&in;}
        for(const auto&e:bi->second.outgoing){if(e.to<0)continue;if(terminalCall&&terminal){if(e.kind==AddressFlowEdgeKind::Call||e.kind==AddressFlowEdgeKind::Restart||e.kind==AddressFlowEdgeKind::Dispatch){State callee=beforeTerminal;callee.stackKnown=false;callee.stack.clear();seed(static_cast<std::uint16_t>(e.to),callee);continue;}State post=callResult(*terminal,beforeTerminal);if(terminal->conditional){State m=beforeTerminal;mergeState(m,post,true);post=m;}seed(static_cast<std::uint16_t>(e.to),post);continue;}State edge=s;if(terminal&&terminal->mnemonic=="DJNZ"){if(e.kind==AddressFlowEdgeKind::BranchTaken){Fact b=filterByte(get(edge,"B"),true);setByte(edge,"B",b);}else if(e.kind==AddressFlowEdgeKind::BranchNotTaken){Fact b=filterByte(get(edge,"B"),false);setByte(edge,"B",b);}}
            // Branch-local equality filtering for the common exact CP n -> Z/NZ shape.
            // The fact is applied only to the corresponding outgoing edge and is never
            // promoted globally.  This is sufficient to preserve finite switch/index
            // sets such as AND $03 / CP $03 / JR NZ without inventing a general ABI.
            if(terminal&&terminal->conditional&&bi->second.instructions.size()>=2){const auto pit=instructions.find(bi->second.instructions[bi->second.instructions.size()-2]);if(pit!=instructions.end()){const auto&prod=pit->second;if(prod.mnemonic=="CP"&&prod.bytes.size()>=2&&prod.bytes[0]==0xFE){const auto tops=splitOps(terminal->operands);if(!tops.empty()&&(tops[0]=="Z"||tops[0]=="NZ")){const bool branchTaken=e.kind==AddressFlowEdgeKind::BranchTaken;const bool wantsEqual=tops[0]=="Z";const bool equalOnEdge=branchTaken?wantsEqual:!wantsEqual;Fact a=filterByteEquality(get(edge,"A"),prod.bytes[1],equalOnEdge);a.provenancePCs.insert(prod.address);a.provenancePCs.insert(terminal->address);setByte(edge,"A",a);}}}}
            seed(static_cast<std::uint16_t>(e.to),edge);}
    }

    std::vector<IndirectMemoryAccessRecord>out;for(auto&kv:agg){auto&x=kv.second;IndirectMemoryAccessRecord r;r.id=out.size();r.pc=x.pc;r.operand=x.operand;r.addressRegister=x.reg;r.displacement=x.displacement;r.direction=x.direction;r.address=toAddressValue(x.addresses);auto bo=blockOwners.find(x.pc);if(bo!=blockOwners.end())r.functionOwners=bo->second;r.pathBounded=x.pathBounded;r.throughRamPointer=x.throughRam;r.throughStackRestore=x.throughStack;r.acrossPreservedCall=x.acrossCall;r.fromDefiniteCallOutput=x.fromReturn;r.arithmeticChain=x.addresses.chain;r.note="indirect-address analysis static abstract interpretation of indirect effective address; unknown alternatives and call/merge provenance remain explicit";out.push_back(r);}
    // Strengthen only when an independently proven finite sweep contains every
    // already-known alternative.  This prevents a recognizer from contradicting a
    // more local exact fact while allowing cyclic worklist widening to be recovered.
    for(auto& r:out)if(r.addressRegister=="HL"&&r.displacement==0&&r.direction!=IndirectMemoryDirection::Write){AddressLatticeValue sweep;if(proveGuardedModuloChecksumSweep(instructions,r.pc,program,defIds,sweep)){bool compatible=true;for(auto v:r.address.values)if(v<sweep.rangeStart||v>sweep.rangeEnd){compatible=false;break;}if(compatible){r.address=sweep;r.pathBounded=true;r.arithmeticChain=sweep.note;r.note="indirect-address analysis exact guarded-loop recognizer replaced cyclic widening with a statically validated compressed contiguous range";}}}
    return out;
}

std::vector<IndirectRomConsumerProofRecord> IndirectAddressAnalysis::synthesizeRomConsumers(const std::vector<IndirectMemoryAccessRecord>&accesses,std::size_t romSize,std::vector<RomConsumerRecord>&consumers){
    std::vector<IndirectRomConsumerProofRecord>out;for(const auto&a:accesses){if(a.direction==IndirectMemoryDirection::Write)continue;IndirectRomConsumerProofRecord base;base.id=out.size();base.accessId=a.id;base.pc=a.pc;base.originDefinitionIds=a.address.originDefinitionIds;base.provenancePCs=a.address.provenancePCs;base.ramOriginAddresses=a.address.ramOriginAddresses;base.callEvidencePCs=a.address.callEvidencePCs;base.exactAddressSet=a.address.values;
        if(!a.address.staticProof||a.address.dynamicOnly){base.note="dynamic-only effective address retained as diagnostic evidence; runtime observation is not static range proof";out.push_back(base);continue;}
        if(a.address.hasUnknownAlternative){base.note="known alternatives coexist with an unknown effective-address alternative";out.push_back(base);continue;}
        if(a.address.compressedRange&&(a.address.kind==AddressValueKind::ContiguousRange||a.address.kind==AddressValueKind::StridedRange)){
            base.rangeBased=true;base.stride=a.address.stride?a.address.stride:1;base.start=a.address.rangeStart;const auto hi=a.address.rangeEnd;if(hi>=romSize){base.mixedNonRomAlternatives=true;base.note="proven compressed address range crosses outside ROM; retained as diagnostic evidence only";out.push_back(base);continue;}if(hi==0xFFFF){base.note="compressed range ends at $FFFF and cannot be represented by the exclusive 16-bit ROM-consumer end field";out.push_back(base);continue;}base.end=static_cast<std::uint16_t>(hi+1);base.bounded=true;base.accepted=true;base.note="statically proven compressed all-ROM address range; admitted as bounded consumer evidence only";RomConsumerRecord c;c.pc=a.pc;c.start=base.start;c.end=base.end;c.kind=RomConsumerKind::IndirectRegisterRead;c.pointerRegister=a.addressRegister;c.bounded=true;c.note="indirect-address analysis compressed finite-range indirect ROM proof; bounded closure only";consumers.push_back(c);out.push_back(base);continue;
        }
        if(a.address.values.empty()){base.note="no finite static effective address";out.push_back(base);continue;}bool allRom=true;for(auto v:a.address.values)if(v>=romSize){allRom=false;break;}if(!allRom){base.mixedNonRomAlternatives=true;base.note="effective-address alternatives include non-ROM memory; retained as diagnostic evidence only";out.push_back(base);continue;}
        if(a.address.values.size()==1){const auto v=*a.address.values.begin();base.start=v;base.end=static_cast<std::uint16_t>(v+1);base.exact=true;base.accepted=true;base.note="single exact static indirect ROM effective address";RomConsumerRecord c;c.pc=a.pc;c.start=base.start;c.end=base.end;c.kind=RomConsumerKind::IndirectRegisterRead;c.pointerRegister=a.addressRegister;c.exact=true;c.note="indirect-address analysis exact indirect-address proof; see indirect ROM consumer provenance";consumers.push_back(c);out.push_back(base);continue;}
        // A finite alternative set is bounded evidence, not proof that every alternative is
        // visited. Emit one singleton bound per member so gaps are never silently claimed.
        base.start=*a.address.values.begin();const auto hi=*a.address.values.rbegin();base.end=hi==0xFFFF?0xFFFF:static_cast<std::uint16_t>(hi+1);base.bounded=true;base.accepted=true;base.note="finite all-ROM static address alternatives; each member is emitted as a singleton bounded consumer so gaps remain unresolved";for(auto v:a.address.values){RomConsumerRecord c;c.pc=a.pc;c.start=v;c.end=static_cast<std::uint16_t>(v+1);c.kind=RomConsumerKind::IndirectRegisterRead;c.pointerRegister=a.addressRegister;c.bounded=true;c.note="indirect-address analysis finite-set indirect ROM address member; possible static access, not definite execution";consumers.push_back(c);}out.push_back(base);
    }for(std::size_t i=0;i<out.size();++i)out[i].id=i;return out;
}

std::vector<IndirectAddressClosureProvenanceRecord> IndirectAddressAnalysis::applyClosureOverlay(
    const std::vector<RomByteClosureRecord>&baseline,const std::vector<IndirectRomConsumerProofRecord>&proofs,std::vector<RomByteClosureRecord>&overlay){
    overlay=baseline;
    for(const auto&p:proofs)if(p.accepted){
        if(p.exact){for(std::size_t a=p.start;a<p.end&&a<overlay.size();++a){if(a<baseline.size()&&baseline[a].primary!=RomClosurePrimary::Unresolved)continue;overlay[a].staticExactDataUse=true;overlay[a].consumerPCs.insert(p.pc);}}
        else if(p.bounded){if(p.rangeBased){for(std::size_t a=p.start;a<p.end&&a<overlay.size();a+=p.stride?p.stride:1){if(a<baseline.size()&&baseline[a].primary!=RomClosurePrimary::Unresolved)continue;overlay[a].boundedConsumer=true;overlay[a].consumerPCs.insert(p.pc);}}else for(auto a:p.exactAddressSet)if(a<overlay.size()){if(a<baseline.size()&&baseline[a].primary!=RomClosurePrimary::Unresolved)continue;overlay[a].boundedConsumer=true;overlay[a].consumerPCs.insert(p.pc);}}
    }
    for(auto&b:overlay)b.primary=RomClosure::classify(b);
    std::vector<IndirectAddressClosureProvenanceRecord>out;
    for(std::size_t a=0;a<overlay.size()&&a<baseline.size();++a){
        if(baseline[a].primary!=RomClosurePrimary::Unresolved||overlay[a].primary==RomClosurePrimary::Unresolved)continue;
        IndirectAddressClosureProvenanceRecord r;r.address=static_cast<std::uint16_t>(a);r.exact=overlay[a].staticExactDataUse&&!baseline[a].staticExactDataUse;r.bounded=!r.exact&&overlay[a].boundedConsumer&&!baseline[a].boundedConsumer;
        for(const auto&p:proofs)if(p.accepted&&((p.exact&&a>=p.start&&a<p.end)||(p.bounded&&((p.rangeBased&&a>=p.start&&a<p.end&&((a-p.start)%(p.stride?p.stride:1)==0))||(!p.rangeBased&&p.exactAddressSet.count(static_cast<std::uint16_t>(a))))))){r.consumerProofIds.insert(p.id);r.accessIds.insert(p.accessId);r.accessPCs.insert(p.pc);r.originDefinitionIds.insert(p.originDefinitionIds.begin(),p.originDefinitionIds.end());r.provenancePCs.insert(p.provenancePCs.begin(),p.provenancePCs.end());}
        r.note="indirect-address analysis closure delta is backed only by accepted static indirect-address proof records listed here";out.push_back(r);
    }
    return out;
}

IndirectAddressStats IndirectAddressAnalysis::stats(const std::vector<IndirectMemoryAccessRecord>&accesses,const std::vector<IndirectRomConsumerProofRecord>&consumers){IndirectAddressStats s;s.indirectAccesses=accesses.size();for(const auto&a:accesses){switch(a.address.kind){case AddressValueKind::Exact:++s.exactAddresses;break;case AddressValueKind::FiniteSet:++s.finiteSetAddresses;break;case AddressValueKind::ContiguousRange:case AddressValueKind::StridedRange:++s.rangeAddresses;break;case AddressValueKind::AmbiguousAlternatives:++s.ambiguousAddresses;break;case AddressValueKind::Unknown:++s.unknownAddresses;break;}if(a.throughRamPointer)++s.ramReloadAddresses;if(a.throughStackRestore)++s.stackRestoreAddresses;if(a.acrossPreservedCall)++s.preservedCallAddresses;if(a.fromDefiniteCallOutput)++s.returnedOutputAddresses;}for(const auto&c:consumers){if(c.accepted){++s.acceptedRomConsumers;if(c.exact)++s.exactRomConsumers;if(c.bounded)++s.boundedRomConsumers;}if(c.mixedNonRomAlternatives)++s.rejectedMixedAddressConsumers;}return s;}

std::string IndirectAddressAnalysis::kindText(AddressValueKind kind){switch(kind){case AddressValueKind::Unknown:return"unknown";case AddressValueKind::Exact:return"exact";case AddressValueKind::FiniteSet:return"finite-set";case AddressValueKind::ContiguousRange:return"contiguous-range";case AddressValueKind::StridedRange:return"strided-range";case AddressValueKind::AmbiguousAlternatives:return"ambiguous-alternatives";}return"unknown";}
std::string IndirectAddressAnalysis::directionText(IndirectMemoryDirection d){switch(d){case IndirectMemoryDirection::Read:return"read";case IndirectMemoryDirection::Write:return"write";case IndirectMemoryDirection::ReadWrite:return"read/write";}return"read";}

} // namespace pacripper
