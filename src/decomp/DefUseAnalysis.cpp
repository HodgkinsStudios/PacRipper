// PacRipper def-use analysis def-use / expression reconstruction
// Created by Jacob Hodgkins

#include "DefUseAnalysis.h"
#include "ConditionSemantics.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <functional>
#include <iomanip>
#include <limits>
#include <queue>
#include <sstream>

namespace pacripper {
namespace {

struct DefPlan {
    std::string entity;
    unsigned bits=0;
    DefExpressionKind op=DefExpressionKind::Unknown;
    std::vector<DefOperandSpec> operands;
    bool exact=false;
    bool callClobber=false;
    bool aliasInvalidation=false;
    std::string note;
    std::size_t id=std::numeric_limits<std::size_t>::max();
};

struct InstructionEffect {
    std::uint16_t address=0;
    std::set<std::string> uses;
    std::vector<DefPlan> defs;
    bool killAllMemory=false;
    std::set<std::string> memoryKills;
};

using State=std::map<std::string,ReachingDefinitionFact>;

std::string h16(std::uint16_t v){std::ostringstream o;o<<'$'<<std::uppercase<<std::hex<<std::setw(4)<<std::setfill('0')<<(unsigned)v;return o.str();}
std::string h8(std::uint8_t v){std::ostringstream o;o<<'$'<<std::uppercase<<std::hex<<std::setw(2)<<std::setfill('0')<<(unsigned)v;return o.str();}

std::string trim(std::string s){
    while(!s.empty()&&std::isspace(static_cast<unsigned char>(s.front())))s.erase(s.begin());
    while(!s.empty()&&std::isspace(static_cast<unsigned char>(s.back())))s.pop_back();
    return s;
}

std::vector<std::string> splitOps(const std::string& text){
    std::vector<std::string> out;std::string cur;int depth=0;
    for(char c:text){
        if(c=='(')++depth; else if(c==')')--depth;
        if(c==','&&depth==0){out.push_back(trim(cur));cur.clear();}
        else cur+=c;
    }
    if(!cur.empty()||!text.empty())out.push_back(trim(cur));
    return out;
}

bool isReg8(const std::string& r){return r=="A"||r=="B"||r=="C"||r=="D"||r=="E"||r=="H"||r=="L";}
bool isReg16(const std::string& r){return r=="BC"||r=="DE"||r=="HL"||r=="SP"||r=="IX"||r=="IY";}
unsigned bitsFor(const std::string& r){return isReg8(r)?8u:16u;}

std::string pairForByte(const std::string& r){
    if(r=="B"||r=="C")return "BC";
    if(r=="D"||r=="E")return "DE";
    if(r=="H"||r=="L")return "HL";
    return {};
}
std::pair<std::string,std::string> componentsForPair(const std::string& r){
    if(r=="BC")return {"B","C"};
    if(r=="DE")return {"D","E"};
    if(r=="HL")return {"H","L"};
    return {};
}

DefOperandSpec entityOp(const std::string& e,unsigned bits=0){DefOperandSpec o;o.entity=e;o.bits=bits?bits:bitsFor(e);return o;}
DefOperandSpec constOp(std::uint16_t v,unsigned bits){DefOperandSpec o;o.constant=true;o.constantValue=v;o.bits=bits;return o;}

void addDef(InstructionEffect& e,const std::string& entity,unsigned bits,DefExpressionKind op,
            const std::vector<DefOperandSpec>& operands,bool exact,const std::string& note={},
            bool callClobber=false,bool aliasInvalidation=false){
    DefPlan d;d.entity=entity;d.bits=bits;d.op=op;d.operands=operands;d.exact=exact;d.note=note;d.callClobber=callClobber;d.aliasInvalidation=aliasInvalidation;e.defs.push_back(d);
    for(const auto& o:operands)if(!o.constant&&!o.entity.empty())e.uses.insert(o.entity);
}

void addUnknownDef(InstructionEffect& e,const std::string& entity,unsigned bits,const std::string& note,bool call=false,bool alias=false){
    addDef(e,entity,bits,DefExpressionKind::Unknown,{},false,note,call,alias);
}

void addByteDefWithAlias(InstructionEffect& e,const std::string& reg,DefExpressionKind op,const std::vector<DefOperandSpec>& operands,bool exact,const std::string& note={}){
    addDef(e,reg,8,op,operands,exact,note);
    const auto p=pairForByte(reg);if(!p.empty())addUnknownDef(e,p,16,"8-bit component write invalidates composite pair value",false,true);
}

void addPairDefWithComponents(InstructionEffect& e,const std::string& pair,DefExpressionKind op,const std::vector<DefOperandSpec>& operands,bool exact,const std::string& note={}){
    addDef(e,pair,16,op,operands,exact,note);
    const auto c=componentsForPair(pair);if(c.first.empty())return;
    if(op==DefExpressionKind::Constant&&!operands.empty()&&operands[0].constant){
        const auto v=operands[0].constantValue;
        addDef(e,c.first,8,DefExpressionKind::Constant,{constOp(static_cast<std::uint8_t>(v>>8),8)},true,"high byte of exact pair constant");
        addDef(e,c.second,8,DefExpressionKind::Constant,{constOp(static_cast<std::uint8_t>(v),8)},true,"low byte of exact pair constant");
    }else if(op==DefExpressionKind::Copy&&!operands.empty()){
        addDef(e,c.first,8,DefExpressionKind::HighByte,operands,exact,"high byte follows exact pair definition");
        addDef(e,c.second,8,DefExpressionKind::LowByte,operands,exact,"low byte follows exact pair definition");
    }else{
        addUnknownDef(e,c.first,8,"pair write changes component; exact byte expression not reconstructed",false,true);
        addUnknownDef(e,c.second,8,"pair write changes component; exact byte expression not reconstructed",false,true);
    }
}

bool directAddress(const Instruction& in,std::uint16_t& address,RefAccess wanted){
    for(const auto& r:in.memoryRefs){
        const bool match=(wanted==RefAccess::Read&&(r.access==RefAccess::Read||r.access==RefAccess::ReadWrite))||
                         (wanted==RefAccess::Write&&(r.access==RefAccess::Write||r.access==RefAccess::ReadWrite));
        if(match){address=r.address;return true;}
    }
    return false;
}

std::string pointerRegFromMemoryOperand(const std::string& op){
    if(op=="(HL)")return "HL";
    if(op=="(DE)")return "DE";
    if(op=="(BC)")return "BC";
    if(op.size()>=3&&op[0]=='('&&op[1]=='I'&&(op[2]=='X'||op[2]=='Y'))return op.substr(1,2);
    return {};
}

bool isMemoryOperand(const std::string& op){return !op.empty()&&op.front()=='('&&op.back()==')';}

bool decodeDirectPairMemory(const Instruction& in,std::uint16_t& address,std::string& pair,bool& read,bool& write){
    const auto& b=in.bytes;read=write=false;
    if(b.size()>=3&&(b[0]==0x2A||b[0]==0x22)){
        address=static_cast<std::uint16_t>(b[1]|(static_cast<std::uint16_t>(b[2])<<8));pair="HL";read=b[0]==0x2A;write=!read;return true;
    }
    if(b.size()>=4&&b[0]==0xED&&(b[1]==0x4B||b[1]==0x5B||b[1]==0x6B||b[1]==0x7B||b[1]==0x43||b[1]==0x53||b[1]==0x63||b[1]==0x73)){
        address=static_cast<std::uint16_t>(b[2]|(static_cast<std::uint16_t>(b[3])<<8));
        const auto op=b[1];pair=(op==0x4B||op==0x43)?"BC":(op==0x5B||op==0x53)?"DE":(op==0x6B||op==0x63)?"HL":"SP";
        read=(op&0x08)!=0;write=!read;return true;
    }
    if(b.size()>=4&&(b[0]==0xDD||b[0]==0xFD)&&(b[1]==0x2A||b[1]==0x22)){
        address=static_cast<std::uint16_t>(b[2]|(static_cast<std::uint16_t>(b[3])<<8));pair=b[0]==0xDD?"IX":"IY";read=b[1]==0x2A;write=!read;return true;
    }
    return false;
}

InstructionEffect makeEffect(const Instruction& in,const std::map<std::uint16_t,FunctionEffectInput>& functions,std::size_t romSize){
    InstructionEffect e;e.address=in.address;const auto ops=splitOps(in.operands);const auto& b=in.bytes;

    // Calls/restarts are barriers according to recovered machine-level callee summaries only.
    if(in.flow==FlowKind::Call||in.flow==FlowKind::Restart){
        const FunctionEffectInput* fx=nullptr;
        if(in.target>=0){auto it=functions.find(static_cast<std::uint16_t>(in.target));if(it!=functions.end())fx=&it->second;}
        for(const auto& r:DefUseAnalysis::trackedRegisters()){
            if(fx&&fx->preservedRegisters.count(r))continue;
            addUnknownDef(e,r,bitsFor(r),fx?"callee may write this value according to object/pointer dataflow machine effects":"unknown call/restart target effects",true,false);
        }
        if(fx){for(auto a:fx->ramMayWrite){if(DefUseAnalysis::isPhysicalRam(a))e.memoryKills.insert(DefUseAnalysis::ram8Entity(a));}e.killAllMemory=fx->unknownMemoryWrite;}
        else e.killAllMemory=true;
        return e;
    }

    // Exact pair immediate loads.
    if(b.size()>=3&&(b[0]==0x01||b[0]==0x11||b[0]==0x21||b[0]==0x31)){
        const std::uint16_t v=static_cast<std::uint16_t>(b[1]|(static_cast<std::uint16_t>(b[2])<<8));const std::string r=b[0]==0x01?"BC":b[0]==0x11?"DE":b[0]==0x21?"HL":"SP";
        addPairDefWithComponents(e,r,DefExpressionKind::Constant,{constOp(v,16)},true,"16-bit immediate load");return e;
    }
    if(b.size()>=4&&(b[0]==0xDD||b[0]==0xFD)&&b[1]==0x21){
        const std::uint16_t v=static_cast<std::uint16_t>(b[2]|(static_cast<std::uint16_t>(b[3])<<8));const std::string r=b[0]==0xDD?"IX":"IY";
        addDef(e,r,16,DefExpressionKind::Constant,{constOp(v,16)},true,"indexed 16-bit immediate load");return e;
    }

    // Exact direct 16-bit memory transfers.
    std::uint16_t pairAddr=0;std::string pair;bool pairRead=false,pairWrite=false;
    if(decodeDirectPairMemory(in,pairAddr,pair,pairRead,pairWrite)){
        if(pairRead){
            if(pairAddr<romSize){
                addPairDefWithComponents(e,pair,DefExpressionKind::IndirectMemoryRead,{constOp(pairAddr,16)},true,"direct 16-bit ROM read");
            }else if(DefUseAnalysis::isPhysicalRam(pairAddr)&&DefUseAnalysis::isPhysicalRam(static_cast<std::uint16_t>(pairAddr+1))){
                const auto mem=DefUseAnalysis::ram16Entity(pairAddr);addPairDefWithComponents(e,pair,DefExpressionKind::DirectMemoryRead,{entityOp(mem,16)},true,"direct 16-bit RAM read");
            }else addPairDefWithComponents(e,pair,DefExpressionKind::IndirectMemoryRead,{constOp(pairAddr,16)},true,"direct 16-bit memory read");
        }else{
            e.uses.insert(pair);
            if(DefUseAnalysis::isPhysicalRam(pairAddr)&&DefUseAnalysis::isPhysicalRam(static_cast<std::uint16_t>(pairAddr+1))){
                const auto word=DefUseAnalysis::ram16Entity(pairAddr),lo=DefUseAnalysis::ram8Entity(pairAddr),hi=DefUseAnalysis::ram8Entity(static_cast<std::uint16_t>(pairAddr+1));
                addDef(e,word,16,DefExpressionKind::Copy,{entityOp(pair,16)},true,"direct Z80 16-bit RAM store");
                addDef(e,lo,8,DefExpressionKind::LowByte,{entityOp(pair,16)},true,"low byte of direct 16-bit RAM store");
                addDef(e,hi,8,DefExpressionKind::HighByte,{entityOp(pair,16)},true,"high byte of direct 16-bit RAM store");
            }else e.killAllMemory=true;
        }
        return e;
    }

    // Common 8-bit immediates.
    static const std::map<std::uint8_t,std::string> imm8={{0x06,"B"},{0x0E,"C"},{0x16,"D"},{0x1E,"E"},{0x26,"H"},{0x2E,"L"},{0x3E,"A"}};
    if(!b.empty()){auto it=imm8.find(b[0]);if(it!=imm8.end()&&b.size()>=2){addByteDefWithAlias(e,it->second,DefExpressionKind::Constant,{constOp(b[1],8)},true,"8-bit immediate load");return e;}}
    if(!b.empty()&&b[0]==0xAF){addByteDefWithAlias(e,"A",DefExpressionKind::Constant,{constOp(0,8)},true,"XOR A is exactly zero");return e;}

    // Generic LD captures register copies and direct/indirect memory reads/writes.
    if(in.mnemonic=="LD"&&ops.size()>=2){
        const auto& dst=ops[0];const auto& src=ops[1];
        if(isReg8(dst)){
            if(isReg8(src)){addByteDefWithAlias(e,dst,DefExpressionKind::Copy,{entityOp(src,8)},true,"8-bit register copy");return e;}
            if(isMemoryOperand(src)){
                std::uint16_t a=0;
                if(directAddress(in,a,RefAccess::Read)){
                    if(DefUseAnalysis::isPhysicalRam(a))addByteDefWithAlias(e,dst,DefExpressionKind::DirectMemoryRead,{entityOp(DefUseAnalysis::ram8Entity(a),8)},true,"exact direct RAM byte read");
                    else addByteDefWithAlias(e,dst,DefExpressionKind::IndirectMemoryRead,{constOp(a,16)},true,a<romSize?"exact direct ROM byte read":"exact direct memory byte read");
                }else{
                    const auto p=pointerRegFromMemoryOperand(src);if(!p.empty())addByteDefWithAlias(e,dst,DefExpressionKind::IndirectMemoryRead,{entityOp(p,16)},true,"indirect byte read with pointer provenance");
                    else addUnknownDef(e,dst,8,"memory addressing form not reconstructed exactly");
                }
                return e;
            }
        }
        if(isReg16(dst)&&isReg16(src)){addDef(e,dst,16,DefExpressionKind::Copy,{entityOp(src,16)},true,"16-bit register copy");return e;}
        if(isMemoryOperand(dst)&&isReg8(src)){
            std::uint16_t a=0;
            if(directAddress(in,a,RefAccess::Write)&&DefUseAnalysis::isPhysicalRam(a))addDef(e,DefUseAnalysis::ram8Entity(a),8,DefExpressionKind::Copy,{entityOp(src,8)},true,"exact direct RAM byte store");
            else {e.uses.insert(src);e.killAllMemory=true;}
            return e;
        }
    }

    // INC/DEC 8-bit and pair operations.
    if((in.mnemonic=="INC"||in.mnemonic=="DEC")&&!ops.empty()){
        const auto& r=ops[0];const auto op=in.mnemonic=="INC"?DefExpressionKind::Increment:DefExpressionKind::Decrement;
        if(isReg8(r)){addByteDefWithAlias(e,r,op,{entityOp(r,8)},true,"exact modular 8-bit increment/decrement");return e;}
        if(isReg16(r)){if(r=="BC"||r=="DE"||r=="HL")addPairDefWithComponents(e,r,op,{entityOp(r,16)},true,"exact modular 16-bit increment/decrement");else addDef(e,r,16,op,{entityOp(r,16)},true,"exact modular 16-bit increment/decrement");return e;}
        if(isMemoryOperand(r)){e.killAllMemory=true;return e;}
    }
    if(in.mnemonic=="DJNZ"){addByteDefWithAlias(e,"B",DefExpressionKind::Decrement,{entityOp("B",8)},true,"DJNZ decrements B before testing");return e;}

    if(in.mnemonic=="EX"&&ops.size()>=2&&((ops[0]=="DE"&&ops[1]=="HL")||(ops[0]=="HL"&&ops[1]=="DE"))){
        addPairDefWithComponents(e,"DE",DefExpressionKind::Copy,{entityOp("HL",16)},true,"EX DE,HL swap");
        addPairDefWithComponents(e,"HL",DefExpressionKind::Copy,{entityOp("DE",16)},true,"EX DE,HL swap");return e;
    }
    if(!b.empty()&&b[0]==0xF9){addDef(e,"SP",16,DefExpressionKind::Copy,{entityOp("HL",16)},true,"LD SP,HL");return e;}

    // 16-bit addition. Carry-producing flag side effects do not change the modular value.
    if(in.mnemonic=="ADD"&&ops.size()==2&&isReg16(ops[0])&&isReg16(ops[1])){
        if(ops[0]=="BC"||ops[0]=="DE"||ops[0]=="HL")addPairDefWithComponents(e,ops[0],DefExpressionKind::Add16,{entityOp(ops[0],16),entityOp(ops[1],16)},true,"exact modular 16-bit add");
        else addDef(e,ops[0],16,DefExpressionKind::Add16,{entityOp(ops[0],16),entityOp(ops[1],16)},true,"exact modular 16-bit add");
        return e;
    }

    // 8-bit arithmetic/logical value reconstruction. ADC/SBC remain conservative because carry provenance is separate.
    auto aBinary=[&](DefExpressionKind op,const DefOperandSpec& rhs,const std::string& note){addByteDefWithAlias(e,"A",op,{entityOp("A",8),rhs},true,note);};
    if((in.mnemonic=="ADD"||in.mnemonic=="SUB"||in.mnemonic=="AND"||in.mnemonic=="OR"||in.mnemonic=="XOR")&&!ops.empty()){
        DefOperandSpec rhs;bool have=false;
        const std::string src=ops.size()>=2?ops.back():ops[0];
        if(isReg8(src)){rhs=entityOp(src,8);have=true;}
        else if(isMemoryOperand(src)){const auto p=pointerRegFromMemoryOperand(src);if(!p.empty()){ // memory-source arithmetic is exact only if the dereference can later be reconstructed; represent as unknown for now.
                e.uses.insert("A");e.uses.insert(p);addUnknownDef(e,"A",8,"memory-source arithmetic needs a separately materialized load expression");return e;}}
        if(!have&&b.size()>=2){const std::uint8_t op=b[0];if(op==0xC6||op==0xD6||op==0xE6||op==0xEE||op==0xF6){rhs=constOp(b[1],8);have=true;}}
        if(have){DefExpressionKind k=DefExpressionKind::Unknown;if(in.mnemonic=="ADD")k=DefExpressionKind::Add;else if(in.mnemonic=="SUB")k=DefExpressionKind::Subtract;else if(in.mnemonic=="AND")k=DefExpressionKind::BitAnd;else if(in.mnemonic=="OR")k=DefExpressionKind::BitOr;else if(in.mnemonic=="XOR")k=DefExpressionKind::BitXor;aBinary(k,rhs,"exact modular 8-bit arithmetic/logical value");return e;}
    }
    if(in.mnemonic=="ADC"||in.mnemonic=="SBC"){e.uses.insert("A");addUnknownDef(e,"A",8,"carry-dependent arithmetic not lifted without an exact carry-value dependency");return e;}

    if(in.mnemonic=="PUSH"){
        if(!ops.empty()){const auto r=ops[0];if(r=="AF")e.uses.insert("A");else if(isReg16(r))e.uses.insert(r);}
        addDef(e,"SP",16,DefExpressionKind::Subtract,{entityOp("SP",16),constOp(2,16)},true,"PUSH decrements SP by two");e.killAllMemory=true;return e;
    }
    if(in.mnemonic=="POP"){
        if(!ops.empty()){const auto r=ops[0];if(r=="AF")addUnknownDef(e,"A",8,"POP AF value originates from stack memory");else if(isReg16(r))addPairDefWithComponents(e,r,DefExpressionKind::Unknown,{},false,"POP pair value originates from stack memory");}
        addDef(e,"SP",16,DefExpressionKind::Add,{entityOp("SP",16),constOp(2,16)},true,"POP increments SP by two");return e;
    }

    // Generic conservative write fallback. This catches prefixed/rare instructions without guessing their expression.
    const auto writes=ConditionSemantics::writtenRegisters(in);
    for(const auto& r:writes){
        if(isReg8(r))addByteDefWithAlias(e,r,DefExpressionKind::Unknown,{},false,"instruction writes register but def-use analysis has no exact expression transfer");
        else if(isReg16(r)){if(r=="BC"||r=="DE"||r=="HL")addPairDefWithComponents(e,r,DefExpressionKind::Unknown,{},false,"instruction writes pair but def-use analysis has no exact expression transfer");else addUnknownDef(e,r,16,"instruction writes register but def-use analysis has no exact expression transfer");}
    }
    if(ConditionSemantics::writesMemory(in)){
        bool exactWrite=false;std::uint16_t a=0;if(directAddress(in,a,RefAccess::Write)&&DefUseAnalysis::isPhysicalRam(a))exactWrite=true;
        if(!exactWrite)e.killAllMemory=true;
    }
    return e;
}

bool sameFact(const ReachingDefinitionFact& a,const ReachingDefinitionFact& b){
    return a.definitionIds==b.definitionIds&&a.includesEntryValue==b.includesEntryValue&&a.includesClobberedUnknown==b.includesClobberedUnknown&&a.unknownSourceAddresses==b.unknownSourceAddresses;
}

ReachingDefinitionFact entryFact(){ReachingDefinitionFact f;f.includesEntryValue=true;return f;}
ReachingDefinitionFact defFact(std::size_t id){ReachingDefinitionFact f;f.definitionIds.insert(id);return f;}
ReachingDefinitionFact clobberedFact(std::uint16_t pc){ReachingDefinitionFact f;f.includesClobberedUnknown=true;f.unknownSourceAddresses.insert(pc);return f;}

ReachingDefinitionFact mergeFact(const ReachingDefinitionFact& a,const ReachingDefinitionFact& b){
    ReachingDefinitionFact r=a;r.definitionIds.insert(b.definitionIds.begin(),b.definitionIds.end());r.includesEntryValue=r.includesEntryValue||b.includesEntryValue;r.includesClobberedUnknown=r.includesClobberedUnknown||b.includesClobberedUnknown;r.unknownSourceAddresses.insert(b.unknownSourceAddresses.begin(),b.unknownSourceAddresses.end());
    // Bound pathological loop ambiguity while retaining the fact that ambiguity exists.
    if(r.definitionIds.size()>64){r.definitionIds.clear();r.includesClobberedUnknown=true;}
    if(r.unknownSourceAddresses.size()>32){auto it=r.unknownSourceAddresses.begin();std::advance(it,32);r.unknownSourceAddresses.erase(it,r.unknownSourceAddresses.end());}
    return r;
}

bool mergeState(State& dst,const State& src,const std::set<std::string>& universe,bool initialized){
    if(!initialized){dst=src;return true;}bool changed=false;
    for(const auto& e:universe){
        const auto ai=dst.find(e);
        const auto bi=src.find(e);
        const auto a=ai==dst.end()?entryFact():ai->second;
        const auto b=bi==src.end()?entryFact():bi->second;
        const auto m=mergeFact(a,b);
        if(ai==dst.end()||!sameFact(ai->second,m)){dst[e]=m;changed=true;}
    }
    return changed;
}

void applyEffect(const InstructionEffect& e,State& s,const std::set<std::string>& memoryUniverse){
    if(e.killAllMemory)for(const auto& m:memoryUniverse)s[m]=clobberedFact(e.address);
    for(const auto& m:e.memoryKills)s[m]=clobberedFact(e.address);
    for(const auto& d:e.defs)s[d.entity]=defFact(d.id);
}

std::set<std::string> memoryEntities(const std::set<std::string>& universe){std::set<std::string> out;for(const auto& e:universe)if(e.rfind("RAM",0)==0)out.insert(e);return out;}

struct BuiltExpr {
    bool exact=false;
    bool ambiguous=false;
    bool constantKnown=false;
    std::uint16_t constantValue=0;
    std::set<std::uint16_t> provenance;
    std::set<std::string> entities;
    std::set<std::size_t> objects;
    bool objectAware=false;
    bool memoryAddressKnown=false;
    std::uint16_t memoryAddress=0;
    std::string text;
    std::string note;
};

std::uint16_t modular(std::uint32_t v,unsigned bits){return static_cast<std::uint16_t>(bits==8?(v&0xFFu):(v&0xFFFFu));}

} // namespace

const std::set<std::string>& DefUseAnalysis::trackedRegisters(){
    static const std::set<std::string> r={"A","B","C","D","E","H","L","BC","DE","HL","SP","IX","IY"};return r;
}
bool DefUseAnalysis::isTrackedRegister(const std::string& entity){return trackedRegisters().count(entity)>0;}
bool DefUseAnalysis::isPhysicalRam(std::uint16_t a){return (a>=0x4000&&a<=0x47FF)||(a>=0x4C00&&a<=0x4FFF);}
std::string DefUseAnalysis::ram8Entity(std::uint16_t a){return "RAM8:"+h16(a);}
std::string DefUseAnalysis::ram16Entity(std::uint16_t a){return "RAM16:"+h16(a);}
std::string DefUseAnalysis::expressionKindText(DefExpressionKind k){
    switch(k){case DefExpressionKind::EntryValue:return"entry";case DefExpressionKind::Constant:return"constant";case DefExpressionKind::Copy:return"copy";case DefExpressionKind::Add:return"add";case DefExpressionKind::Subtract:return"subtract";case DefExpressionKind::BitAnd:return"and";case DefExpressionKind::BitOr:return"or";case DefExpressionKind::BitXor:return"xor";case DefExpressionKind::Increment:return"increment";case DefExpressionKind::Decrement:return"decrement";case DefExpressionKind::Add16:return"add16";case DefExpressionKind::DirectMemoryRead:return"direct-memory-read";case DefExpressionKind::IndirectMemoryRead:return"indirect-memory-read";case DefExpressionKind::HighByte:return"high-byte";case DefExpressionKind::LowByte:return"low-byte";case DefExpressionKind::Unknown:return"unknown";}return"unknown";
}

DefUseResult DefUseAnalysis::analyze(const std::map<std::uint16_t,Instruction>& instructions,
                                     const std::vector<DefUseBlockInput>& inputBlocks,
                                     const std::map<std::uint16_t,FunctionEffectInput>& functions,
                                     const std::vector<RomObjectView>& romObjects,
                                     std::size_t romSize){
    DefUseResult result;

    std::map<std::uint16_t,DefUseBlockInput> blocks;
    std::set<std::uint16_t> ignored;
    for(const auto& b:inputBlocks){if(!b.staticProof){ignored.insert(b.start);continue;}blocks[b.start]=b;}
    for(auto& kv:blocks){for(auto it=kv.second.successors.begin();it!=kv.second.successors.end();){if(!blocks.count(*it))it=kv.second.successors.erase(it);else ++it;}}

    std::map<std::uint16_t,InstructionEffect> effects;
    std::set<std::string> universe=trackedRegisters();
    std::set<std::uint16_t> analyzedInstructions;
    for(const auto& bk:blocks)for(auto pc:bk.second.instructions){auto ii=instructions.find(pc);if(ii==instructions.end())continue;auto e=makeEffect(ii->second,functions,romSize);effects[pc]=e;analyzedInstructions.insert(pc);for(const auto& u:e.uses)universe.insert(u);for(const auto& d:e.defs)universe.insert(d.entity);for(const auto& m:e.memoryKills)universe.insert(m);}

    // Word/byte aliases are part of the tracked universe. Add invalidations after all direct memory entities are known.
    std::set<std::string> memUniverse=memoryEntities(universe);
    for(auto& ek:effects){auto& e=ek.second;std::vector<DefPlan> extra;
        for(const auto& d:e.defs){
            if(d.entity.rfind("RAM8:",0)==0){
                const auto pos=d.entity.find('$');if(pos!=std::string::npos){const auto v=static_cast<std::uint16_t>(std::strtoul(d.entity.c_str()+pos+1,nullptr,16));
                    for(const auto a:{v,static_cast<std::uint16_t>(v==0?0:v-1)}){const auto w=ram16Entity(a);if(memUniverse.count(w)){DefPlan q;q.entity=w;q.bits=16;q.op=DefExpressionKind::Unknown;q.exact=false;q.aliasInvalidation=true;q.note="overlapping byte store invalidates 16-bit RAM reaching value";extra.push_back(q);}}
                }
            }
        }
        e.defs.insert(e.defs.end(),extra.begin(),extra.end());
    }
    // New alias definitions do not introduce new entity names beyond the existing word universe.

    // Assign stable definition IDs and materialize definition records.
    for(auto& ek:effects){auto ii=instructions.find(ek.first);const std::string source=ii==instructions.end()?std::string():ii->second.text();for(auto& d:ek.second.defs){d.id=result.definitions.size();DefinitionRecord r;r.id=d.id;r.instructionAddress=ek.first;r.entity=d.entity;r.bits=d.bits;r.sourceInstruction=source;r.operation=d.op;r.operands=d.operands;r.semanticExact=d.exact;r.callBoundaryClobber=d.callClobber;r.aliasInvalidation=d.aliasInvalidation;r.note=d.note;result.definitions.push_back(r);}}

    // Predecessors restricted to accepted static function-local blocks.
    std::map<std::uint16_t,std::set<std::uint16_t>> preds;
    for(const auto& bk:blocks)for(auto s:bk.second.successors)if(blocks.count(s)&&blocks.at(s).functionEntry==bk.second.functionEntry)preds[s].insert(bk.first);

    std::map<std::uint16_t,State> entryStates,exitStates;
    std::map<std::uint16_t,bool> initialized;
    std::queue<std::uint16_t> q;
    auto seedEntry=[&](std::uint16_t ba){State s;for(const auto& e:universe)s[e]=entryFact();entryStates[ba]=s;initialized[ba]=true;q.push(ba);};
    std::set<std::uint16_t> functionsSeen;
    for(const auto& bk:blocks){if(bk.first==bk.second.functionEntry){seedEntry(bk.first);functionsSeen.insert(bk.second.functionEntry);}}
    // Conservatively analyze isolated accepted blocks as independent entry contexts rather than inventing predecessors.
    for(const auto& bk:blocks)if(!initialized[bk.first]&&preds[bk.first].empty()){seedEntry(bk.first);functionsSeen.insert(bk.second.functionEntry);}

    std::size_t guard=0;
    while(!q.empty()&&guard++<1000000){const auto ba=q.front();q.pop();auto bi=blocks.find(ba);if(bi==blocks.end())continue;State s=entryStates[ba];for(auto pc:bi->second.instructions){auto ei=effects.find(pc);if(ei!=effects.end())applyEffect(ei->second,s,memUniverse);}const bool exitChanged=!exitStates.count(ba)||exitStates[ba]!=s;exitStates[ba]=s;if(!exitChanged&&guard>blocks.size())continue;for(auto succ:bi->second.successors){auto si=blocks.find(succ);if(si==blocks.end()||si->second.functionEntry!=bi->second.functionEntry)continue;const bool was=initialized[succ];const bool changed=mergeState(entryStates[succ],s,universe,was);if(!was){initialized[succ]=true;}if(changed||!was)q.push(succ);}}

    // Replay final reaching states at each instruction and capture uses/source definitions.
    for(const auto& bk:blocks){if(!initialized[bk.first])continue;State s=entryStates[bk.first];for(auto pc:bk.second.instructions){auto ei=effects.find(pc);if(ei==effects.end())continue;result.stateBeforeInstruction[pc]=s;for(const auto& u:ei->second.uses){UseRecord ur;ur.instructionAddress=pc;ur.entity=u;auto f=s.find(u);ur.reaching=f==s.end()?entryFact():f->second;result.uses.push_back(ur);}for(auto& d:ei->second.defs){auto& rec=result.definitions[d.id];for(const auto& op:d.operands)if(!op.constant&&!op.entity.empty()){auto f=s.find(op.entity);const auto fact=f==s.end()?entryFact():f->second;rec.reachingOperands[op.entity]=fact;rec.sourceDefinitionIds.insert(fact.definitionIds.begin(),fact.definitionIds.end());}}applyEffect(ei->second,s,memUniverse);result.stateAfterInstruction[pc]=s;}}

    // Standard backwards liveness over the same static graph. Unknown memory writes kill all tracked exact cells.
    std::map<std::uint16_t,std::set<std::string>> blockUse,blockDef,liveIn,liveOut;
    for(const auto& bk:blocks){std::set<std::string> use,def;for(auto pc:bk.second.instructions){auto ei=effects.find(pc);if(ei==effects.end())continue;for(const auto& u:ei->second.uses)if(!def.count(u))use.insert(u);if(ei->second.killAllMemory)def.insert(memUniverse.begin(),memUniverse.end());def.insert(ei->second.memoryKills.begin(),ei->second.memoryKills.end());for(const auto& d:ei->second.defs)def.insert(d.entity);}blockUse[bk.first]=use;blockDef[bk.first]=def;}
    bool liveChanged=true;guard=0;while(liveChanged&&guard++<100000){liveChanged=false;for(auto it=blocks.rbegin();it!=blocks.rend();++it){const auto ba=it->first;std::set<std::string> out;for(auto s:it->second.successors)if(blocks.count(s)&&blocks.at(s).functionEntry==it->second.functionEntry){out.insert(liveIn[s].begin(),liveIn[s].end());}std::set<std::string> in=blockUse[ba];for(const auto& x:out)if(!blockDef[ba].count(x))in.insert(x);if(out!=liveOut[ba]||in!=liveIn[ba]){liveOut[ba]=out;liveIn[ba]=in;liveChanged=true;}}}
    for(const auto& bk:blocks){std::set<std::string> live=liveOut[bk.first];for(auto ri=bk.second.instructions.rbegin();ri!=bk.second.instructions.rend();++ri){auto ei=effects.find(*ri);if(ei==effects.end())continue;LivenessRecord lr;lr.instructionAddress=*ri;lr.liveAfter=live;std::set<std::string> defs;if(ei->second.killAllMemory)defs.insert(memUniverse.begin(),memUniverse.end());defs.insert(ei->second.memoryKills.begin(),ei->second.memoryKills.end());for(const auto& d:ei->second.defs)defs.insert(d.entity);for(const auto& d:defs)live.erase(d);live.insert(ei->second.uses.begin(),ei->second.uses.end());lr.liveBefore=live;result.liveness[*ri]=lr;}}

    // Recursive expression reconstruction over the now-stable reaching-definition graph.
    std::map<std::size_t,BuiltExpr> memo;std::set<std::size_t> active;
    std::function<BuiltExpr(const std::string&,const ReachingDefinitionFact&)> resolveFact;
    std::function<BuiltExpr(std::size_t)> buildDefinition;

    auto entryExpression=[&](const std::string& entity)->BuiltExpr{BuiltExpr x;x.exact=true;x.entities.insert(entity);if(entity.rfind("RAM8:",0)==0){x.text="RAM_"+entity.substr(entity.find('$')+1)+"@entry";}else if(entity.rfind("RAM16:",0)==0){x.text="RAM16_"+entity.substr(entity.find('$')+1)+"@entry";}else x.text="entry_"+entity;return x;};

    resolveFact=[&](const std::string& entity,const ReachingDefinitionFact& f)->BuiltExpr{
        if(f.exactDefinition())return buildDefinition(*f.definitionIds.begin());
        if(f.exactEntryValue())return entryExpression(entity);
        BuiltExpr x;x.ambiguous=f.ambiguous();x.entities.insert(entity);x.provenance.insert(f.unknownSourceAddresses.begin(),f.unknownSourceAddresses.end());
        std::vector<std::string> alternatives;
        if(f.includesEntryValue)alternatives.push_back(entryExpression(entity).text);
        for(auto id:f.definitionIds){auto y=buildDefinition(id);x.provenance.insert(y.provenance.begin(),y.provenance.end());x.entities.insert(y.entities.begin(),y.entities.end());if(!y.text.empty())alternatives.push_back(y.text);}
        if(f.includesClobberedUnknown)alternatives.push_back("unknown_clobber");
        if(x.ambiguous&&!alternatives.empty()){std::ostringstream o;o<<"phi(";for(std::size_t i=0;i<alternatives.size();++i){if(i)o<<", ";o<<alternatives[i];}o<<")";x.text=o.str();x.note="multiple reaching definitions remain; expression is intentionally non-exact";}else{x.text="unknown("+entity+")";x.note="value was clobbered or could not be proven";}
        return x;
    };

    buildDefinition=[&](std::size_t id)->BuiltExpr{
        auto mi=memo.find(id);if(mi!=memo.end())return mi->second;BuiltExpr x;if(id>=result.definitions.size()){x.text="unknown";return x;}if(active.count(id)){x.ambiguous=true;x.text="cyclic_def";x.note="loop-carried definition cycle";return x;}active.insert(id);const auto& d=result.definitions[id];x.provenance.insert(d.instructionAddress);x.entities.insert(d.entity);
        std::vector<BuiltExpr> args;for(const auto& op:d.operands){if(op.constant){BuiltExpr a;a.exact=true;a.constantKnown=true;a.constantValue=modular(op.constantValue,op.bits?op.bits:d.bits);a.text=op.bits==8?h8(static_cast<std::uint8_t>(a.constantValue)):h16(a.constantValue);args.push_back(a);}else{auto fi=d.reachingOperands.find(op.entity);const auto fact=fi==d.reachingOperands.end()?entryFact():fi->second;args.push_back(resolveFact(op.entity,fact));}}
        for(const auto& a:args){x.provenance.insert(a.provenance.begin(),a.provenance.end());x.entities.insert(a.entities.begin(),a.entities.end());x.objects.insert(a.objects.begin(),a.objects.end());x.ambiguous=x.ambiguous||a.ambiguous;}
        const bool argsExact=std::all_of(args.begin(),args.end(),[](const BuiltExpr& a){return a.exact;});x.exact=d.semanticExact&&argsExact&&!x.ambiguous;
        auto binary=[&](const char* op){if(args.size()<2)return std::string("unknown");return "("+args[0].text+" "+op+" "+args[1].text+")";};
        switch(d.operation){
            case DefExpressionKind::Constant:if(!args.empty()){x.text=args[0].text;x.constantKnown=args[0].constantKnown;x.constantValue=args[0].constantValue;}break;
            case DefExpressionKind::Copy:if(!args.empty()){x.text=args[0].text;x.constantKnown=args[0].constantKnown;x.constantValue=args[0].constantValue;}break;
            case DefExpressionKind::Add:case DefExpressionKind::Add16:x.text=binary("+");break;
            case DefExpressionKind::Subtract:x.text=binary("-");break;
            case DefExpressionKind::BitAnd:x.text=binary("&");break;
            case DefExpressionKind::BitOr:x.text=binary("|");break;
            case DefExpressionKind::BitXor:x.text=binary("^");break;
            case DefExpressionKind::Increment:if(!args.empty())x.text="("+args[0].text+" + 1)";break;
            case DefExpressionKind::Decrement:if(!args.empty())x.text="("+args[0].text+" - 1)";break;
            case DefExpressionKind::HighByte:if(!args.empty())x.text="high8("+args[0].text+")";break;
            case DefExpressionKind::LowByte:if(!args.empty())x.text="low8("+args[0].text+")";break;
            case DefExpressionKind::DirectMemoryRead:if(!args.empty())x.text=args[0].text;break;
            case DefExpressionKind::IndirectMemoryRead:{
                if(args.empty()){x.text="unknown_memory_read";x.exact=false;break;}const auto& p=args[0];
                if(p.constantKnown){const auto a=p.constantValue;x.memoryAddressKnown=true;x.memoryAddress=a;if(a<romSize){
                        std::vector<const RomObjectView*> candidates;for(const auto& o:romObjects)if(!o.dynamicOnly&&a>=o.start&&a<o.end)candidates.push_back(&o);
                        if(candidates.size()==1&&candidates[0]->entrySize){const auto* o=candidates[0];const std::size_t off=static_cast<std::size_t>(a-o->start),index=off/o->entrySize,field=off%o->entrySize;std::ostringstream z;z<<"ROM_OBJECT_"<<o->id<<"["<<index<<"]";if(field)z<<".byte_"<<field;x.text=z.str();x.objectAware=true;x.objects.insert(o->id);}else{x.text=(d.bits==16?"ROM16[":"ROM[")+h16(a)+"]";for(const auto* o:candidates)x.objects.insert(o->id);}x.exact=p.exact;
                    }else if(isPhysicalRam(a))x.text=(d.bits==16?"RAM16[":"RAM[")+h16(a)+"]";else x.text="MEM["+h16(a)+"]";
                }else{x.text="MEM["+p.text+"]";x.exact=p.exact;}
                break;}
            case DefExpressionKind::EntryValue:x.text="entry_"+d.entity;x.exact=true;break;
            case DefExpressionKind::Unknown:default:x.text="unknown("+d.entity+")";x.exact=false;break;
        }
        if(x.exact&&args.size()>=1){
            if(d.operation==DefExpressionKind::Increment&&args[0].constantKnown){x.constantKnown=true;x.constantValue=modular(static_cast<std::uint32_t>(args[0].constantValue)+1,d.bits);}
            else if(d.operation==DefExpressionKind::Decrement&&args[0].constantKnown){x.constantKnown=true;x.constantValue=modular(static_cast<std::uint32_t>(args[0].constantValue)-1,d.bits);}
            else if(d.operation==DefExpressionKind::HighByte&&args[0].constantKnown){x.constantKnown=true;x.constantValue=static_cast<std::uint8_t>(args[0].constantValue>>8);}
            else if(d.operation==DefExpressionKind::LowByte&&args[0].constantKnown){x.constantKnown=true;x.constantValue=static_cast<std::uint8_t>(args[0].constantValue);}
            else if(args.size()>=2&&args[0].constantKnown&&args[1].constantKnown){std::uint32_t v=0;bool ok=true;switch(d.operation){case DefExpressionKind::Add:case DefExpressionKind::Add16:v=args[0].constantValue+args[1].constantValue;break;case DefExpressionKind::Subtract:v=args[0].constantValue-args[1].constantValue;break;case DefExpressionKind::BitAnd:v=args[0].constantValue&args[1].constantValue;break;case DefExpressionKind::BitOr:v=args[0].constantValue|args[1].constantValue;break;case DefExpressionKind::BitXor:v=args[0].constantValue^args[1].constantValue;break;default:ok=false;break;}if(ok){x.constantKnown=true;x.constantValue=modular(v,d.bits);}}
        }
        if(!d.note.empty())x.note=d.note;
        active.erase(id);memo[id]=x;return x;
    };

    for(const auto& d:result.definitions){const auto x=buildDefinition(d.id);ExpressionRecord r;r.definitionId=d.id;r.instructionAddress=d.instructionAddress;r.entity=d.entity;r.bits=d.bits;r.operation=d.operation;r.exact=x.exact;r.ambiguous=x.ambiguous;r.constantKnown=x.constantKnown;r.constantValue=x.constantValue;r.objectAware=x.objectAware;r.memoryAddressKnown=x.memoryAddressKnown;r.memoryAddress=x.memoryAddress;r.romObjectIds=x.objects;r.provenance=x.provenance;r.referencedEntities=x.entities;r.text=x.text;r.note=x.note;result.expressions.push_back(r);}

    // Stats are deliberately descriptive; they do not alter Analyzer classification truth.
    result.stats.analyzedFunctions=functionsSeen.size();result.stats.analyzedBlocks=blocks.size();result.stats.analyzedInstructions=analyzedInstructions.size();result.stats.definitions=result.definitions.size();result.stats.uses=result.uses.size();
    for(const auto& u:result.uses){if(u.reaching.exactDefinition()||u.reaching.exactEntryValue())++result.stats.exactUses;if(u.reaching.ambiguous())++result.stats.ambiguousUses;}
    for(const auto& e:result.expressions){if(e.exact)++result.stats.exactExpressions;if(e.ambiguous)++result.stats.ambiguousExpressions;if(e.objectAware)++result.stats.objectAwareExpressions;if(e.exact&&e.operation==DefExpressionKind::IndirectMemoryRead&&e.text.rfind("ROM",0)==0)++result.stats.exactRomReads;}
    for(const auto& ek:effects)if(instructions.count(ek.first)&&(instructions.at(ek.first).flow==FlowKind::Call||instructions.at(ek.first).flow==FlowKind::Restart)){
        const auto& in=instructions.at(ek.first);const FunctionEffectInput* fx=nullptr;if(in.target>=0){auto fi=functions.find(static_cast<std::uint16_t>(in.target));if(fi!=functions.end())fx=&fi->second;}
        if(fx)result.stats.callPreservedFacts+=fx->preservedRegisters.size();
        for(const auto& d:ek.second.defs)if(d.callClobber)++result.stats.callClobberedFacts;
    }
    return result;
}

} // namespace pacripper
