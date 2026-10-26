// PacRipper semantic-lift engine recompilable semantic-lift foundation
// Created by Jacob Hodgkins

#include "SemanticLiftEngine.h"

#include <algorithm>
#include <iomanip>
#include <map>
#include <sstream>
#include <utility>

namespace pacripper {
namespace {

std::string h8(std::uint8_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(2)<<std::setfill('0')<<(unsigned)v;return o.str();}
std::string h16(std::uint16_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(4)<<std::setfill('0')<<(unsigned)v;return o.str();}

bool pairOperand(const std::string& op){return op=="BC"||op=="DE"||op=="HL"||op=="SP"||op=="IX"||op=="IY";}
std::string firstOperand(const std::string& operands){const auto p=operands.find(',');return p==std::string::npos?operands:operands.substr(0,p);}

SemanticKind classifyKind(const Instruction& in){
    const std::string& m=in.mnemonic;
    if(m=="NOP")return SemanticKind::Nop;
    if(m=="LD")return pairOperand(firstOperand(in.operands))?SemanticKind::Load16:SemanticKind::Load8;
    if(m=="INC")return pairOperand(firstOperand(in.operands))?SemanticKind::Increment16:SemanticKind::Increment8;
    if(m=="DEC")return pairOperand(firstOperand(in.operands))?SemanticKind::Decrement16:SemanticKind::Decrement8;
    if(m=="ADD")return (in.operands.rfind("HL,",0)==0||in.operands.rfind("IX,",0)==0||in.operands.rfind("IY,",0)==0)?SemanticKind::Add16:SemanticKind::Add8;
    if(m=="ADC")return SemanticKind::AddCarry8;
    if(m=="SUB")return SemanticKind::Subtract8;
    if(m=="SBC")return in.operands.rfind("HL,",0)==0?SemanticKind::SubtractCarry16:SemanticKind::SubtractCarry8;
    if(m=="AND")return SemanticKind::And8;
    if(m=="XOR")return SemanticKind::Xor8;
    if(m=="OR")return SemanticKind::Or8;
    if(m=="CP")return SemanticKind::Compare8;
    if(m=="RLCA"||m=="RRCA"||m=="RLA"||m=="RRA")return SemanticKind::RotateAccumulator;
    if(m=="RLC"||m=="RRC"||m=="RL"||m=="RR"||m=="SLA"||m=="SRA"||m=="SLL"||m=="SRL")return SemanticKind::RotateShift;
    if(m=="BIT")return SemanticKind::BitTest;
    if(m=="SET")return SemanticKind::BitSet;
    if(m=="RES")return SemanticKind::BitReset;
    if(m=="DAA")return SemanticKind::DecimalAdjust;
    if(m=="CPL")return SemanticKind::ComplementAccumulator;
    if(m=="SCF")return SemanticKind::SetCarry;
    if(m=="CCF")return SemanticKind::ComplementCarry;
    if(m=="JP")return SemanticKind::Jump;
    if(m=="JR")return SemanticKind::RelativeJump;
    if(m=="DJNZ")return SemanticKind::Djnz;
    if(m=="CALL")return SemanticKind::Call;
    if(m=="RET"||m=="RETI"||m=="RETN")return SemanticKind::Return;
    if(m=="RST")return SemanticKind::Restart;
    if(m=="PUSH")return SemanticKind::Push;
    if(m=="POP")return SemanticKind::Pop;
    if(m=="EX")return SemanticKind::Exchange;
    if(m=="EXX")return SemanticKind::ExchangeAlternate;
    if(m=="HALT")return SemanticKind::Halt;
    if(m=="DI")return SemanticKind::InterruptDisable;
    if(m=="EI")return SemanticKind::InterruptEnable;
    if(m=="IM")return SemanticKind::InterruptMode;
    if(m=="IN")return SemanticKind::IoRead;
    if(m=="OUT")return SemanticKind::IoWrite;
    return SemanticKind::Unsupported;
}

bool encodingSupported(const Instruction& in){
    if(in.bytes.empty())return false;
    const auto b0=in.bytes[0];
    if(b0==0xED){
        if(in.bytes.size()<2)return false;
        switch(in.bytes[1]){
            case 0x42:case 0x52:case 0x62:case 0x72:
            case 0x4A:case 0x5A:case 0x6A:case 0x7A:
            case 0x43:case 0x53:case 0x63:case 0x73:
            case 0x4B:case 0x5B:case 0x6B:case 0x7B:
            case 0x47:
            case 0x46:case 0x4E:case 0x56:case 0x5E:case 0x66:case 0x6E:case 0x76:case 0x7E:
                return true;
            default:return false;
        }
    }
    if(b0==0xDD||b0==0xFD){
        if(in.bytes.size()<2)return false;
        switch(in.bytes[1]){
            case 0x19:case 0x21:case 0x23:case 0x36:case 0x46:case 0x5E:case 0x66:case 0x6E:
            case 0x77:case 0x7E:case 0x86:case 0xE1:case 0xE5:case 0xCB:return true;
            default:return false;
        }
    }
    return true; // complete unprefixed + CB execution core below
}

std::uint16_t getBC(const SemanticMachineState&s){return static_cast<std::uint16_t>((s.b<<8)|s.c);}
std::uint16_t getDE(const SemanticMachineState&s){return static_cast<std::uint16_t>((s.d<<8)|s.e);}
std::uint16_t getHL(const SemanticMachineState&s){return static_cast<std::uint16_t>((s.h<<8)|s.l);}
std::uint16_t getAF(const SemanticMachineState&s){return static_cast<std::uint16_t>((s.a<<8)|s.f);}
void setBC(SemanticMachineState&s,std::uint16_t v){s.b=static_cast<std::uint8_t>(v>>8);s.c=static_cast<std::uint8_t>(v);}
void setDE(SemanticMachineState&s,std::uint16_t v){s.d=static_cast<std::uint8_t>(v>>8);s.e=static_cast<std::uint8_t>(v);}
void setHL(SemanticMachineState&s,std::uint16_t v){s.h=static_cast<std::uint8_t>(v>>8);s.l=static_cast<std::uint8_t>(v);}
void setAF(SemanticMachineState&s,std::uint16_t v){s.a=static_cast<std::uint8_t>(v>>8);s.f=static_cast<std::uint8_t>(v);}

void addEffect(SemanticExecutionState&st,SemanticEffectKind kind,std::uint16_t address,std::uint8_t value,std::uint16_t pc){
    SemanticEffect e;e.sequence=st.effects.size();e.kind=kind;e.address=address;e.value=value;e.sourcePC=pc;st.effects.push_back(e);
}
std::uint8_t read8(SemanticExecutionState&st,std::uint16_t address,std::uint16_t pc){const auto v=st.cpu.memory[address];addEffect(st,SemanticEffectKind::MemoryRead,address,v,pc);return v;}
void write8(SemanticExecutionState&st,std::uint16_t address,std::uint8_t value,std::uint16_t pc){st.cpu.memory[address]=value;addEffect(st,SemanticEffectKind::MemoryWrite,address,value,pc);}
std::uint16_t read16(SemanticExecutionState&st,std::uint16_t address,std::uint16_t pc){const auto lo=read8(st,address,pc);const auto hi=read8(st,static_cast<std::uint16_t>(address+1),pc);return static_cast<std::uint16_t>(lo|(hi<<8));}
void write16(SemanticExecutionState&st,std::uint16_t address,std::uint16_t value,std::uint16_t pc){write8(st,address,static_cast<std::uint8_t>(value),pc);write8(st,static_cast<std::uint16_t>(address+1),static_cast<std::uint8_t>(value>>8),pc);}
void push16(SemanticExecutionState&st,std::uint16_t value,std::uint16_t pc){st.cpu.sp=static_cast<std::uint16_t>(st.cpu.sp-1);write8(st,st.cpu.sp,static_cast<std::uint8_t>(value>>8),pc);st.cpu.sp=static_cast<std::uint16_t>(st.cpu.sp-1);write8(st,st.cpu.sp,static_cast<std::uint8_t>(value),pc);}
std::uint16_t pop16(SemanticExecutionState&st,std::uint16_t pc){const auto lo=read8(st,st.cpu.sp,pc);st.cpu.sp=static_cast<std::uint16_t>(st.cpu.sp+1);const auto hi=read8(st,st.cpu.sp,pc);st.cpu.sp=static_cast<std::uint16_t>(st.cpu.sp+1);return static_cast<std::uint16_t>(lo|(hi<<8));}

std::uint8_t readReg8(SemanticExecutionState&st,unsigned r,std::uint16_t pc){
    switch(r&7u){case 0:return st.cpu.b;case 1:return st.cpu.c;case 2:return st.cpu.d;case 3:return st.cpu.e;case 4:return st.cpu.h;case 5:return st.cpu.l;case 6:return read8(st,getHL(st.cpu),pc);default:return st.cpu.a;}
}
void writeReg8(SemanticExecutionState&st,unsigned r,std::uint8_t v,std::uint16_t pc){
    switch(r&7u){case 0:st.cpu.b=v;break;case 1:st.cpu.c=v;break;case 2:st.cpu.d=v;break;case 3:st.cpu.e=v;break;case 4:st.cpu.h=v;break;case 5:st.cpu.l=v;break;case 6:write8(st,getHL(st.cpu),v,pc);break;default:st.cpu.a=v;break;}
}
std::uint16_t getRP(const SemanticMachineState&s,unsigned p){switch(p&3u){case 0:return getBC(s);case 1:return getDE(s);case 2:return getHL(s);default:return s.sp;}}
void setRP(SemanticMachineState&s,unsigned p,std::uint16_t v){switch(p&3u){case 0:setBC(s,v);break;case 1:setDE(s,v);break;case 2:setHL(s,v);break;default:s.sp=v;break;}}
std::uint16_t getRP2(const SemanticMachineState&s,unsigned p){switch(p&3u){case 0:return getBC(s);case 1:return getDE(s);case 2:return getHL(s);default:return getAF(s);}}
void setRP2(SemanticMachineState&s,unsigned p,std::uint16_t v){switch(p&3u){case 0:setBC(s,v);break;case 1:setDE(s,v);break;case 2:setHL(s,v);break;default:setAF(s,v);break;}}

bool condition(unsigned y,std::uint8_t f){switch(y&7u){case 0:return (f&SemanticFlagZ)==0;case 1:return (f&SemanticFlagZ)!=0;case 2:return (f&SemanticFlagC)==0;case 3:return (f&SemanticFlagC)!=0;case 4:return (f&SemanticFlagPV)==0;case 5:return (f&SemanticFlagPV)!=0;case 6:return (f&SemanticFlagS)==0;default:return (f&SemanticFlagS)!=0;}}

void incrementR(SemanticMachineState&s,unsigned count){const auto top=static_cast<std::uint8_t>(s.r&0x80);const auto low=static_cast<std::uint8_t>(((s.r&0x7F)+count)&0x7F);s.r=static_cast<std::uint8_t>(top|low);}

std::uint8_t add16Flags(std::uint8_t oldF,std::uint16_t lhs,std::uint16_t rhs,std::uint16_t result){
    std::uint8_t f=static_cast<std::uint8_t>(oldF&(SemanticFlagS|SemanticFlagZ|SemanticFlagPV));
    if(((lhs^rhs^result)&0x1000u)!=0)f|=SemanticFlagH;
    if(static_cast<unsigned>(lhs)+static_cast<unsigned>(rhs)>0xFFFFu)f|=SemanticFlagC;
    const auto hi=static_cast<std::uint8_t>(result>>8);f|=static_cast<std::uint8_t>(hi&(SemanticFlagX|SemanticFlagY));return f;
}
std::uint8_t sbc16Flags(std::uint16_t lhs,std::uint16_t rhs,std::uint8_t carry,std::uint16_t result){
    std::uint8_t f=SemanticFlagN;const auto hi=static_cast<std::uint8_t>(result>>8);f|=static_cast<std::uint8_t>(hi&(SemanticFlagX|SemanticFlagY));
    if(result&0x8000u)f|=SemanticFlagS;
    if(result==0)f|=SemanticFlagZ;
    if(((lhs^rhs^result)&0x1000u)!=0)f|=SemanticFlagH;
    if(((lhs^rhs)&(lhs^result)&0x8000u)!=0)f|=SemanticFlagPV;
    if(static_cast<unsigned>(lhs)<static_cast<unsigned>(rhs)+carry)f|=SemanticFlagC;
    return f;
}
std::uint8_t adc16Flags(std::uint16_t lhs,std::uint16_t rhs,std::uint8_t carry,std::uint16_t result){
    std::uint8_t f=0;const auto hi=static_cast<std::uint8_t>(result>>8);f|=static_cast<std::uint8_t>(hi&(SemanticFlagX|SemanticFlagY));
    if(result&0x8000u)f|=SemanticFlagS;
    if(result==0)f|=SemanticFlagZ;
    if(((lhs^rhs^result)&0x1000u)!=0)f|=SemanticFlagH;
    if(((~(lhs^rhs))&(lhs^result)&0x8000u)!=0)f|=SemanticFlagPV;
    if(static_cast<unsigned>(lhs)+static_cast<unsigned>(rhs)+carry>0xFFFFu)f|=SemanticFlagC;
    return f;
}

void alu8(SemanticExecutionState&st,unsigned operation,std::uint8_t value){
    const auto a=st.cpu.a;const auto carry=static_cast<std::uint8_t>((st.cpu.f&SemanticFlagC)?1:0);std::uint8_t r=0;
    switch(operation&7u){
        case 0:r=static_cast<std::uint8_t>(a+value);st.cpu.a=r;st.cpu.f=SemanticLiftEngine::add8Flags(a,value,0,r);break;
        case 1:r=static_cast<std::uint8_t>(a+value+carry);st.cpu.a=r;st.cpu.f=SemanticLiftEngine::add8Flags(a,value,carry,r);break;
        case 2:r=static_cast<std::uint8_t>(a-value);st.cpu.a=r;st.cpu.f=SemanticLiftEngine::sub8Flags(a,value,0,r,false);break;
        case 3:r=static_cast<std::uint8_t>(a-value-carry);st.cpu.a=r;st.cpu.f=SemanticLiftEngine::sub8Flags(a,value,carry,r,false);break;
        case 4:r=static_cast<std::uint8_t>(a&value);st.cpu.a=r;st.cpu.f=SemanticLiftEngine::logicFlags(r,true);break;
        case 5:r=static_cast<std::uint8_t>(a^value);st.cpu.a=r;st.cpu.f=SemanticLiftEngine::logicFlags(r,false);break;
        case 6:r=static_cast<std::uint8_t>(a|value);st.cpu.a=r;st.cpu.f=SemanticLiftEngine::logicFlags(r,false);break;
        default:r=static_cast<std::uint8_t>(a-value);st.cpu.f=SemanticLiftEngine::sub8Flags(a,value,0,r,true);break;
    }
}

void daa(SemanticMachineState&s){
    const auto oldA=s.a;const auto oldF=s.f;std::uint8_t correction=0;bool c=(oldF&SemanticFlagC)!=0;
    if((oldF&SemanticFlagN)==0){if((oldF&SemanticFlagH)||(s.a&0x0F)>9)correction|=0x06;if(c||s.a>0x99){correction|=0x60;c=true;}s.a=static_cast<std::uint8_t>(s.a+correction);}
    else{if(oldF&SemanticFlagH)correction|=0x06;if(c)correction|=0x60;s.a=static_cast<std::uint8_t>(s.a-correction);}
    std::uint8_t f=static_cast<std::uint8_t>(oldF&SemanticFlagN);if(c)f|=SemanticFlagC;if(s.a&0x80)f|=SemanticFlagS;if(s.a==0)f|=SemanticFlagZ;if(SemanticLiftEngine::evenParity(s.a))f|=SemanticFlagPV;if(((oldA^s.a)&0x10)!=0)f|=SemanticFlagH;f|=static_cast<std::uint8_t>(s.a&(SemanticFlagX|SemanticFlagY));s.f=f;
}

bool executeCB(std::uint8_t op,bool indexed,std::uint16_t effective,SemanticExecutionState&st,std::uint16_t pc,std::string&error){
    const unsigned x=op>>6,y=(op>>3)&7,z=op&7;std::uint8_t value=indexed?read8(st,effective,pc):readReg8(st,z,pc);
    if(x==0){
        const auto carryIn=static_cast<std::uint8_t>((st.cpu.f&SemanticFlagC)?1:0);std::uint8_t carryOut=0,result=value;
        switch(y){
            case 0:carryOut=static_cast<std::uint8_t>(value>>7);result=static_cast<std::uint8_t>((value<<1)|carryOut);break;
            case 1:carryOut=static_cast<std::uint8_t>(value&1);result=static_cast<std::uint8_t>((value>>1)|(carryOut<<7));break;
            case 2:carryOut=static_cast<std::uint8_t>(value>>7);result=static_cast<std::uint8_t>((value<<1)|carryIn);break;
            case 3:carryOut=static_cast<std::uint8_t>(value&1);result=static_cast<std::uint8_t>((value>>1)|(carryIn<<7));break;
            case 4:carryOut=static_cast<std::uint8_t>(value>>7);result=static_cast<std::uint8_t>(value<<1);break;
            case 5:carryOut=static_cast<std::uint8_t>(value&1);result=static_cast<std::uint8_t>((value>>1)|(value&0x80));break;
            case 6:carryOut=static_cast<std::uint8_t>(value>>7);result=static_cast<std::uint8_t>((value<<1)|1);break;
            default:carryOut=static_cast<std::uint8_t>(value&1);result=static_cast<std::uint8_t>(value>>1);break;
        }
        std::uint8_t f=static_cast<std::uint8_t>(result&(SemanticFlagS|SemanticFlagX|SemanticFlagY));if(result==0)f|=SemanticFlagZ;if(SemanticLiftEngine::evenParity(result))f|=SemanticFlagPV;if(carryOut)f|=SemanticFlagC;st.cpu.f=f;
        if(indexed){write8(st,effective,result,pc);if(z!=6)writeReg8(st,z,result,pc);}else writeReg8(st,z,result,pc);return true;
    }
    if(x==1){
        const bool clear=(value&(1u<<y))==0;std::uint8_t f=static_cast<std::uint8_t>((st.cpu.f&SemanticFlagC)|SemanticFlagH);if(clear)f|=SemanticFlagZ|SemanticFlagPV;if(y==7&&!clear)f|=SemanticFlagS;
        if(indexed||z==6){const auto hi=static_cast<std::uint8_t>(effective>>8);f|=static_cast<std::uint8_t>(hi&(SemanticFlagX|SemanticFlagY));}else f|=static_cast<std::uint8_t>(value&(SemanticFlagX|SemanticFlagY));st.cpu.f=f;return true;
    }
    const std::uint8_t mask=static_cast<std::uint8_t>(1u<<y);const std::uint8_t result=x==2?static_cast<std::uint8_t>(value&~mask):static_cast<std::uint8_t>(value|mask);
    if(indexed){write8(st,effective,result,pc);if(z!=6)writeReg8(st,z,result,pc);}else writeReg8(st,z,result,pc);return true;
    (void)error;
}

bool executeIndex(const std::vector<std::uint8_t>&b,std::uint16_t fallthrough,SemanticExecutionState&st,std::uint16_t pc,std::string&error){
    if(b.size()<2){error="truncated index-prefixed instruction";return false;}const bool iy=b[0]==0xFD;auto& index=iy?st.cpu.iy:st.cpu.ix;const auto op=b[1];
    auto eff=[&](std::uint8_t disp){return static_cast<std::uint16_t>(index+static_cast<std::int8_t>(disp));};
    switch(op){
        case 0x19:{const auto old=index;const auto rhs=getDE(st.cpu);const auto r=static_cast<std::uint16_t>(old+rhs);st.cpu.f=add16Flags(st.cpu.f,old,rhs,r);index=r;st.cpu.pc=fallthrough;return true;}
        case 0x21:if(b.size()>=4){index=static_cast<std::uint16_t>(b[2]|(b[3]<<8));st.cpu.pc=fallthrough;return true;}break;
        case 0x23:index=static_cast<std::uint16_t>(index+1);st.cpu.pc=fallthrough;return true;
        case 0x36:if(b.size()>=4){write8(st,eff(b[2]),b[3],pc);st.cpu.pc=fallthrough;return true;}break;
        case 0x46:if(b.size()>=3){st.cpu.b=read8(st,eff(b[2]),pc);st.cpu.pc=fallthrough;return true;}break;
        case 0x5E:if(b.size()>=3){st.cpu.e=read8(st,eff(b[2]),pc);st.cpu.pc=fallthrough;return true;}break;
        case 0x66:if(b.size()>=3){st.cpu.h=read8(st,eff(b[2]),pc);st.cpu.pc=fallthrough;return true;}break;
        case 0x6E:if(b.size()>=3){st.cpu.l=read8(st,eff(b[2]),pc);st.cpu.pc=fallthrough;return true;}break;
        case 0x77:if(b.size()>=3){write8(st,eff(b[2]),st.cpu.a,pc);st.cpu.pc=fallthrough;return true;}break;
        case 0x7E:if(b.size()>=3){st.cpu.a=read8(st,eff(b[2]),pc);st.cpu.pc=fallthrough;return true;}break;
        case 0x86:if(b.size()>=3){alu8(st,0,read8(st,eff(b[2]),pc));st.cpu.pc=fallthrough;return true;}break;
        case 0xE1:index=pop16(st,pc);st.cpu.pc=fallthrough;return true;
        case 0xE5:push16(st,index,pc);st.cpu.pc=fallthrough;return true;
        case 0xCB:if(b.size()>=4){const auto address=eff(b[2]);const bool ok=executeCB(b[3],true,address,st,pc,error);if(ok)st.cpu.pc=fallthrough;return ok;}break;
        default:break;
    }
    error="unsupported index-prefixed opcode $"+h8(op)+" at $"+h16(pc);return false;
}

bool executeED(const std::vector<std::uint8_t>&b,std::uint16_t fallthrough,SemanticExecutionState&st,std::uint16_t pc,std::string&error){
    if(b.size()<2){error="truncated ED-prefixed instruction";return false;}const auto op=b[1];const unsigned p=(op>>4)&3u;
    switch(op){
        case 0x42:case 0x52:case 0x62:case 0x72:{const unsigned rp=(op>>4)&3u;const std::uint16_t lhs=getHL(st.cpu);const std::uint16_t rhs=getRP(st.cpu,rp);const std::uint8_t carry=static_cast<std::uint8_t>((st.cpu.f&SemanticFlagC)?1:0);const auto r=static_cast<std::uint16_t>(lhs-rhs-carry);setHL(st.cpu,r);st.cpu.f=sbc16Flags(lhs,rhs,carry,r);st.cpu.pc=fallthrough;return true;}
        case 0x4A:case 0x5A:case 0x6A:case 0x7A:{const unsigned rp=(op>>4)&3u;const std::uint16_t lhs=getHL(st.cpu);const std::uint16_t rhs=getRP(st.cpu,rp);const std::uint8_t carry=static_cast<std::uint8_t>((st.cpu.f&SemanticFlagC)?1:0);const auto r=static_cast<std::uint16_t>(lhs+rhs+carry);setHL(st.cpu,r);st.cpu.f=adc16Flags(lhs,rhs,carry,r);st.cpu.pc=fallthrough;return true;}
        case 0x43:case 0x53:case 0x63:case 0x73:if(b.size()>=4){const auto nn=static_cast<std::uint16_t>(b[2]|(b[3]<<8));write16(st,nn,getRP(st.cpu,p),pc);st.cpu.pc=fallthrough;return true;}break;
        case 0x4B:case 0x5B:case 0x6B:case 0x7B:if(b.size()>=4){const auto nn=static_cast<std::uint16_t>(b[2]|(b[3]<<8));setRP(st.cpu,p,read16(st,nn,pc));st.cpu.pc=fallthrough;return true;}break;
        case 0x47:st.cpu.i=st.cpu.a;st.cpu.pc=fallthrough;return true;
        case 0x46:case 0x4E:case 0x66:case 0x6E:st.cpu.interruptMode=0;addEffect(st,SemanticEffectKind::InterruptControl,0,0,pc);st.cpu.pc=fallthrough;return true;
        case 0x56:case 0x76:st.cpu.interruptMode=1;addEffect(st,SemanticEffectKind::InterruptControl,0,1,pc);st.cpu.pc=fallthrough;return true;
        case 0x5E:case 0x7E:st.cpu.interruptMode=2;addEffect(st,SemanticEffectKind::InterruptControl,0,2,pc);st.cpu.pc=fallthrough;return true;
        default:break;
    }
    error="unsupported ED-prefixed opcode $"+h8(op)+" at $"+h16(pc);return false;
}

bool executeBase(const std::vector<std::uint8_t>&b,std::uint16_t fallthrough,SemanticExecutionState&st,std::uint16_t pc,std::string&error){
    if(b.empty()){error="empty instruction";return false;}const auto op=b[0];const unsigned x=op>>6,y=(op>>3)&7,z=op&7,p=y>>1,q=y&1;
    auto nn=[&](){return b.size()>=3?static_cast<std::uint16_t>(b[1]|(b[2]<<8)):0;};
    auto n=[&](){return b.size()>=2?b[1]:static_cast<std::uint8_t>(0);};
    const auto physicalNext=static_cast<std::uint16_t>(pc+static_cast<std::uint16_t>(b.size()));
    st.cpu.pc=fallthrough;
    if(x==0){
        switch(z){
            case 0:
                if(y==0)return true;
                if(y==1){std::swap(st.cpu.a,st.cpu.aAlt);std::swap(st.cpu.f,st.cpu.fAlt);return true;}
                if(y==2){st.cpu.b=static_cast<std::uint8_t>(st.cpu.b-1);if(st.cpu.b!=0)st.cpu.pc=static_cast<std::uint16_t>(fallthrough+static_cast<std::int8_t>(n()));return true;}
                if(y==3){st.cpu.pc=static_cast<std::uint16_t>(fallthrough+static_cast<std::int8_t>(n()));return true;}
                if(condition(y-4,st.cpu.f))st.cpu.pc=static_cast<std::uint16_t>(fallthrough+static_cast<std::int8_t>(n()));
                return true;
            case 1:
                if(!q){if(b.size()<3){error="truncated LD rr,nn";return false;}setRP(st.cpu,p,nn());return true;}
                else{const auto lhs=getHL(st.cpu),rhs=getRP(st.cpu,p),r=static_cast<std::uint16_t>(lhs+rhs);setHL(st.cpu,r);st.cpu.f=add16Flags(st.cpu.f,lhs,rhs,r);return true;}
            case 2:{const auto address=nn();switch(y){
                case 0:write8(st,getBC(st.cpu),st.cpu.a,pc);return true;case 1:st.cpu.a=read8(st,getBC(st.cpu),pc);return true;
                case 2:write8(st,getDE(st.cpu),st.cpu.a,pc);return true;case 3:st.cpu.a=read8(st,getDE(st.cpu),pc);return true;
                case 4:if(b.size()<3){error="truncated LD (nn),HL";return false;}write16(st,address,getHL(st.cpu),pc);return true;
                case 5:if(b.size()<3){error="truncated LD HL,(nn)";return false;}setHL(st.cpu,read16(st,address,pc));return true;
                case 6:if(b.size()<3){error="truncated LD (nn),A";return false;}write8(st,address,st.cpu.a,pc);return true;
                default:if(b.size()<3){error="truncated LD A,(nn)";return false;}st.cpu.a=read8(st,address,pc);return true;}}
            case 3:{const auto old=getRP(st.cpu,p);setRP(st.cpu,p,q?static_cast<std::uint16_t>(old-1):static_cast<std::uint16_t>(old+1));return true;}
            case 4:{const auto old=readReg8(st,y,pc),r=static_cast<std::uint8_t>(old+1);writeReg8(st,y,r,pc);st.cpu.f=SemanticLiftEngine::inc8Flags(old,r,st.cpu.f);return true;}
            case 5:{const auto old=readReg8(st,y,pc),r=static_cast<std::uint8_t>(old-1);writeReg8(st,y,r,pc);st.cpu.f=SemanticLiftEngine::dec8Flags(old,r,st.cpu.f);return true;}
            case 6:if(b.size()<2){error="truncated LD r,n";return false;}writeReg8(st,y,n(),pc);return true;
            case 7:
                switch(y){
                    case 0:{const auto c=static_cast<std::uint8_t>(st.cpu.a>>7);st.cpu.a=static_cast<std::uint8_t>((st.cpu.a<<1)|c);st.cpu.f=static_cast<std::uint8_t>((st.cpu.f&(SemanticFlagS|SemanticFlagZ|SemanticFlagPV))|(st.cpu.a&(SemanticFlagX|SemanticFlagY))|(c?SemanticFlagC:0));return true;}
                    case 1:{const auto c=static_cast<std::uint8_t>(st.cpu.a&1);st.cpu.a=static_cast<std::uint8_t>((st.cpu.a>>1)|(c<<7));st.cpu.f=static_cast<std::uint8_t>((st.cpu.f&(SemanticFlagS|SemanticFlagZ|SemanticFlagPV))|(st.cpu.a&(SemanticFlagX|SemanticFlagY))|(c?SemanticFlagC:0));return true;}
                    case 2:{const auto oldC=static_cast<std::uint8_t>((st.cpu.f&SemanticFlagC)?1:0),c=static_cast<std::uint8_t>(st.cpu.a>>7);st.cpu.a=static_cast<std::uint8_t>((st.cpu.a<<1)|oldC);st.cpu.f=static_cast<std::uint8_t>((st.cpu.f&(SemanticFlagS|SemanticFlagZ|SemanticFlagPV))|(st.cpu.a&(SemanticFlagX|SemanticFlagY))|(c?SemanticFlagC:0));return true;}
                    case 3:{const auto oldC=static_cast<std::uint8_t>((st.cpu.f&SemanticFlagC)?1:0),c=static_cast<std::uint8_t>(st.cpu.a&1);st.cpu.a=static_cast<std::uint8_t>((st.cpu.a>>1)|(oldC<<7));st.cpu.f=static_cast<std::uint8_t>((st.cpu.f&(SemanticFlagS|SemanticFlagZ|SemanticFlagPV))|(st.cpu.a&(SemanticFlagX|SemanticFlagY))|(c?SemanticFlagC:0));return true;}
                    case 4:daa(st.cpu);return true;
                    case 5:st.cpu.a=static_cast<std::uint8_t>(~st.cpu.a);st.cpu.f=static_cast<std::uint8_t>((st.cpu.f&(SemanticFlagS|SemanticFlagZ|SemanticFlagPV|SemanticFlagC))|SemanticFlagH|SemanticFlagN|(st.cpu.a&(SemanticFlagX|SemanticFlagY)));return true;
                    case 6:st.cpu.f=static_cast<std::uint8_t>((st.cpu.f&(SemanticFlagS|SemanticFlagZ|SemanticFlagPV))|SemanticFlagC|(st.cpu.a&(SemanticFlagX|SemanticFlagY)));return true;
                    default:{const bool oldC=(st.cpu.f&SemanticFlagC)!=0;st.cpu.f=static_cast<std::uint8_t>((st.cpu.f&(SemanticFlagS|SemanticFlagZ|SemanticFlagPV))|(oldC?SemanticFlagH:0)|(!oldC?SemanticFlagC:0)|(st.cpu.a&(SemanticFlagX|SemanticFlagY)));return true;}
                }
        }
    }
    if(x==1){if(op==0x76){st.cpu.halted=true;return true;}writeReg8(st,y,readReg8(st,z,pc),pc);return true;}
    if(x==2){alu8(st,y,readReg8(st,z,pc));return true;}
    switch(z){
        case 0:if(condition(y,st.cpu.f))st.cpu.pc=pop16(st,pc);return true;
        case 1:
            if(!q){setRP2(st.cpu,p,pop16(st,pc));return true;}
            switch(p){case 0:st.cpu.pc=pop16(st,pc);return true;case 1:std::swap(st.cpu.b,st.cpu.bAlt);std::swap(st.cpu.c,st.cpu.cAlt);std::swap(st.cpu.d,st.cpu.dAlt);std::swap(st.cpu.e,st.cpu.eAlt);std::swap(st.cpu.h,st.cpu.hAlt);std::swap(st.cpu.l,st.cpu.lAlt);return true;case 2:st.cpu.pc=getHL(st.cpu);return true;default:st.cpu.sp=getHL(st.cpu);return true;}
        case 2:if(b.size()<3){error="truncated JP cc,nn";return false;}if(condition(y,st.cpu.f))st.cpu.pc=nn();return true;
        case 3:
            switch(y){
                case 0:if(b.size()<3){error="truncated JP nn";return false;}st.cpu.pc=nn();return true;
                case 1:error="CB prefix reached base executor";return false;
                case 2:{if(b.size()<2){error="truncated OUT";return false;}const auto port=static_cast<std::uint16_t>((st.cpu.a<<8)|b[1]);addEffect(st,SemanticEffectKind::PortWrite,port,st.cpu.a,pc);return true;}
                case 3:{if(b.size()<2){error="truncated IN";return false;}const auto port=static_cast<std::uint16_t>((st.cpu.a<<8)|b[1]);st.cpu.a=st.portInputs[b[1]];addEffect(st,SemanticEffectKind::PortRead,port,st.cpu.a,pc);return true;}
                case 4:{const auto v=read16(st,st.cpu.sp,pc);write16(st,st.cpu.sp,getHL(st.cpu),pc);setHL(st.cpu,v);return true;}
                case 5:{const auto de=getDE(st.cpu);setDE(st.cpu,getHL(st.cpu));setHL(st.cpu,de);return true;}
                case 6:st.cpu.iff1=false;st.cpu.iff2=false;st.cpu.eiDelay=false;addEffect(st,SemanticEffectKind::InterruptControl,0,0,pc);return true;
                default:st.cpu.iff1=true;st.cpu.iff2=true;st.cpu.eiDelay=true;addEffect(st,SemanticEffectKind::InterruptControl,0,1,pc);return true;
            }
        case 4:if(b.size()<3){error="truncated CALL cc,nn";return false;}if(condition(y,st.cpu.f)){push16(st,physicalNext,pc);st.cpu.pc=nn();}return true;
        case 5:
            if(!q){push16(st,getRP2(st.cpu,p),pc);return true;}
            if(p==0){if(b.size()<3){error="truncated CALL nn";return false;}push16(st,physicalNext,pc);st.cpu.pc=nn();return true;}
            error="unexpected prefix opcode in base executor";return false;
        case 6:if(b.size()<2){error="truncated ALU immediate";return false;}alu8(st,y,b[1]);return true;
        case 7:push16(st,physicalNext,pc);st.cpu.pc=static_cast<std::uint16_t>(y*8);return true;
    }
    error="unhandled base opcode $"+h8(op);return false;
}

bool executeEncoding(const Instruction&in,std::uint16_t fallthrough,SemanticExecutionState&st,std::string&error){
    if(in.bytes.empty()){error="instruction has no raw bytes";return false;}
    const bool oldDelay=st.cpu.eiDelay;st.cpu.eiDelay=false;
    const auto b0=in.bytes[0];incrementR(st.cpu,(b0==0xCB||b0==0xED||b0==0xDD||b0==0xFD)?2u:1u);
    bool ok=false;
    if(b0==0xCB){if(in.bytes.size()<2){error="truncated CB instruction";return false;}ok=executeCB(in.bytes[1],false,getHL(st.cpu),st,in.address,error);if(ok)st.cpu.pc=fallthrough;}
    else if(b0==0xED)ok=executeED(in.bytes,fallthrough,st,in.address,error);
    else if(b0==0xDD||b0==0xFD)ok=executeIndex(in.bytes,fallthrough,st,in.address,error);
    else ok=executeBase(in.bytes,fallthrough,st,in.address,error);
    if(!ok)return false;
    if(oldDelay&&b0!=0xFB)st.cpu.eiDelay=false;
    return true;
}

bool positiveDataPrimary(RomClosurePrimary p){return p==RomClosurePrimary::CodeAndDataUse||p==RomClosurePrimary::HardData||p==RomClosurePrimary::ProvenDataUse||p==RomClosurePrimary::BoundedConsumer||p==RomClosurePrimary::PointerTarget;}

} // namespace

bool SemanticLiftEngine::evenParity(std::uint8_t value){value^=static_cast<std::uint8_t>(value>>4);value^=static_cast<std::uint8_t>(value>>2);value^=static_cast<std::uint8_t>(value>>1);return (value&1)==0;}

std::uint8_t SemanticLiftEngine::add8Flags(std::uint8_t lhs,std::uint8_t rhs,std::uint8_t carry,std::uint8_t result){
    std::uint8_t f=static_cast<std::uint8_t>(result&(SemanticFlagS|SemanticFlagX|SemanticFlagY));if(result==0)f|=SemanticFlagZ;if(((lhs^rhs^result)&0x10)!=0)f|=SemanticFlagH;if(((~(lhs^rhs))&(lhs^result)&0x80)!=0)f|=SemanticFlagPV;if(static_cast<unsigned>(lhs)+rhs+carry>0xFFu)f|=SemanticFlagC;return f;
}
std::uint8_t SemanticLiftEngine::sub8Flags(std::uint8_t lhs,std::uint8_t rhs,std::uint8_t carry,std::uint8_t result,bool compare){
    std::uint8_t f=SemanticFlagN;f|=static_cast<std::uint8_t>((compare?rhs:result)&(SemanticFlagX|SemanticFlagY));if(result&0x80)f|=SemanticFlagS;if(result==0)f|=SemanticFlagZ;if(((lhs^rhs^result)&0x10)!=0)f|=SemanticFlagH;if(((lhs^rhs)&(lhs^result)&0x80)!=0)f|=SemanticFlagPV;if(static_cast<unsigned>(lhs)<static_cast<unsigned>(rhs)+carry)f|=SemanticFlagC;return f;
}
std::uint8_t SemanticLiftEngine::inc8Flags(std::uint8_t oldValue,std::uint8_t result,std::uint8_t oldFlags){
    std::uint8_t f=static_cast<std::uint8_t>(oldFlags&SemanticFlagC);f|=static_cast<std::uint8_t>(result&(SemanticFlagS|SemanticFlagX|SemanticFlagY));if(result==0)f|=SemanticFlagZ;if((oldValue&0x0F)==0x0F)f|=SemanticFlagH;if(oldValue==0x7F)f|=SemanticFlagPV;return f;
}
std::uint8_t SemanticLiftEngine::dec8Flags(std::uint8_t oldValue,std::uint8_t result,std::uint8_t oldFlags){
    std::uint8_t f=static_cast<std::uint8_t>((oldFlags&SemanticFlagC)|SemanticFlagN);f|=static_cast<std::uint8_t>(result&(SemanticFlagS|SemanticFlagX|SemanticFlagY));if(result==0)f|=SemanticFlagZ;if((oldValue&0x0F)==0)f|=SemanticFlagH;if(oldValue==0x80)f|=SemanticFlagPV;return f;
}
std::uint8_t SemanticLiftEngine::logicFlags(std::uint8_t result,bool halfCarry){std::uint8_t f=static_cast<std::uint8_t>(result&(SemanticFlagS|SemanticFlagX|SemanticFlagY));if(result==0)f|=SemanticFlagZ;if(evenParity(result))f|=SemanticFlagPV;if(halfCarry)f|=SemanticFlagH;return f;}

std::string SemanticLiftEngine::semanticKindText(SemanticKind kind){
    switch(kind){case SemanticKind::Nop:return"nop";case SemanticKind::Load8:return"load8";case SemanticKind::Load16:return"load16";case SemanticKind::Increment8:return"inc8";case SemanticKind::Decrement8:return"dec8";case SemanticKind::Increment16:return"inc16";case SemanticKind::Decrement16:return"dec16";case SemanticKind::Add8:return"add8";case SemanticKind::AddCarry8:return"adc8";case SemanticKind::Subtract8:return"sub8";case SemanticKind::SubtractCarry8:return"sbc8";case SemanticKind::Add16:return"add16";case SemanticKind::SubtractCarry16:return"sbc16";case SemanticKind::And8:return"and8";case SemanticKind::Xor8:return"xor8";case SemanticKind::Or8:return"or8";case SemanticKind::Compare8:return"compare8";case SemanticKind::RotateAccumulator:return"rotate_a";case SemanticKind::RotateShift:return"rotate_shift";case SemanticKind::BitTest:return"bit_test";case SemanticKind::BitSet:return"bit_set";case SemanticKind::BitReset:return"bit_reset";case SemanticKind::DecimalAdjust:return"daa";case SemanticKind::ComplementAccumulator:return"cpl";case SemanticKind::SetCarry:return"scf";case SemanticKind::ComplementCarry:return"ccf";case SemanticKind::Jump:return"jump";case SemanticKind::RelativeJump:return"relative_jump";case SemanticKind::Djnz:return"djnz";case SemanticKind::Call:return"call";case SemanticKind::Return:return"return";case SemanticKind::Restart:return"restart";case SemanticKind::Push:return"push";case SemanticKind::Pop:return"pop";case SemanticKind::Exchange:return"exchange";case SemanticKind::ExchangeAlternate:return"exchange_alt";case SemanticKind::Halt:return"halt";case SemanticKind::InterruptDisable:return"di";case SemanticKind::InterruptEnable:return"ei";case SemanticKind::InterruptMode:return"im";case SemanticKind::IoRead:return"io_read";case SemanticKind::IoWrite:return"io_write";default:return"unsupported";}
}
std::string SemanticLiftEngine::effectKindText(SemanticEffectKind kind){switch(kind){case SemanticEffectKind::MemoryRead:return"memory_read";case SemanticEffectKind::MemoryWrite:return"memory_write";case SemanticEffectKind::PortRead:return"port_read";case SemanticEffectKind::PortWrite:return"port_write";default:return"interrupt_control";}}
std::string SemanticLiftEngine::stableBlockId(std::uint16_t start){return"B_"+h16(start);}
std::string SemanticLiftEngine::stableOperationId(std::uint16_t blockStart,std::uint16_t sourcePC){return stableBlockId(blockStart)+"_I_"+h16(sourcePC);}

SemanticLiftedOperation SemanticLiftEngine::lowerInstruction(const Instruction& in,std::uint16_t blockStart,std::uint16_t fallthroughPC,std::size_t id){
    SemanticLiftedOperation o;o.id=id;o.blockStart=blockStart;o.blockId=stableBlockId(blockStart);o.sourcePC=in.address;o.fallthroughPC=fallthroughPC;o.stableId=stableOperationId(blockStart,in.address);o.bytes=in.bytes;o.mnemonic=in.mnemonic;o.operands=in.operands;o.rawText=in.text();o.kind=classifyKind(in);o.supported=o.kind!=SemanticKind::Unsupported&&encodingSupported(in);if(!o.supported)o.kind=SemanticKind::Unsupported;o.note=o.supported?"mechanical source-PC-preserving machine-semantic operation":"semantic execution intentionally refused until this encoding has an exact implementation";return o;
}

std::vector<SemanticRomProvenanceRecord> SemanticLiftEngine::buildProvenanceLedger(const Analyzer&analyzer,const std::vector<RomByteClosureRecord>&closure,const std::vector<ResidualExtentClosureProvenanceRecord>&residualExtentProvenance,const std::vector<Im2VectorClosureProvenanceRecord>&im2VectorProvenance,const std::vector<Im2VectorVectorDomainProofRecord>&domains,const std::set<std::uint16_t>&rooted,SemanticLiftStats&stats){
    std::map<std::uint16_t,std::set<std::uint16_t>> codeByByte;for(const auto&kv:analyzer.instructions())for(std::size_t i=0;i<kv.second.length()&&static_cast<std::size_t>(kv.first)+i<closure.size();++i)codeByByte[static_cast<std::uint16_t>(kv.first+i)].insert(kv.first);
    std::map<std::uint16_t,const ResidualExtentClosureProvenanceRecord*> m24;for(const auto&r:residualExtentProvenance)m24[r.address]=&r;std::map<std::uint16_t,const Im2VectorClosureProvenanceRecord*>m25;for(const auto&r:im2VectorProvenance)m25[r.address]=&r;
    std::set<std::uint16_t> vectorBytes;for(const auto&d:domains)if(d.accepted)for(auto a:d.vectorWordAddresses){vectorBytes.insert(a);vectorBytes.insert(static_cast<std::uint16_t>(a+1));}
    std::vector<SemanticRomProvenanceRecord> out;out.reserve(closure.size());stats.rootedCodeInstructions=rooted.size();
    for(std::size_t i=0;i<closure.size();++i){const auto&b=closure[i];SemanticRomProvenanceRecord r;r.address=static_cast<std::uint16_t>(i);r.primary=b.primary;r.resolved=b.primary!=RomClosurePrimary::Unresolved;r.code=b.code;r.hardData=b.hardData;r.staticExactDataUse=b.staticExactDataUse;r.dynamicDataUse=b.dynamicDataUse;r.boundedConsumer=b.boundedConsumer;r.pointerTarget=b.pointerTarget;r.provenUnused=b.provenUnused;r.consumerPCs=b.consumerPCs;
        auto ci=codeByByte.find(r.address);if(ci!=codeByByte.end())r.instructionPCs=ci->second;
        if(r.code)r.sourceTags.insert("rooted_instruction");
        if(r.hardData)r.sourceTags.insert("hard_data_region");
        if(!r.consumerPCs.empty())r.sourceTags.insert("consumer_pc");
        if(r.boundedConsumer)r.sourceTags.insert("bounded_consumer");
        if(r.pointerTarget)r.sourceTags.insert("pointer_target");
        if(vectorBytes.count(r.address))r.sourceTags.insert("im2_vector_word");
        auto a24=m24.find(r.address);if(a24!=m24.end()){r.residualExtentNegativeProofIds=a24->second->negativeProofIds;if(!r.residualExtentNegativeProofIds.empty())r.sourceTags.insert("residual_extent_negative_proof");}
        auto a25=m25.find(r.address);if(a25!=m25.end()){r.im2VectorSystemNegativeProofIds=a25->second->systemNegativeProofIds;r.im2VectorVectorDomainProofIds=a25->second->vectorDomainProofIds;if(!r.im2VectorSystemNegativeProofIds.empty())r.sourceTags.insert("im2_system_negative_proof");}
        unsigned evidenceKinds=0;if(r.code)++evidenceKinds;if(r.hardData||r.staticExactDataUse||r.dynamicDataUse||r.boundedConsumer||r.pointerTarget)++evidenceKinds;if(r.provenUnused)++evidenceKinds;r.overlappingEvidence=evidenceKinds>1;
        bool codeOk=true;if(r.code){codeOk=false;for(auto pc:r.instructionPCs)if(rooted.count(pc)){codeOk=true;break;}}
        bool dataOk=true;if(positiveDataPrimary(r.primary)){dataOk=r.hardData||r.pointerTarget||!r.consumerPCs.empty()||vectorBytes.count(r.address)!=0;}
        bool unusedOk=true;if(r.provenUnused)unusedOk=!r.residualExtentNegativeProofIds.empty()||!r.im2VectorSystemNegativeProofIds.empty();
        r.provenanceComplete=r.resolved&&codeOk&&dataOk&&unusedOk;
        if(!r.resolved)r.note="unresolved primary classification";else if(!r.provenanceComplete)r.note="primary classification is resolved but a required provenance edge is incomplete";else if(r.overlappingEvidence)r.note="resolved byte with overlapping evidence preserved explicitly";else r.note="resolved byte with source-map provenance";
        ++stats.provenanceRecords;if(r.resolved)++stats.resolvedRomBytes;else ++stats.unresolvedRomBytes;if(r.code){++stats.codeBytes;if(codeOk)++stats.codeBytesWithRootedInstructionProvenance;}if(positiveDataPrimary(r.primary)){++stats.positiveDataBytes;if(dataOk)++stats.positiveDataBytesWithProvenance;}if(r.provenUnused){++stats.provenUnusedBytes;if(unusedOk)++stats.provenUnusedBytesWithNegativeProvenance;}if(r.overlappingEvidence)++stats.overlappingEvidenceBytes;if(!r.provenanceComplete)++stats.incompleteProvenanceBytes;out.push_back(std::move(r));}
    stats.romByteAccountingFrozen=closure.size()==16384&&stats.unresolvedRomBytes==0;stats.wholeRomProvenanceComplete=stats.romByteAccountingFrozen&&stats.incompleteProvenanceBytes==0;return out;
}

void SemanticLiftEngine::lowerBlocks(const Analyzer&analyzer,const std::vector<SemanticBlockInput>&blocks,const std::vector<std::uint16_t>&fallthroughByPC,std::vector<SemanticLiftedOperation>&operations,std::vector<SemanticLiftedBlock>&liftedBlocks,SemanticLiftStats&stats){
    operations.clear();liftedBlocks.clear();for(const auto&b:blocks){SemanticLiftedBlock lb;lb.stableId=stableBlockId(b.start);lb.start=b.start;lb.end=b.end;lb.fullySupported=true;for(auto pc:b.instructionPCs){const auto ii=analyzer.instructions().find(pc);if(ii==analyzer.instructions().end()){lb.fullySupported=false;continue;}const auto fall=pc<fallthroughByPC.size()?fallthroughByPC[pc]:static_cast<std::uint16_t>(pc+ii->second.length());auto op=lowerInstruction(ii->second,b.start,fall,operations.size());if(!op.supported)lb.fullySupported=false;else ++stats.mechanicallyLiftedInstructions;if(!op.supported)++stats.unsupportedInstructionSemantics;lb.operationIds.push_back(op.id);operations.push_back(std::move(op));}if(lb.fullySupported)++stats.fullySupportedBlocks;liftedBlocks.push_back(std::move(lb));}stats.liftedBlocks=liftedBlocks.size();
}

SemanticExecutionState SemanticLiftEngine::deterministicSnapshot(const std::vector<std::uint8_t>&program,std::uint16_t pc,unsigned seed){
    SemanticExecutionState s;std::uint32_t x=0x9E3779B9u^(seed*0x85EBCA6Bu)^pc;auto next=[&](){x^=x<<13;x^=x>>17;x^=x<<5;return static_cast<std::uint8_t>(x>>24);};for(auto&v:s.cpu.memory)v=next();for(std::size_t i=0;i<program.size()&&i<s.cpu.memory.size();++i)s.cpu.memory[i]=program[i];for(auto&v:s.portInputs)v=next();s.cpu.a=next();s.cpu.f=next();s.cpu.b=next();s.cpu.c=next();s.cpu.d=next();s.cpu.e=next();s.cpu.h=next();s.cpu.l=next();s.cpu.aAlt=next();s.cpu.fAlt=next();s.cpu.bAlt=next();s.cpu.cAlt=next();s.cpu.dAlt=next();s.cpu.eAlt=next();s.cpu.hAlt=next();s.cpu.lAlt=next();s.cpu.ix=static_cast<std::uint16_t>(0x4C00u|(next()<<2));s.cpu.iy=static_cast<std::uint16_t>(0x4C00u|(next()<<2));s.cpu.sp=static_cast<std::uint16_t>(0x4F00u|(next()&0x7Eu));s.cpu.pc=pc;s.cpu.i=next();s.cpu.r=next();s.cpu.interruptMode=static_cast<std::uint8_t>(seed%3);s.cpu.iff1=(seed&1)!=0;s.cpu.iff2=(seed&2)!=0;return s;
}

bool SemanticLiftEngine::executeReference(const Instruction&instruction,std::uint16_t fallthroughPC,SemanticExecutionState&state,std::string&error){if(!encodingSupported(instruction)){error="reference executor intentionally lacks exact semantics for "+instruction.text();return false;}return executeEncoding(instruction,fallthroughPC,state,error);}
bool SemanticLiftEngine::executeLifted(const SemanticLiftedOperation&operation,SemanticExecutionState&state,std::string&error){if(!operation.supported){error="lifted operation is explicitly unsupported: "+operation.stableId;return false;}Instruction in;in.address=operation.sourcePC;in.bytes=operation.bytes;in.mnemonic=operation.mnemonic;in.operands=operation.operands;const auto expected=classifyKind(in);if(expected!=operation.kind){error="semantic-kind/source mismatch for "+operation.stableId;return false;}return executeEncoding(in,operation.fallthroughPC,state,error);}

bool SemanticLiftEngine::compareExecutionStates(const SemanticExecutionState&a,const SemanticExecutionState&b,std::string&d){
#define CMP8(field,label) do{if(a.cpu.field!=b.cpu.field){d=std::string(label)+" mismatch reference=$"+h8(a.cpu.field)+" lifted=$"+h8(b.cpu.field);return false;}}while(false)
#define CMP16(field,label) do{if(a.cpu.field!=b.cpu.field){d=std::string(label)+" mismatch reference=$"+h16(a.cpu.field)+" lifted=$"+h16(b.cpu.field);return false;}}while(false)
    CMP8(a,"A");CMP8(f,"F");CMP8(b,"B");CMP8(c,"C");CMP8(d,"D");CMP8(e,"E");CMP8(h,"H");CMP8(l,"L");CMP8(aAlt,"A'");CMP8(fAlt,"F'");CMP8(bAlt,"B'");CMP8(cAlt,"C'");CMP8(dAlt,"D'");CMP8(eAlt,"E'");CMP8(hAlt,"H'");CMP8(lAlt,"L'");CMP16(ix,"IX");CMP16(iy,"IY");CMP16(sp,"SP");CMP16(pc,"PC");CMP8(i,"I");CMP8(r,"R");CMP8(interruptMode,"IM");
#undef CMP8
#undef CMP16
    if(a.cpu.iff1!=b.cpu.iff1){d="IFF1 mismatch";return false;}if(a.cpu.iff2!=b.cpu.iff2){d="IFF2 mismatch";return false;}if(a.cpu.halted!=b.cpu.halted){d="HALT state mismatch";return false;}if(a.cpu.eiDelay!=b.cpu.eiDelay){d="EI-delay state mismatch";return false;}
    for(std::size_t i=0;i<a.cpu.memory.size();++i)if(a.cpu.memory[i]!=b.cpu.memory[i]){d="memory mismatch at $"+h16(static_cast<std::uint16_t>(i))+" reference=$"+h8(a.cpu.memory[i])+" lifted=$"+h8(b.cpu.memory[i]);return false;}
    if(a.effects.size()!=b.effects.size()){d="effect count mismatch reference="+std::to_string(a.effects.size())+" lifted="+std::to_string(b.effects.size());return false;}
    for(std::size_t i=0;i<a.effects.size();++i){const auto&x=a.effects[i];const auto&y=b.effects[i];if(x.sequence!=y.sequence||x.kind!=y.kind||x.address!=y.address||x.value!=y.value||x.sourcePC!=y.sourcePC){d="ordered effect mismatch at index "+std::to_string(i);return false;}}
    d.clear();return true;
}

std::vector<SemanticDifferentialRecord> SemanticLiftEngine::verifyBlocks(const Analyzer&analyzer,const std::vector<SemanticBlockInput>&blocks,const std::vector<SemanticLiftedOperation>&operations,const std::vector<SemanticLiftedBlock>&liftedBlocks,SemanticLiftStats&stats,unsigned snapshotsPerBlock){
    std::vector<SemanticDifferentialRecord> out;const auto&program=analyzer.program();std::map<std::uint16_t,const SemanticBlockInput*>byStart;for(const auto&b:blocks)byStart[b.start]=&b;
    for(const auto&lb:liftedBlocks){SemanticDifferentialRecord r;r.id=out.size();r.blockId=lb.stableId;r.blockStart=lb.start;r.supported=lb.fullySupported;if(!lb.fullySupported){r.diagnostic="block contains one or more explicitly unsupported instruction semantics";out.push_back(r);continue;}bool ok=true;std::string diag;
        for(unsigned seed=0;seed<snapshotsPerBlock&&ok;++seed){auto ref=deterministicSnapshot(program,lb.start,seed+1);auto lifted=ref;++r.snapshots;++stats.differentialSnapshots;for(auto oid:lb.operationIds){if(oid>=operations.size()){ok=false;diag="invalid lifted operation id";break;}const auto&op=operations[oid];const auto ii=analyzer.instructions().find(op.sourcePC);if(ii==analyzer.instructions().end()){ok=false;diag="source instruction missing at $"+h16(op.sourcePC);break;}if(ref.cpu.pc!=op.sourcePC||lifted.cpu.pc!=op.sourcePC){ok=false;r.firstDivergencePC=op.sourcePC;diag="block-boundary PC mismatch before $"+h16(op.sourcePC);break;}std::string e1,e2;if(!executeReference(ii->second,op.fallthroughPC,ref,e1)){ok=false;r.firstDivergencePC=op.sourcePC;diag="reference executor: "+e1;break;}if(!executeLifted(op,lifted,e2)){ok=false;r.firstDivergencePC=op.sourcePC;diag="lifted executor: "+e2;break;}++r.operationsCompared;++stats.differentialOperations;std::string sd;if(!compareExecutionStates(ref,lifted,sd)){ok=false;r.firstDivergencePC=op.sourcePC;diag=sd;break;}}
        }
        r.accepted=ok;r.diagnostic=ok?"raw-byte and mechanically lifted execution match for every compared snapshot/operation":diag;if(ok)++stats.differentiallyVerifiedBlocks;else ++stats.differentialMismatches;out.push_back(std::move(r));}
    return out;
}

} // namespace pacripper
