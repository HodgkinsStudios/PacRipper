// PacRipper canonical semantic lift corrected canonical semantic rebase
// Created by Jacob Hodgkins

#include "CanonicalSemanticLift.h"
#include "../disasm/Z80Disassembler.h"
#include "../reference/pacemu/cpu/Z80.h"

#include <algorithm>
#include <array>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>

namespace pacripper {
namespace {

std::string h8(std::uint8_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(2)<<std::setfill('0')<<(unsigned)v;return o.str();}
std::string h16(std::uint16_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(4)<<std::setfill('0')<<(unsigned)v;return o.str();}
void addEffect(SemanticExecutionState&st,SemanticEffectKind kind,std::uint16_t address,std::uint8_t value,std::uint16_t pc){SemanticEffect e;e.sequence=st.effects.size();e.kind=kind;e.address=address;e.value=value;e.sourcePC=pc;st.effects.push_back(e);}
std::uint8_t read8(SemanticExecutionState&st,std::uint16_t address,std::uint16_t pc){const auto v=st.cpu.memory[address];addEffect(st,SemanticEffectKind::MemoryRead,address,v,pc);return v;}
void write8(SemanticExecutionState&st,std::uint16_t address,std::uint8_t value,std::uint16_t pc){st.cpu.memory[address]=value;addEffect(st,SemanticEffectKind::MemoryWrite,address,value,pc);}
void incrementR(SemanticMachineState&s,unsigned count){const auto top=static_cast<std::uint8_t>(s.r&0x80);const auto low=static_cast<std::uint8_t>(((s.r&0x7F)+count)&0x7F);s.r=static_cast<std::uint8_t>(top|low);}

SemanticOracleExtensionKind semanticOracleExtensionFor(const SemanticLiftedOperation&op){
    if(op.bytes.size()==2&&op.bytes[0]==0xCB){const auto cb=op.bytes[1];if((cb>>6)==1u&&(cb&7u)==6u&&op.mnemonic=="BIT")return SemanticOracleExtensionKind::BitIndirectHl;}
    if(op.bytes.size()!=2||op.bytes[0]!=0xED)return SemanticOracleExtensionKind::None;
    if(op.bytes[1]==0xA0&&op.mnemonic=="LDI")return SemanticOracleExtensionKind::Ldi;
    if(op.bytes[1]==0xB0&&op.mnemonic=="LDIR")return SemanticOracleExtensionKind::Ldir;
    if(op.bytes[1]==0xB1&&op.mnemonic=="CPIR")return SemanticOracleExtensionKind::Cpir;
    return SemanticOracleExtensionKind::None;
}

CanonicalSemanticExtensionKind canonicalSemanticExtensionFor(const SemanticLiftedOperation&op){
    if(op.bytes.size()==2&&op.bytes[0]==0xED&&op.bytes[1]==0x44&&op.mnemonic=="NEG")return CanonicalSemanticExtensionKind::Neg;
    if(op.bytes.size()>=3&&(op.bytes[0]==0xDD||op.bytes[0]==0xFD)){
        const auto code=op.bytes[1];const unsigned x=code>>6,y=(code>>3)&7u,z=code&7u;
        if((x==1&&(y==6||z==6))||(x==2&&z==6)||(x==0&&(y==6)&&(z==4||z==5)))return CanonicalSemanticExtensionKind::IndexedMemory;
        if(code==0x34||code==0x35)return CanonicalSemanticExtensionKind::IndexedMemory;
    }
    return CanonicalSemanticExtensionKind::None;
}

std::uint8_t readPlainReg(const SemanticMachineState&s,unsigned r){switch(r&7u){case 0:return s.b;case 1:return s.c;case 2:return s.d;case 3:return s.e;case 4:return s.h;case 5:return s.l;default:return s.a;}}
void writePlainReg(SemanticMachineState&s,unsigned r,std::uint8_t v){switch(r&7u){case 0:s.b=v;break;case 1:s.c=v;break;case 2:s.d=v;break;case 3:s.e=v;break;case 4:s.h=v;break;case 5:s.l=v;break;default:s.a=v;break;}}

bool executeCanonicalSemanticExtension(const CanonicalSemanticLiftedOperation&op,SemanticExecutionState&st,std::string&error){
    const bool oldDelay=st.cpu.eiDelay;st.cpu.eiDelay=false;incrementR(st.cpu,2);
    if(op.canonicalSemanticExtension==CanonicalSemanticExtensionKind::Neg){
        const auto old=st.cpu.a;const auto result=static_cast<std::uint8_t>(0-old);st.cpu.a=result;st.cpu.f=SemanticLiftEngine::sub8Flags(0,old,0,result,false);st.cpu.pc=op.fallthroughPC;if(oldDelay)st.cpu.eiDelay=false;error.clear();return true;
    }
    if(op.canonicalSemanticExtension!=CanonicalSemanticExtensionKind::IndexedMemory||op.bytes.size()<3){error="unsupported canonical semantic lift extension at $"+h16(op.sourcePC);return false;}
    const bool iy=op.bytes[0]==0xFD;const auto index=iy?st.cpu.iy:st.cpu.ix;const auto code=op.bytes[1];const auto address=static_cast<std::uint16_t>(index+static_cast<std::int8_t>(op.bytes[2]));const unsigned x=code>>6,y=(code>>3)&7u,z=code&7u;
    st.cpu.pc=op.fallthroughPC;
    if(x==1&&(y==6||z==6)){
        const auto value=z==6?read8(st,address,op.sourcePC):readPlainReg(st.cpu,z);
        if(y==6)write8(st,address,value,op.sourcePC);else writePlainReg(st.cpu,y,value);
    }else if(code==0x34||code==0x35){
        const auto old=read8(st,address,op.sourcePC);const auto result=code==0x34?static_cast<std::uint8_t>(old+1):static_cast<std::uint8_t>(old-1);write8(st,address,result,op.sourcePC);st.cpu.f=code==0x34?SemanticLiftEngine::inc8Flags(old,result,st.cpu.f):SemanticLiftEngine::dec8Flags(old,result,st.cpu.f);
    }else if(x==2&&z==6){
        const auto value=read8(st,address,op.sourcePC);const auto oldA=st.cpu.a;const auto carry=static_cast<std::uint8_t>((st.cpu.f&SemanticFlagC)?1:0);
        switch(y){
            case 0:{const auto r=static_cast<std::uint8_t>(oldA+value);st.cpu.a=r;st.cpu.f=SemanticLiftEngine::add8Flags(oldA,value,0,r);break;}
            case 1:{const auto r=static_cast<std::uint8_t>(oldA+value+carry);st.cpu.a=r;st.cpu.f=SemanticLiftEngine::add8Flags(oldA,value,carry,r);break;}
            case 2:{const auto r=static_cast<std::uint8_t>(oldA-value);st.cpu.a=r;st.cpu.f=SemanticLiftEngine::sub8Flags(oldA,value,0,r,false);break;}
            case 3:{const auto r=static_cast<std::uint8_t>(oldA-value-carry);st.cpu.a=r;st.cpu.f=SemanticLiftEngine::sub8Flags(oldA,value,carry,r,false);break;}
            case 4:st.cpu.a=static_cast<std::uint8_t>(oldA&value);st.cpu.f=SemanticLiftEngine::logicFlags(st.cpu.a,true);break;
            case 5:st.cpu.a=static_cast<std::uint8_t>(oldA^value);st.cpu.f=SemanticLiftEngine::logicFlags(st.cpu.a,false);break;
            case 6:st.cpu.a=static_cast<std::uint8_t>(oldA|value);st.cpu.f=SemanticLiftEngine::logicFlags(st.cpu.a,false);break;
            default:{const auto r=static_cast<std::uint8_t>(oldA-value);st.cpu.f=SemanticLiftEngine::sub8Flags(oldA,value,0,r,true);break;}
        }
    }else{error="unsupported indexed-memory encoding $"+h8(code)+" at $"+h16(op.sourcePC);return false;}
    if(oldDelay)st.cpu.eiDelay=false;
    error.clear();return true;
}

bool terminalInstruction(const Instruction&in){return in.flow!=FlowKind::Normal||in.conditional;}

struct OracleBus final:pacemu::Z80Bus {
    std::array<std::uint8_t,65536> memory{};std::array<std::uint8_t,256> portInputs{};std::vector<SemanticEffect> rawEffects;std::uint16_t currentSourcePC=0;std::uint8_t vectorLatch=0;
    std::uint8_t read8(std::uint16_t address) override{const auto value=memory[address];SemanticEffect e;e.sequence=rawEffects.size();e.kind=SemanticEffectKind::MemoryRead;e.address=address;e.value=value;e.sourcePC=currentSourcePC;rawEffects.push_back(e);return value;}
    void write8(std::uint16_t address,std::uint8_t value) override{memory[address]=value;SemanticEffect e;e.sequence=rawEffects.size();e.kind=SemanticEffectKind::MemoryWrite;e.address=address;e.value=value;e.sourcePC=currentSourcePC;rawEffects.push_back(e);}
    std::uint8_t ioRead(std::uint16_t port) override{const auto value=portInputs[port&0xFFu];SemanticEffect e;e.sequence=rawEffects.size();e.kind=SemanticEffectKind::PortRead;e.address=port;e.value=value;e.sourcePC=currentSourcePC;rawEffects.push_back(e);return value;}
    void ioWrite(std::uint16_t port,std::uint8_t value) override{if((port&0xFFu)==0)vectorLatch=value;SemanticEffect e;e.sequence=rawEffects.size();e.kind=SemanticEffectKind::PortWrite;e.address=port;e.value=value;e.sourcePC=currentSourcePC;rawEffects.push_back(e);}
    std::uint8_t interruptAcknowledge(std::uint8_t requestedVector) override{(void)requestedVector;return vectorLatch;}
};
std::uint16_t pair(std::uint8_t hi,std::uint8_t lo){return static_cast<std::uint16_t>((hi<<8)|lo);}
void loadOracle(pacemu::Z80&cpu,const SemanticExecutionState&s){auto&r=cpu.registersMutable();r.af=pair(s.cpu.a,s.cpu.f);r.bc=pair(s.cpu.b,s.cpu.c);r.de=pair(s.cpu.d,s.cpu.e);r.hl=pair(s.cpu.h,s.cpu.l);r.af_alt=pair(s.cpu.aAlt,s.cpu.fAlt);r.bc_alt=pair(s.cpu.bAlt,s.cpu.cAlt);r.de_alt=pair(s.cpu.dAlt,s.cpu.eAlt);r.hl_alt=pair(s.cpu.hAlt,s.cpu.lAlt);r.ix=s.cpu.ix;r.iy=s.cpu.iy;r.sp=s.cpu.sp;r.pc=s.cpu.pc;r.i=s.cpu.i;r.r=s.cpu.r;r.iff1=s.cpu.iff1;r.iff2=s.cpu.iff2;r.interrupt_mode=s.cpu.interruptMode;}
SemanticExecutionState oracleState(const pacemu::Z80&cpu,const OracleBus&bus,const std::vector<SemanticEffect>&effects){SemanticExecutionState o;const auto&r=cpu.registers();o.cpu.a=static_cast<std::uint8_t>(r.af>>8);o.cpu.f=static_cast<std::uint8_t>(r.af);o.cpu.b=static_cast<std::uint8_t>(r.bc>>8);o.cpu.c=static_cast<std::uint8_t>(r.bc);o.cpu.d=static_cast<std::uint8_t>(r.de>>8);o.cpu.e=static_cast<std::uint8_t>(r.de);o.cpu.h=static_cast<std::uint8_t>(r.hl>>8);o.cpu.l=static_cast<std::uint8_t>(r.hl);o.cpu.aAlt=static_cast<std::uint8_t>(r.af_alt>>8);o.cpu.fAlt=static_cast<std::uint8_t>(r.af_alt);o.cpu.bAlt=static_cast<std::uint8_t>(r.bc_alt>>8);o.cpu.cAlt=static_cast<std::uint8_t>(r.bc_alt);o.cpu.dAlt=static_cast<std::uint8_t>(r.de_alt>>8);o.cpu.eAlt=static_cast<std::uint8_t>(r.de_alt);o.cpu.hAlt=static_cast<std::uint8_t>(r.hl_alt>>8);o.cpu.lAlt=static_cast<std::uint8_t>(r.hl_alt);o.cpu.ix=r.ix;o.cpu.iy=r.iy;o.cpu.sp=r.sp;o.cpu.pc=r.pc;o.cpu.i=r.i;o.cpu.r=r.r;o.cpu.interruptMode=r.interrupt_mode;o.cpu.iff1=r.iff1;o.cpu.iff2=r.iff2;o.cpu.halted=cpu.halted();o.cpu.eiDelay=cpu.eiDelay()!=0;o.cpu.memory=bus.memory;o.portInputs=bus.portInputs;o.effects=effects;return o;}
bool normalizeEffects(const CanonicalSemanticLiftedOperation&op,const std::vector<SemanticEffect>&raw,std::vector<SemanticEffect>&out,std::string&error){std::size_t pos=0;for(std::size_t i=0;i<op.bytes.size();++i){if(pos>=raw.size()){error="oracle did not expose complete instruction fetch";return false;}const auto&e=raw[pos++];if(e.kind!=SemanticEffectKind::MemoryRead||e.address!=static_cast<std::uint16_t>(op.sourcePC+i)||e.value!=op.bytes[i]){error="oracle fetch normalization failed at $"+h16(op.sourcePC);return false;}}for(;pos<raw.size();++pos){auto e=raw[pos];e.sequence=out.size();out.push_back(e);}if(op.mnemonic=="DI"||op.mnemonic=="EI"||op.mnemonic=="IM"){SemanticEffect e;e.sequence=out.size();e.kind=SemanticEffectKind::InterruptControl;e.sourcePC=op.sourcePC;if(op.mnemonic=="EI")e.value=1;else if(op.mnemonic=="IM"){if(op.operands.find('2')!=std::string::npos)e.value=2;else if(op.operands.find('1')!=std::string::npos)e.value=1;}out.push_back(e);}error.clear();return true;}

} // namespace

std::string CanonicalSemanticLift::extensionKindText(CanonicalSemanticExtensionKind k){switch(k){case CanonicalSemanticExtensionKind::IndexedMemory:return"indexed-memory";case CanonicalSemanticExtensionKind::Neg:return"neg";default:return"none";}}
std::string CanonicalSemanticLift::semanticKindText(const CanonicalSemanticLiftedOperation&o){if(o.canonicalSemanticExtension!=CanonicalSemanticExtensionKind::None)return extensionKindText(o.canonicalSemanticExtension);if(o.semanticOracleExtension!=SemanticOracleExtensionKind::None)return SemanticOracleEngine::extensionKindText(o.semanticOracleExtension);return SemanticLiftEngine::semanticKindText(o.baseKind);}

void CanonicalSemanticLift::buildCanonicalLift(const std::vector<std::uint8_t>&program,const std::vector<ReconciliationCanonicalInstructionRecord>&canonical,std::vector<CanonicalSemanticLiftedOperation>&ops,std::vector<CanonicalSemanticLiftedBlock>&blocks,CanonicalSemanticStats&stats){
    ops.clear();blocks.clear();stats.canonicalInstructionStarts=canonical.size();if(canonical.empty())return;Z80Disassembler dis;std::map<std::uint16_t,Instruction> ins;std::set<std::uint16_t> pcs;for(const auto&r:canonical){auto in=dis.decode(program,r.pc);ins[r.pc]=in;pcs.insert(r.pc);}
    std::set<std::uint16_t> leaders;leaders.insert(canonical.front().pc);for(const auto&r:canonical){const auto&in=ins[r.pc];if(in.target>=0&&in.target<0x4000&&pcs.count(static_cast<std::uint16_t>(in.target)))leaders.insert(static_cast<std::uint16_t>(in.target));const auto next=static_cast<std::uint16_t>(r.pc+r.length);if(terminalInstruction(in)&&pcs.count(next))leaders.insert(next);}
    for(std::size_t i=1;i<canonical.size();++i){const auto&prev=canonical[i-1];if(static_cast<std::uint16_t>(prev.pc+prev.length)!=canonical[i].pc)leaders.insert(canonical[i].pc);}
    std::map<std::uint16_t,std::uint16_t> blockByPc;std::size_t i=0;while(i<canonical.size()){const auto start=canonical[i].pc;CanonicalSemanticLiftedBlock b;b.start=start;b.stableId=SemanticLiftEngine::stableBlockId(start);b.fullySupported=true;std::size_t j=i;for(;;){const auto&cr=canonical[j];blockByPc[cr.pc]=start;b.end=static_cast<std::uint16_t>(cr.pc+cr.length);const auto&in=ins[cr.pc];if(terminalInstruction(in)){++j;break;}if(j+1>=canonical.size()){++j;break;}const auto expected=static_cast<std::uint16_t>(cr.pc+cr.length);if(canonical[j+1].pc!=expected||leaders.count(canonical[j+1].pc)){++j;break;}++j;}blocks.push_back(std::move(b));i=j;}
    ops.reserve(canonical.size());for(const auto&cr:canonical){const auto&in=ins[cr.pc];const auto bs=blockByPc[cr.pc];const auto fall=static_cast<std::uint16_t>(cr.pc+cr.length);auto base=SemanticLiftEngine::lowerInstruction(in,bs,fall,ops.size());CanonicalSemanticLiftedOperation o;o.id=ops.size();o.stableId=base.stableId;o.blockId=base.blockId;o.blockStart=base.blockStart;o.sourcePC=base.sourcePC;o.fallthroughPC=base.fallthroughPC;o.baseKind=base.kind;o.bytes=base.bytes;o.mnemonic=base.mnemonic;o.operands=base.operands;o.rawText=base.rawText;o.semanticOracleExtension=semanticOracleExtensionFor(base);o.canonicalSemanticExtension=canonicalSemanticExtensionFor(base);o.supported=base.supported||o.semanticOracleExtension!=SemanticOracleExtensionKind::None||o.canonicalSemanticExtension!=CanonicalSemanticExtensionKind::None;if(base.supported){++stats.semanticLiftPrimitiveOperations;o.note="semantic-lift engine semantic primitive reused";}else if(o.semanticOracleExtension!=SemanticOracleExtensionKind::None){++stats.semanticOracleExtensionOperations;o.note="semantic-oracle analysis exact semantic extension reused";}else if(o.canonicalSemanticExtension!=CanonicalSemanticExtensionKind::None){++stats.canonicalSemanticExtensionOperations;o.note="canonical semantic lift exact canonical extension";}else{o.note="unsupported after canonical semantic lift canonical audit";}if(o.supported)++stats.mechanicallyLiftedInstructions;else ++stats.unsupportedInstructionSemantics;ops.push_back(std::move(o));}
    for(auto&b:blocks){b.fullySupported=true;for(std::size_t k=0;k<ops.size();++k)if(ops[k].blockStart==b.start){b.operationIds.push_back(k);if(!ops[k].supported)b.fullySupported=false;}if(b.fullySupported)++stats.fullySupportedBlocks;}stats.canonicalBlocks=blocks.size();stats.completeCanonicalSemanticCoverage=stats.canonicalInstructionStarts!=0&&stats.mechanicallyLiftedInstructions==stats.canonicalInstructionStarts&&stats.unsupportedInstructionSemantics==0&&stats.fullySupportedBlocks==stats.canonicalBlocks;
}

bool CanonicalSemanticLift::executeLifted(const CanonicalSemanticLiftedOperation&o,SemanticExecutionState&state,std::string&error){if(!o.supported){error="canonical semantic lift operation remains unsupported: "+o.stableId;return false;}if(o.canonicalSemanticExtension!=CanonicalSemanticExtensionKind::None)return executeCanonicalSemanticExtension(o,state,error);SemanticOracleLiftedOperation p;p.id=o.id;p.stableId=o.stableId;p.blockId=o.blockId;p.blockStart=o.blockStart;p.sourcePC=o.sourcePC;p.fallthroughPC=o.fallthroughPC;p.baseKind=o.baseKind;p.extension=o.semanticOracleExtension;p.supported=true;p.bytes=o.bytes;p.mnemonic=o.mnemonic;p.operands=o.operands;p.rawText=o.rawText;p.note=o.note;return SemanticOracleEngine::executeLifted(p,state,error);}

std::vector<CanonicalSemanticOracleRecord> CanonicalSemanticLift::verifyWithIndependentOracle(const std::vector<std::uint8_t>&program,const std::vector<CanonicalSemanticLiftedOperation>&ops,const std::vector<CanonicalSemanticLiftedBlock>&blocks,CanonicalSemanticStats&stats,unsigned snapshotsPerBlock){std::vector<CanonicalSemanticOracleRecord> out;out.reserve(blocks.size());for(const auto&b:blocks){CanonicalSemanticOracleRecord rec;rec.id=out.size();rec.blockId=b.stableId;rec.blockStart=b.start;rec.supported=b.fullySupported;if(!b.fullySupported){rec.diagnostic="block contains unsupported canonical semantics";++stats.independentOracleMismatches;out.push_back(std::move(rec));continue;}bool ok=true;std::string diag;for(unsigned seed=0;seed<snapshotsPerBlock&&ok;++seed){++rec.snapshots;++stats.independentOracleSnapshots;for(auto oid:b.operationIds){if(oid>=ops.size()){ok=false;diag="invalid operation id";break;}const auto&op=ops[oid];auto candidate=SemanticLiftEngine::deterministicSnapshot(program,op.sourcePC,seed+1);OracleBus bus;bus.memory=candidate.cpu.memory;bus.portInputs=candidate.portInputs;bus.currentSourcePC=op.sourcePC;pacemu::Z80 oracle;oracle.connectBus(&bus);loadOracle(oracle,candidate);std::string ee;if(!executeLifted(op,candidate,ee)){ok=false;rec.firstDivergencePC=op.sourcePC;diag="lifted executor: "+ee;break;}const int cycles=oracle.step();if(cycles<=0){ok=false;rec.firstDivergencePC=op.sourcePC;diag="independent oracle failed to execute";break;}std::vector<SemanticEffect> normalized;std::string ne;if(!normalizeEffects(op,bus.rawEffects,normalized,ne)){ok=false;rec.firstDivergencePC=op.sourcePC;diag=ne;break;}const auto reference=oracleState(oracle,bus,normalized);std::string sd;++rec.operationsCompared;++stats.independentOracleOperations;if(!SemanticLiftEngine::compareExecutionStates(reference,candidate,sd)){ok=false;rec.firstDivergencePC=op.sourcePC;diag="oracle divergence at $"+h16(op.sourcePC)+" bytes=[";for(std::size_t q=0;q<op.bytes.size();++q){if(q)diag+=' ';diag+=h8(op.bytes[q]);}diag+="]: "+sd;break;}}}
        rec.accepted=ok;rec.diagnostic=ok?"independent emulator-derived Z80 oracle matches corrected canonical semantic block":diag;if(ok)++stats.independentlyVerifiedBlocks;else ++stats.independentOracleMismatches;out.push_back(std::move(rec));}
    stats.independentOracleComplete=stats.canonicalBlocks!=0&&stats.independentlyVerifiedBlocks==stats.canonicalBlocks&&stats.independentOracleMismatches==0;return out;}

} // namespace pacripper
