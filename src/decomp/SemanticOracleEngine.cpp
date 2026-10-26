// PacRipper semantic-oracle analysis complete rooted semantic lift + independent oracle
// Created by Jacob Hodgkins

#include "SemanticOracleEngine.h"
#include "../reference/pacemu/cpu/Z80.h"

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <sys/stat.h>
#include <utility>

namespace pacripper {
namespace {

std::string h8(std::uint8_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(2)<<std::setfill('0')<<(unsigned)v;return o.str();}
std::string h16(std::uint16_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(4)<<std::setfill('0')<<(unsigned)v;return o.str();}
std::uint16_t getBC(const SemanticMachineState&s){return static_cast<std::uint16_t>((s.b<<8)|s.c);}
std::uint16_t getDE(const SemanticMachineState&s){return static_cast<std::uint16_t>((s.d<<8)|s.e);}
std::uint16_t getHL(const SemanticMachineState&s){return static_cast<std::uint16_t>((s.h<<8)|s.l);}
void setBC(SemanticMachineState&s,std::uint16_t v){s.b=static_cast<std::uint8_t>(v>>8);s.c=static_cast<std::uint8_t>(v);}
void setDE(SemanticMachineState&s,std::uint16_t v){s.d=static_cast<std::uint8_t>(v>>8);s.e=static_cast<std::uint8_t>(v);}
void setHL(SemanticMachineState&s,std::uint16_t v){s.h=static_cast<std::uint8_t>(v>>8);s.l=static_cast<std::uint8_t>(v);}
void incrementR(SemanticMachineState&s,unsigned count){const auto top=static_cast<std::uint8_t>(s.r&0x80);const auto low=static_cast<std::uint8_t>(((s.r&0x7F)+count)&0x7F);s.r=static_cast<std::uint8_t>(top|low);}
void addEffect(SemanticExecutionState&st,SemanticEffectKind kind,std::uint16_t address,std::uint8_t value,std::uint16_t pc){SemanticEffect e;e.sequence=st.effects.size();e.kind=kind;e.address=address;e.value=value;e.sourcePC=pc;st.effects.push_back(e);}
std::uint8_t read8(SemanticExecutionState&st,std::uint16_t address,std::uint16_t pc){const auto v=st.cpu.memory[address];addEffect(st,SemanticEffectKind::MemoryRead,address,v,pc);return v;}
void write8(SemanticExecutionState&st,std::uint16_t address,std::uint8_t value,std::uint16_t pc){st.cpu.memory[address]=value;addEffect(st,SemanticEffectKind::MemoryWrite,address,value,pc);}

SemanticOracleExtensionKind extensionFor(const SemanticLiftedOperation&op){
    if(op.bytes.size()==2&&op.bytes[0]==0xCB){
        const auto cb=op.bytes[1];
        if((cb>>6)==1u&&(cb&7u)==6u&&op.mnemonic=="BIT")return SemanticOracleExtensionKind::BitIndirectHl;
    }
    if(op.bytes.size()!=2||op.bytes[0]!=0xED)return SemanticOracleExtensionKind::None;
    if(op.bytes[1]==0xA0&&op.mnemonic=="LDI")return SemanticOracleExtensionKind::Ldi;
    if(op.bytes[1]==0xB0&&op.mnemonic=="LDIR")return SemanticOracleExtensionKind::Ldir;
    if(op.bytes[1]==0xB1&&op.mnemonic=="CPIR")return SemanticOracleExtensionKind::Cpir;
    return SemanticOracleExtensionKind::None;
}

bool executeExtension(const SemanticOracleLiftedOperation&op,SemanticExecutionState&st,std::string&error){
    if(op.extension==SemanticOracleExtensionKind::None){error="no semantic-oracle analysis extension semantics for "+op.stableId;return false;}
    const bool oldDelay=st.cpu.eiDelay;
    st.cpu.eiDelay=false;
    incrementR(st.cpu,2);
    if(op.extension==SemanticOracleExtensionKind::BitIndirectHl){
        const auto cb=op.bytes[1];
        const unsigned bit=(cb>>3)&7u;
        const auto value=read8(st,getHL(st.cpu),op.sourcePC);
        std::uint8_t f=static_cast<std::uint8_t>((st.cpu.f&SemanticFlagC)|SemanticFlagH);
        const bool clear=(value&(1u<<bit))==0;
        if(clear)f|=SemanticFlagZ|SemanticFlagPV;
        if(bit==7&&!clear)f|=SemanticFlagS;
        f|=static_cast<std::uint8_t>(value&(SemanticFlagX|SemanticFlagY));
        st.cpu.f=f;st.cpu.pc=op.fallthroughPC;
    }else if(op.extension==SemanticOracleExtensionKind::Ldi||op.extension==SemanticOracleExtensionKind::Ldir){
        const auto source=getHL(st.cpu);const auto dest=getDE(st.cpu);const auto value=read8(st,source,op.sourcePC);write8(st,dest,value,op.sourcePC);
        setHL(st.cpu,static_cast<std::uint16_t>(source+1));setDE(st.cpu,static_cast<std::uint16_t>(dest+1));
        const auto bc=static_cast<std::uint16_t>(getBC(st.cpu)-1);setBC(st.cpu,bc);
        const auto sum=static_cast<std::uint8_t>(st.cpu.a+value);
        std::uint8_t f=static_cast<std::uint8_t>(st.cpu.f&(SemanticFlagS|SemanticFlagZ|SemanticFlagC));
        if(bc!=0) f|=SemanticFlagPV;
        if(sum&0x08) f|=SemanticFlagX;
        if(sum&0x02) f|=SemanticFlagY;
        st.cpu.f=f;
        st.cpu.pc=(op.extension==SemanticOracleExtensionKind::Ldir&&bc!=0)?op.sourcePC:op.fallthroughPC;
    }else{
        const auto source=getHL(st.cpu);const auto value=read8(st,source,op.sourcePC);const auto av=st.cpu.a;const auto result=static_cast<std::uint8_t>(av-value);const bool half=((av^value^result)&0x10)!=0;
        setHL(st.cpu,static_cast<std::uint16_t>(source+1));const auto bc=static_cast<std::uint16_t>(getBC(st.cpu)-1);setBC(st.cpu,bc);
        std::uint8_t f=static_cast<std::uint8_t>((st.cpu.f&SemanticFlagC)|SemanticFlagN|(result&SemanticFlagS));
        if(result==0) f|=SemanticFlagZ;
        if(half) f|=SemanticFlagH;
        if(bc!=0) f|=SemanticFlagPV;
        const auto adjusted=static_cast<std::uint8_t>(result-(half?1:0));
        if(adjusted&0x08) f|=SemanticFlagX;
        if(adjusted&0x02) f|=SemanticFlagY;
        st.cpu.f=f;
        st.cpu.pc=(bc!=0&&result!=0)?op.sourcePC:op.fallthroughPC;
    }
    if(oldDelay)st.cpu.eiDelay=false;
    error.clear();return true;
}

bool mirrorMatch(std::uint16_t address,std::uint16_t start,std::uint16_t end,std::uint16_t mirror,std::uint16_t&offset){const auto canonical=static_cast<std::uint16_t>(address&static_cast<std::uint16_t>(~mirror));if(canonical<start||canonical>end)return false;offset=static_cast<std::uint16_t>(canonical-start);return true;}

struct OracleBus final:pacemu::Z80Bus {
    std::array<std::uint8_t,65536> memory{};
    std::array<std::uint8_t,256> portInputs{};
    std::vector<SemanticEffect> rawEffects;
    std::uint16_t currentSourcePC=0;
    std::uint8_t vectorLatch=0;
    std::uint8_t read8(std::uint16_t address) override{const auto value=memory[address];SemanticEffect e;e.sequence=rawEffects.size();e.kind=SemanticEffectKind::MemoryRead;e.address=address;e.value=value;e.sourcePC=currentSourcePC;rawEffects.push_back(e);return value;}
    void write8(std::uint16_t address,std::uint8_t value) override{memory[address]=value;SemanticEffect e;e.sequence=rawEffects.size();e.kind=SemanticEffectKind::MemoryWrite;e.address=address;e.value=value;e.sourcePC=currentSourcePC;rawEffects.push_back(e);}
    std::uint8_t ioRead(std::uint16_t port) override{const auto value=portInputs[port&0xFFu];SemanticEffect e;e.sequence=rawEffects.size();e.kind=SemanticEffectKind::PortRead;e.address=port;e.value=value;e.sourcePC=currentSourcePC;rawEffects.push_back(e);return value;}
    void ioWrite(std::uint16_t port,std::uint8_t value) override{if((port&0x00FFu)==0)vectorLatch=value;SemanticEffect e;e.sequence=rawEffects.size();e.kind=SemanticEffectKind::PortWrite;e.address=port;e.value=value;e.sourcePC=currentSourcePC;rawEffects.push_back(e);}
    std::uint8_t interruptAcknowledge(std::uint8_t requestedVector) override{(void)requestedVector;return vectorLatch;}
};

std::uint16_t makePair(std::uint8_t hi,std::uint8_t lo){return static_cast<std::uint16_t>((hi<<8)|lo);}
void loadOracleCpu(pacemu::Z80&cpu,const SemanticExecutionState&state){auto&r=cpu.registersMutable();r.af=makePair(state.cpu.a,state.cpu.f);r.bc=makePair(state.cpu.b,state.cpu.c);r.de=makePair(state.cpu.d,state.cpu.e);r.hl=makePair(state.cpu.h,state.cpu.l);r.af_alt=makePair(state.cpu.aAlt,state.cpu.fAlt);r.bc_alt=makePair(state.cpu.bAlt,state.cpu.cAlt);r.de_alt=makePair(state.cpu.dAlt,state.cpu.eAlt);r.hl_alt=makePair(state.cpu.hAlt,state.cpu.lAlt);r.ix=state.cpu.ix;r.iy=state.cpu.iy;r.sp=state.cpu.sp;r.pc=state.cpu.pc;r.i=state.cpu.i;r.r=state.cpu.r;r.iff1=state.cpu.iff1;r.iff2=state.cpu.iff2;r.interrupt_mode=state.cpu.interruptMode;}

SemanticExecutionState oracleState(const pacemu::Z80&cpu,const OracleBus&bus,const std::vector<SemanticEffect>&normalized){SemanticExecutionState out;const auto&r=cpu.registers();out.cpu.a=static_cast<std::uint8_t>(r.af>>8);out.cpu.f=static_cast<std::uint8_t>(r.af);out.cpu.b=static_cast<std::uint8_t>(r.bc>>8);out.cpu.c=static_cast<std::uint8_t>(r.bc);out.cpu.d=static_cast<std::uint8_t>(r.de>>8);out.cpu.e=static_cast<std::uint8_t>(r.de);out.cpu.h=static_cast<std::uint8_t>(r.hl>>8);out.cpu.l=static_cast<std::uint8_t>(r.hl);out.cpu.aAlt=static_cast<std::uint8_t>(r.af_alt>>8);out.cpu.fAlt=static_cast<std::uint8_t>(r.af_alt);out.cpu.bAlt=static_cast<std::uint8_t>(r.bc_alt>>8);out.cpu.cAlt=static_cast<std::uint8_t>(r.bc_alt);out.cpu.dAlt=static_cast<std::uint8_t>(r.de_alt>>8);out.cpu.eAlt=static_cast<std::uint8_t>(r.de_alt);out.cpu.hAlt=static_cast<std::uint8_t>(r.hl_alt>>8);out.cpu.lAlt=static_cast<std::uint8_t>(r.hl_alt);out.cpu.ix=r.ix;out.cpu.iy=r.iy;out.cpu.sp=r.sp;out.cpu.pc=r.pc;out.cpu.i=r.i;out.cpu.r=r.r;out.cpu.interruptMode=r.interrupt_mode;out.cpu.iff1=r.iff1;out.cpu.iff2=r.iff2;out.cpu.halted=cpu.halted();out.cpu.eiDelay=cpu.eiDelay()!=0;out.cpu.memory=bus.memory;out.portInputs=bus.portInputs;out.effects=normalized;return out;}

bool appendNormalizedEffects(const SemanticOracleLiftedOperation&op,const std::vector<SemanticEffect>&raw,std::size_t start,std::vector<SemanticEffect>&normalized,std::string&error){std::size_t pos=start;for(std::size_t i=0;i<op.bytes.size();++i){if(pos>=raw.size()){error="oracle did not expose all instruction fetches";return false;}const auto&e=raw[pos];const auto expectedAddress=static_cast<std::uint16_t>(op.sourcePC+i);if(e.kind!=SemanticEffectKind::MemoryRead||e.address!=expectedAddress||e.value!=op.bytes[i]){error="oracle instruction-fetch normalization failed at byte "+std::to_string(i)+" for $"+h16(op.sourcePC);return false;}++pos;}for(;pos<raw.size();++pos){auto e=raw[pos];e.sequence=normalized.size();normalized.push_back(e);}if(op.mnemonic=="DI"||op.mnemonic=="EI"||op.mnemonic=="IM"){SemanticEffect e;e.sequence=normalized.size();e.kind=SemanticEffectKind::InterruptControl;e.address=0;e.sourcePC=op.sourcePC;if(op.mnemonic=="EI")e.value=1;else if(op.mnemonic=="IM"){if(op.operands.find('2')!=std::string::npos)e.value=2;else if(op.operands.find('1')!=std::string::npos)e.value=1;else e.value=0;}normalized.push_back(e);}error.clear();return true;}

std::string commentText(std::string s){for(char&c:s)if(c=='\n'||c=='\r')c=' ';return s;}
std::string bytesInitializer(const std::vector<std::uint8_t>&bytes){std::ostringstream o;for(std::size_t i=0;i<bytes.size();++i){if(i)o<<",";o<<"0x"<<h8(bytes[i]);}return o.str();}

} // namespace

std::uint8_t SemanticOraclePacmanBoard::readMemory(const SemanticOracleBoardState&s,std::uint16_t a){std::uint16_t off=0;if(mirrorMatch(a,0x0000,0x3FFF,0x8000,off))return s.rom[off];if(mirrorMatch(a,0x4000,0x43FF,0xA000,off))return s.videoRam[off];if(mirrorMatch(a,0x4400,0x47FF,0xA000,off))return s.colorRam[off];if(mirrorMatch(a,0x4800,0x4BFF,0xA000,off))return 0xBF;if(mirrorMatch(a,0x4C00,0x4FEF,0xA000,off))return s.workRam[off];if(mirrorMatch(a,0x4FF0,0x4FFF,0xA000,off))return s.spriteRam[off];if(mirrorMatch(a,0x5000,0x5000,0xAF3F,off))return s.inputPorts[0];if(mirrorMatch(a,0x5040,0x5040,0xAF3F,off))return s.inputPorts[1];if(mirrorMatch(a,0x5080,0x5080,0xAF3F,off))return s.inputPorts[2];if(mirrorMatch(a,0x50C0,0x50C0,0xAF3F,off))return s.inputPorts[3];return 0xFF;}
void SemanticOraclePacmanBoard::writeMemory(SemanticOracleBoardState&s,std::uint16_t a,std::uint8_t v){std::uint16_t off=0;if(mirrorMatch(a,0x4000,0x43FF,0xA000,off)){s.videoRam[off]=v;return;}if(mirrorMatch(a,0x4400,0x47FF,0xA000,off)){s.colorRam[off]=v;return;}if(mirrorMatch(a,0x4800,0x4BFF,0xA000,off))return;if(mirrorMatch(a,0x4C00,0x4FEF,0xA000,off)){s.workRam[off]=v;return;}if(mirrorMatch(a,0x4FF0,0x4FFF,0xA000,off)){s.spriteRam[off]=v;return;}if(mirrorMatch(a,0x5000,0x5007,0xAF38,off)){const auto bit=static_cast<std::size_t>(off&7u);const auto previous=s.outputLatch[bit];s.outputLatch[bit]=static_cast<std::uint8_t>(v&1u);if(bit==0)s.irqEnable=s.outputLatch[bit]!=0;else if(bit==1)s.soundEnable=s.outputLatch[bit]!=0;else if(bit==3)s.flipScreen=s.outputLatch[bit]!=0;else if(bit==7&&previous==0&&s.outputLatch[bit]!=0)++s.coinCounterPulses;return;}if(mirrorMatch(a,0x5040,0x505F,0xAF00,off)){s.soundRegisters[off]=v;return;}if(mirrorMatch(a,0x5060,0x506F,0xAF00,off)){s.spriteCoords[off]=v;return;}if(mirrorMatch(a,0x5070,0x507F,0xAF00,off))return;if(mirrorMatch(a,0x5080,0x5080,0xAF3F,off))return;if(mirrorMatch(a,0x50C0,0x50C0,0xAF3F,off)){++s.watchdogWrites;return;}}
std::uint8_t SemanticOraclePacmanBoard::readPort(const SemanticOracleBoardState&,std::uint16_t){return 0xFF;}
void SemanticOraclePacmanBoard::writePort(SemanticOracleBoardState&s,std::uint16_t port,std::uint8_t value){if((port&0x00FFu)==0)s.vectorLatch=value;}
std::uint8_t SemanticOraclePacmanBoard::interruptAcknowledge(const SemanticOracleBoardState&s){return s.vectorLatch;}

std::string SemanticOracleEngine::extensionKindText(SemanticOracleExtensionKind kind){switch(kind){case SemanticOracleExtensionKind::Ldi:return"ldi";case SemanticOracleExtensionKind::Ldir:return"ldir";case SemanticOracleExtensionKind::Cpir:return"cpir";case SemanticOracleExtensionKind::BitIndirectHl:return"bit_indirect_hl";default:return"none";}}
std::string SemanticOracleEngine::semanticKindText(const SemanticOracleLiftedOperation&op){return op.extension==SemanticOracleExtensionKind::None?SemanticLiftEngine::semanticKindText(op.baseKind):extensionKindText(op.extension);}

void SemanticOracleEngine::liftFromSemanticLift(const std::vector<SemanticLiftedOperation>&semanticOperations,const std::vector<SemanticLiftedBlock>&semanticBlocks,std::vector<SemanticOracleLiftedOperation>&ops,std::vector<SemanticOracleLiftedBlock>&blocks,SemanticOracleStats&stats){ops.clear();blocks.clear();stats.rootedCodeInstructions=semanticOperations.size();ops.reserve(semanticOperations.size());for(const auto&old:semanticOperations){SemanticOracleLiftedOperation o;o.id=old.id;o.stableId=old.stableId;o.blockId=old.blockId;o.blockStart=old.blockStart;o.sourcePC=old.sourcePC;o.fallthroughPC=old.fallthroughPC;o.baseKind=old.kind;o.extension=extensionFor(old);o.supported=old.supported||o.extension!=SemanticOracleExtensionKind::None;o.bytes=old.bytes;o.mnemonic=old.mnemonic;o.operands=old.operands;o.rawText=old.rawText;if(old.supported&&o.extension==SemanticOracleExtensionKind::None)o.note="semantic-lift engine semantic operation preserved unchanged";else if(old.supported)o.note="semantic-oracle analysis independent-oracle correction overlay; verified semantic-lift engine record preserved";else if(o.supported)o.note="semantic-oracle analysis exact ED block semantic extension";else o.note="still unsupported after semantic-oracle analysis extension audit";if(o.supported)++stats.mechanicallyLiftedInstructions;else ++stats.unsupportedInstructionSemantics;ops.push_back(std::move(o));}blocks.reserve(semanticBlocks.size());for(const auto&old:semanticBlocks){SemanticOracleLiftedBlock b;b.stableId=old.stableId;b.start=old.start;b.end=old.end;b.operationIds=old.operationIds;b.fullySupported=true;for(auto id:b.operationIds)if(id>=ops.size()||!ops[id].supported){b.fullySupported=false;break;}if(b.fullySupported)++stats.fullySupportedBlocks;blocks.push_back(std::move(b));}stats.liftedBlocks=blocks.size();stats.completeRootedSemanticCoverage=stats.rootedCodeInstructions!=0&&stats.mechanicallyLiftedInstructions==stats.rootedCodeInstructions&&stats.unsupportedInstructionSemantics==0&&stats.fullySupportedBlocks==stats.liftedBlocks;stats.boardBoundaryModelPresent=true;}

bool SemanticOracleEngine::executeLifted(const SemanticOracleLiftedOperation&op,SemanticExecutionState&state,std::string&error){if(!op.supported){error="semantic-oracle analysis operation remains unsupported: "+op.stableId;return false;}if(op.extension!=SemanticOracleExtensionKind::None)return executeExtension(op,state,error);SemanticLiftedOperation base;base.id=op.id;base.stableId=op.stableId;base.blockId=op.blockId;base.blockStart=op.blockStart;base.sourcePC=op.sourcePC;base.fallthroughPC=op.fallthroughPC;base.kind=op.baseKind;base.supported=true;base.bytes=op.bytes;base.mnemonic=op.mnemonic;base.operands=op.operands;base.rawText=op.rawText;base.note=op.note;return SemanticLiftEngine::executeLifted(base,state,error);}

std::vector<SemanticOracleOracleRecord> SemanticOracleEngine::verifyWithIndependentOracle(
    const std::vector<std::uint8_t>&program,const std::vector<SemanticOracleLiftedOperation>&ops,
    const std::vector<SemanticOracleLiftedBlock>&blocks,SemanticOracleStats&stats,unsigned snapshotsPerBlock){
    std::vector<SemanticOracleOracleRecord>out;out.reserve(blocks.size());
    for(const auto&block:blocks){
        SemanticOracleOracleRecord rec;rec.id=out.size();rec.blockId=block.stableId;rec.blockStart=block.start;rec.supported=block.fullySupported;
        if(!block.fullySupported){rec.diagnostic="block still contains unsupported semantic-oracle analysis semantics";out.push_back(std::move(rec));continue;}
        bool ok=true;std::string diag;
        for(unsigned seed=0;seed<snapshotsPerBlock&&ok;++seed){
            auto candidate=SemanticLiftEngine::deterministicSnapshot(program,block.start,seed+1);
            if(candidate.cpu.halted||candidate.cpu.eiDelay){ok=false;diag="oracle seed requires unsupported private initial HALT/EI-delay injection";break;}
            OracleBus bus;bus.memory=candidate.cpu.memory;bus.portInputs=candidate.portInputs;pacemu::Z80 oracle;oracle.connectBus(&bus);loadOracleCpu(oracle,candidate);
            std::vector<SemanticEffect>normalized;++rec.snapshots;++stats.independentOracleSnapshots;
            for(std::size_t opIndex=0;opIndex<block.operationIds.size();++opIndex){
                const auto oid=block.operationIds[opIndex];
                if(oid>=ops.size()){ok=false;diag="invalid semantic-oracle analysis operation id";break;}
                const auto&op=ops[oid];
                const bool mustReachNextOperation=opIndex+1<block.operationIds.size();
                if(candidate.cpu.pc!=op.sourcePC||oracle.registers().pc!=op.sourcePC){ok=false;rec.firstDivergencePC=op.sourcePC;rec.firstDivergenceBytes=op.bytes;diag="block-boundary PC mismatch before $"+h16(op.sourcePC);break;}
                std::size_t repeatSteps=0;
                for(;;){
                    std::string candidateError;if(!executeLifted(op,candidate,candidateError)){ok=false;rec.firstDivergencePC=op.sourcePC;rec.firstDivergenceBytes=op.bytes;diag="semantic-oracle analysis lifted executor: "+candidateError;break;}
                    bus.currentSourcePC=op.sourcePC;const auto rawStart=bus.rawEffects.size();const int cycles=oracle.step();
                    if(cycles<=0){ok=false;rec.firstDivergencePC=op.sourcePC;rec.firstDivergenceBytes=op.bytes;diag="independent oracle failed to execute instruction";break;}
                    std::string normalizeError;if(!appendNormalizedEffects(op,bus.rawEffects,rawStart,normalized,normalizeError)){ok=false;rec.firstDivergencePC=op.sourcePC;rec.firstDivergenceBytes=op.bytes;diag=normalizeError;break;}
                    ++rec.operationsCompared;++stats.independentOracleOperations;
                    const auto reference=oracleState(oracle,bus,normalized);std::string stateDiag;
                    if(!SemanticLiftEngine::compareExecutionStates(reference,candidate,stateDiag)){ok=false;rec.firstDivergencePC=op.sourcePC;rec.firstDivergenceBytes=op.bytes;diag="oracle divergence at $"+h16(op.sourcePC)+" bytes=[";for(std::size_t i=0;i<op.bytes.size();++i){if(i)diag+=' ';diag+=h8(op.bytes[i]);}diag+="]: "+stateDiag;break;}
                    const bool repeatable=op.extension==SemanticOracleExtensionKind::Ldir||op.extension==SemanticOracleExtensionKind::Cpir;
                    const bool candidateRepeats=repeatable&&candidate.cpu.pc==op.sourcePC;
                    const bool oracleRepeats=repeatable&&oracle.registers().pc==op.sourcePC;
                    if(candidateRepeats!=oracleRepeats){ok=false;rec.firstDivergencePC=op.sourcePC;rec.firstDivergenceBytes=op.bytes;diag="repeat-boundary disagreement at $"+h16(op.sourcePC);break;}
                    if(!candidateRepeats||!mustReachNextOperation)break;
                    if(++repeatSteps>=65536u){ok=false;rec.firstDivergencePC=op.sourcePC;rec.firstDivergenceBytes=op.bytes;diag="repeat instruction exceeded 65536 execution steps";break;}
                }
                if(!ok)break;
            }
        }
        rec.accepted=ok;rec.diagnostic=ok?"independent user-supplied-emulator Z80 oracle matches lifted state/effects at every compared instruction boundary, including repeat iterations":diag;
        if(ok)++stats.independentlyVerifiedBlocks;else ++stats.independentOracleMismatches;out.push_back(std::move(rec));
    }
    return out;
}

std::vector<SemanticOracleGeneratedSourceRecord> SemanticOracleEngine::buildGeneratedSourceMap(const std::vector<SemanticOracleLiftedOperation>&ops){std::vector<SemanticOracleGeneratedSourceRecord>out;out.reserve(ops.size());for(const auto&op:ops){SemanticOracleGeneratedSourceRecord r;r.id=out.size();r.blockId=op.blockId;r.operationId=op.stableId;r.blockStart=op.blockStart;r.sourcePC=op.sourcePC;r.fallthroughPC=op.fallthroughPC;r.semanticKind=semanticKindText(op);r.bytes=op.bytes;r.generatedFunction=op.blockId;out.push_back(std::move(r));}return out;}

bool SemanticOracleEngine::emitGeneratedCorpus(const std::string&dir,const std::vector<SemanticOracleLiftedOperation>&ops,const std::vector<SemanticOracleLiftedBlock>&blocks,std::vector<SemanticOracleGeneratedSourceRecord>&sourceMap,std::string&error){std::error_code ec;const std::filesystem::path outputDir(dir);if(!std::filesystem::is_directory(outputDir,ec)){ec.clear();if(!std::filesystem::create_directories(outputDir,ec)&&!std::filesystem::is_directory(outputDir)){error="Failed creating generated C++ directory: "+(ec?ec.message():std::string("unknown filesystem error"));return false;}}sourceMap=buildGeneratedSourceMap(ops);std::ofstream h((dir+"/SemanticOracleGeneratedBlocks.h").c_str());if(!h){error="Failed writing generated header";return false;}h<<"#pragma once\n// Generated by PacRipper semantic-oracle analysis. Not original Namco source.\n// Created by Jacob Hodgkins\n\n#include <array>\n#include <cstddef>\n#include <cstdint>\n#include <string_view>\n\nnamespace pacripper_generated {\n"
 <<"struct MachineState { std::uint8_t a=0,f=0,b=0,c=0,d=0,e=0,h=0,l=0,a_alt=0,f_alt=0,b_alt=0,c_alt=0,d_alt=0,e_alt=0,h_alt=0,l_alt=0; std::uint16_t ix=0,iy=0,sp=0,pc=0; std::uint8_t i=0,r=0,interrupt_mode=0; bool iff1=false,iff2=false,halted=false,ei_delay=false; };\n"
 <<"class BoardIntrinsics { public: virtual ~BoardIntrinsics()=default; virtual std::uint8_t read8(std::uint16_t)=0; virtual void write8(std::uint16_t,std::uint8_t)=0; virtual std::uint8_t ioRead(std::uint16_t)=0; virtual void ioWrite(std::uint16_t,std::uint8_t)=0; virtual std::uint8_t interruptAcknowledge()=0; };\n"
 <<"struct OperationDesc { const char* stable_id; std::uint16_t source_pc; std::uint16_t fallthrough_pc; const char* semantic_kind; const std::uint8_t* raw_bytes; std::size_t raw_size; };\n"
 <<"class SemanticRuntime { public: virtual ~SemanticRuntime()=default; virtual bool execute(const OperationDesc&,MachineState&,BoardIntrinsics&)=0; };\n"
 <<"using BlockFunction=bool(*)(MachineState&,BoardIntrinsics&,SemanticRuntime&);\nstruct BlockDesc { const char* stable_id; std::uint16_t start; std::uint16_t end; BlockFunction function; };\n";
    for(const auto&b:blocks)h<<"bool "<<b.stableId<<"(MachineState&,BoardIntrinsics&,SemanticRuntime&);\n";
    h<<"const std::array<BlockDesc,"<<blocks.size()<<">& allBlocks();\n}\n";if(!h){error="Failed while writing generated header";return false;}
    std::ofstream c((dir+"/SemanticOracleGeneratedBlocks.cpp").c_str());if(!c){error="Failed writing generated source";return false;}c<<"#include \"SemanticOracleGeneratedBlocks.h\"\n\nnamespace pacripper_generated {\n";
    for(const auto&b:blocks){c<<"\nbool "<<b.stableId<<"(MachineState& state,BoardIntrinsics& board,SemanticRuntime& runtime){\n";for(auto oid:b.operationIds){if(oid>=ops.size()){error="Generated block references invalid operation";return false;}const auto&op=ops[oid];c<<"    // source $"<<h16(op.sourcePC)<<" bytes [";for(std::size_t i=0;i<op.bytes.size();++i){if(i)c<<' ';c<<h8(op.bytes[i]);}c<<"] "<<commentText(op.rawText)<<"\n";c<<"    { static constexpr std::uint8_t raw[] = {"<<bytesInitializer(op.bytes)<<"}; const OperationDesc op{\""<<op.stableId<<"\",0x"<<h16(op.sourcePC)<<",0x"<<h16(op.fallthroughPC)<<",\""<<semanticKindText(op)<<"\",raw,sizeof(raw)}; do { if(!runtime.execute(op,state,board)) return false; } while(state.pc==op.source_pc && (std::string_view(op.semantic_kind)==\"ldir\" || std::string_view(op.semantic_kind)==\"cpir\")); if(state.pc!=op.fallthrough_pc) return true; }\n";}c<<"    return true;\n}\n";}
    c<<"\nconst std::array<BlockDesc,"<<blocks.size()<<">& allBlocks(){\n    static const std::array<BlockDesc,"<<blocks.size()<<"> blocks{{\n";for(const auto&b:blocks)c<<"        BlockDesc{\""<<b.stableId<<"\",0x"<<h16(b.start)<<",0x"<<h16(b.end)<<",&"<<b.stableId<<"},\n";c<<"    }};\n    return blocks;\n}\n\n} // namespace pacripper_generated\n";if(!c){error="Failed while writing generated source";return false;}error.clear();return true;}

} // namespace pacripper
