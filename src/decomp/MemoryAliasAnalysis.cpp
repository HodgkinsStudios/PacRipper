// PacRipper memory-alias analysis memory-state / writer-alias / pointer-lifecycle proofs
// Created by Jacob Hodgkins

#include "MemoryAliasAnalysis.h"
#include "../disasm/Z80Disassembler.h"

#include <algorithm>
#include <map>
#include <set>
#include <sstream>
#include <tuple>

namespace pacripper {
namespace {

bool writeDirection(IndirectMemoryDirection d){return d==IndirectMemoryDirection::Write||d==IndirectMemoryDirection::ReadWrite;}
bool writeRef(RefAccess a){return a==RefAccess::Write||a==RefAccess::ReadWrite;}

const std::set<std::uint16_t>& frozenInherited(){
    static const std::set<std::uint16_t> s={0x0016,0x001D,0x0715,0x2000,0x2007,0x2390,0x2398,0x294D,0x2950,0x29E1,0x29E4,0x2A91,0x2ABE,0x2AC6,0x3078};
    return s;
}
const std::set<std::uint16_t>& frozenNewlyRooted(){
    static const std::set<std::uint16_t> s={0x0A97,0x2D72,0x2F5B,0x2F60,0x2F6B,0x2F7D,0x2F8F,0x2FA1};
    return s;
}

struct ProofKey {
    std::uint16_t pc=0;
    std::string operand;
    IndirectMemoryDirection direction=IndirectMemoryDirection::Write;
    bool operator<(const ProofKey&o)const{return std::tie(pc,operand,direction)<std::tie(o.pc,o.operand,o.direction);}
};

bool finite(const RootContextAddressProofRecord&p,std::set<std::uint16_t>&d){return p.accepted&&RootContextAnalysis::completeFiniteDomain(p.aggregateAddress,d);}
bool intersects(const std::set<std::uint16_t>&d,std::uint16_t start,std::uint16_t end){for(auto a:d)if(a>=start&&a<end)return true;return false;}

AddressLatticeValue domainRange(std::uint16_t start,std::uint16_t end,std::uint16_t stride,const std::set<std::uint16_t>&proof,const std::string&note){
    AddressLatticeValue a;a.rangeStart=start;a.rangeEnd=end;a.stride=stride?stride:1;a.staticProof=true;a.dynamicOnly=false;a.hasUnknownAlternative=false;a.wraparound=false;a.provenancePCs=proof;a.note=note;
    if(start==end){a.kind=AddressValueKind::Exact;a.values.insert(start);}else if(a.stride==1)a.kind=AddressValueKind::ContiguousRange;else a.kind=AddressValueKind::StridedRange;
    return a;
}

void addProof(MemoryAliasAnalysisResult&out,std::size_t romSize,std::uint16_t pc,const std::string&operand,MemoryAliasProofKind kind,const AddressLatticeValue&address,const std::set<std::uint16_t>&proofPCs,const std::set<std::size_t>&writerIds,const std::string&note,bool gate=true){
    MemoryAliasAddressProofRecord p;p.id=out.addressProofs.size();p.pc=pc;p.operand=operand;p.kind=kind;p.address=address;p.domainClass=RootContextAnalysis::classifyDomain(address,romSize);p.inheritedRootContextBlocker=out.inheritedBlockerPCs.count(pc)!=0;p.newlyRootedRootContextBlocker=out.newlyRootedBlockerPCs.count(pc)!=0;p.sourceInvariant=true;p.writerAliasRecordIds=writerIds;p.proofPCs=proofPCs;p.proofPCs.insert(pc);std::set<std::uint16_t>d;p.exactSingleton=RootContextAnalysis::completeFiniteDomain(address,d)&&d.size()==1;p.accepted=gate&&(p.domainClass==RootContextDomainClass::FiniteRom||p.domainClass==RootContextDomainClass::FiniteNonRom||p.domainClass==RootContextDomainClass::Mixed)&&!address.hasUnknownAlternative;p.note=note;out.addressProofs.push_back(std::move(p));
}

MemoryAliasWriterAliasRecord inventory(const Analyzer&analyzer,const std::set<std::uint16_t>&rooted,const std::vector<RootContextAddressProofRecord>&writerProofs,std::uint16_t start,std::uint16_t end){
    MemoryAliasWriterAliasRecord r;r.start=start;r.end=end;Z80Disassembler dis;
    // Direct absolute writers are exact decoded facts from every system-root reachability analysis rooted PC.
    for(auto pc:rooted){Instruction in=dis.decode(analyzer.program(),pc);for(const auto&m:in.memoryRefs)if(writeRef(m.access)&&m.address>=start&&m.address<end){r.directWriterPCs.insert(pc);r.proofPCs.insert(pc);}}
    // Choose an accepted source-invariant proof over a generic unresolved proof for
    // the same access key, but never discard an unresolved *different* writer.
    std::map<ProofKey,const RootContextAddressProofRecord*> best;
    for(const auto&p:writerProofs){if(!writeDirection(p.direction))continue;ProofKey k{p.pc,p.operand,p.direction};auto it=best.find(k);if(it==best.end()||(p.accepted&&!it->second->accepted)||(p.sourceInvariant&&!it->second->sourceInvariant))best[k]=&p;}
    for(const auto&kv:best){const auto&p=*kv.second;std::set<std::uint16_t>d;if(!finite(p,d)){r.unknownAliasWriterPCs.insert(p.pc);continue;}if(intersects(d,start,end)){r.indirectWriterPCs.insert(p.pc);r.indirectWriterProofIds.insert(p.id);r.proofPCs.insert(p.pc);r.proofPCs.insert(p.proofPCs.begin(),p.proofPCs.end());}}
    r.complete=r.unknownAliasWriterPCs.empty();
    std::ostringstream n;n<<"rooted writer inventory for ["<<Z80Disassembler::hex16(start)<<","<<Z80Disassembler::hex16(static_cast<std::uint16_t>(end-1))<<"]: direct="<<r.directWriterPCs.size()<<", finite indirect aliases="<<r.indirectWriterPCs.size()<<", unresolved indirect writer sites="<<r.unknownAliasWriterPCs.size();if(!r.complete)n<<"; unresolved writer aliases conservatively veto lifecycle proof";r.note=n.str();return r;
}

bool hasDirectExactly(const MemoryAliasWriterAliasRecord&r,const std::set<std::uint16_t>&allowed){for(auto pc:r.directWriterPCs)if(!allowed.count(pc))return false;return true;}

AddressLatticeValue domainSet(const std::set<std::uint16_t>&values,const std::set<std::uint16_t>&proof,const std::string&note){
    AddressLatticeValue a;if(values.empty()){a.kind=AddressValueKind::Unknown;a.staticProof=false;a.note=note;return a;}
    a.kind=values.size()==1?AddressValueKind::Exact:AddressValueKind::FiniteSet;a.values=values;a.rangeStart=*values.begin();a.rangeEnd=*values.rbegin();a.staticProof=true;a.dynamicOnly=false;a.hasUnknownAlternative=false;a.wraparound=false;a.provenancePCs=proof;a.note=note;return a;
}

std::set<std::uint16_t> directCallsTo(const Analyzer&analyzer,const std::set<std::uint16_t>&rooted,std::uint16_t target){
    Z80Disassembler d;std::set<std::uint16_t> out;for(auto pc:rooted){const auto in=d.decode(analyzer.program(),pc);if(in.flow==FlowKind::Call&&!in.indirect&&in.target==target)out.insert(pc);}return out;
}

bool repairedReadDomain(const std::vector<RootContextAddressContextRecord>&contexts,std::uint16_t pc,std::size_t romSize,
                        const std::map<std::uint16_t,std::set<std::uint16_t>>&repairByFrame,
                        std::set<std::uint16_t>&domain,std::set<std::uint16_t>&proofPCs){
    domain.clear();bool saw=false;for(const auto&r:contexts){if(r.pc!=pc||r.direction==IndirectMemoryDirection::Write)continue;saw=true;std::set<std::uint16_t>d;
        if(RootContextAnalysis::completeFiniteDomain(r.address,d)){for(auto a:d)if(static_cast<std::size_t>(a)>=romSize)return false;domain.insert(d.begin(),d.end());proofPCs.insert(r.proofPCs.begin(),r.proofPCs.end());continue;}
        bool fixed=false;for(const auto&kv:repairByFrame){const std::string tag=Z80Disassembler::hex16(kv.first)+"->";if(r.contextKey.find(tag)!=std::string::npos){domain.insert(kv.second.begin(),kv.second.end());proofPCs.insert(kv.first);fixed=true;break;}}
        if(!fixed)return false;
    }return saw&&!domain.empty();
}

bool insn(const Analyzer&a,std::uint16_t pc,const std::string&m,const std::string&ops){Z80Disassembler d;auto i=d.decode(a.program(),pc);return i.mnemonic==m&&i.operands==ops;}
std::uint16_t readWord(const std::vector<std::uint8_t>&rom,std::size_t at){
    if(at+1>=rom.size())return 0xFFFFu;
    return static_cast<std::uint16_t>(rom[at]|(static_cast<std::uint16_t>(rom[at+1])<<8));
}
std::uint16_t scanToSentinel(const std::vector<std::uint8_t>&rom,std::uint16_t start,std::uint8_t sentinel){
    std::size_t p=start;
    while(p<rom.size()&&rom[p]!=sentinel)++p;
    return p<rom.size()?static_cast<std::uint16_t>(p):0xFFFFu;
}

} // namespace

MemoryAliasAnalysisResult MemoryAliasAnalysis::analyze(const Analyzer&analyzer,const std::vector<SystemRootReachabilityRecord>&rootedReachability,const std::vector<RootContextAddressContextRecord>&readContexts,const std::vector<RootContextAddressContextRecord>&writerContexts,const std::vector<RootContextAddressProofRecord>&writerProofs,bool callerInventoryComplete,std::size_t contextOverflowEvents,std::size_t guardTrips,std::size_t unresolvedIndirectControlPCs){
    MemoryAliasAnalysisResult out;out.inheritedBlockerPCs=frozenInherited();out.newlyRootedBlockerPCs=frozenNewlyRooted();
    out.writerContexts=writerContexts;out.writerProofs=writerProofs;out.writerCallerInventoryComplete=callerInventoryComplete;out.writerContextOverflowEvents=contextOverflowEvents;out.writerGuardTrips=guardTrips;out.writerUnresolvedIndirectControlPCs=unresolvedIndirectControlPCs;
    std::set<std::uint16_t>rooted;for(const auto&r:rootedReachability)rooted.insert(r.pc);

    // First-class inventories needed by Tier A.  These are exported even when
    // incomplete so a failed proof says exactly which writer aliases block it.
    const std::pair<std::uint16_t,std::uint16_t> tracked[]={{0x4E0A,0x4E0C},{0x4E73,0x4E75},{0x4C82,0x4C84},{0x4D3B,0x4D3C},{0x4E38,0x4E3A}};
    for(const auto&t:tracked){auto r=inventory(analyzer,rooted,out.writerProofs,t.first,t.second);r.id=out.writerAliases.size();out.writerAliases.push_back(std::move(r));}

    const auto&ptr=out.writerAliases[0];const auto&seed=out.writerAliases[1];const auto&queue=out.writerAliases[2];const auto&shadow=out.writerAliases[4];
    // $4E73 -> $4E0A lifecycle.  The local code constrains B to 0/1 before RST
    // $18, so the seed pointer is one of the two words at $272C/$272E.  $0A97
    // then advances bytewise and stops before consuming the $14 sentinel.
    const bool ptrShape=insn(analyzer,0x270F,"LD","A,B")&&insn(analyzer,0x2710,"RLCA","")&&insn(analyzer,0x2711,"RLCA","")&&insn(analyzer,0x2712,"CPL","")&&insn(analyzer,0x2713,"AND","$01")&&insn(analyzer,0x2715,"LD","B,A")&&insn(analyzer,0x2716,"LD","HL,$272C")&&insn(analyzer,0x2719,"RST","$0018")&&insn(analyzer,0x271A,"LD","($4E73),HL")&&insn(analyzer,0x0883,"LD","HL,($4E73)")&&insn(analyzer,0x0886,"LD","($4E0A),HL")&&insn(analyzer,0x0A94,"LD","HL,($4E0A)")&&insn(analyzer,0x0A97,"LD","A,(HL)")&&insn(analyzer,0x0A98,"CP","$14")&&insn(analyzer,0x0A9A,"RET","Z")&&insn(analyzer,0x0A9B,"INC","HL")&&insn(analyzer,0x0A9C,"LD","($4E0A),HL");
    const auto&rom=analyzer.program();
    // Pointer seeds and terminators are derived from the user's validated ROM.
    const std::uint16_t seed0=readWord(rom,0x272C),seed1=readWord(rom,0x272E);
    const std::uint16_t end0=scanToSentinel(rom,seed0,0x14),end1=scanToSentinel(rom,seed1,0x14);
    const bool tableBytes=seed0<rom.size()&&seed1<rom.size()&&end0<rom.size()&&end1<rom.size();

    // RST $08 zero-fill at $087F intentionally aliases the pointer word before
    // the exact $0886 recomposition.  Accept that known pre-initialization write,
    // but reject any other finite alias or any unknown alias.
    const std::set<std::uint16_t> allowedPtrDirect={0x0886,0x0A9C};
    const std::set<std::uint16_t> allowedPtrIndirect={0x0008,0x0AB9};
    const std::set<std::uint16_t> allowedSeedIndirect={0x0008};
    const std::set<std::uint16_t> allowedShadowIndirect={0x0008,0x0892,0x0AB6};
    bool ptrAliases=ptr.complete&&seed.complete&&shadow.complete&&hasDirectExactly(ptr,allowedPtrDirect)&&hasDirectExactly(seed,{0x271A})&&shadow.directWriterPCs.empty();
    for(auto pc:ptr.indirectWriterPCs)if(!allowedPtrIndirect.count(pc))ptrAliases=false;
    for(auto pc:seed.indirectWriterPCs)if(!allowedSeedIndirect.count(pc))ptrAliases=false;
    for(auto pc:shadow.indirectWriterPCs)if(!allowedShadowIndirect.count(pc))ptrAliases=false;
    const bool ptrSwapClosure=insn(analyzer,0x0889,"LD","HL,$4E0A")&&insn(analyzer,0x088C,"LD","DE,$4E38")&&insn(analyzer,0x088F,"LD","BC,$002E")&&insn(analyzer,0x0892,"LDIR","")&&
        insn(analyzer,0x0AA6,"LD","B,$2E")&&insn(analyzer,0x0AA8,"LD","IX,$4E0A")&&insn(analyzer,0x0AAC,"LD","IY,$4E38")&&insn(analyzer,0x0AB0,"LD","D,(IX+0)")&&insn(analyzer,0x0AB3,"LD","E,(IY+0)")&&insn(analyzer,0x0AB6,"LD","(IY+0),D")&&insn(analyzer,0x0AB9,"LD","(IX+0),E")&&insn(analyzer,0x0AC0,"DJNZ","$0AB0");
    // The only RST-$08 fill capable of touching these words is the boot-wide
    // $4C00-$4FBD clear, which precedes the exact queue/pointer initializers.
    const bool bootPreInit=insn(analyzer,0x235E,"RST","$0008")&&insn(analyzer,0x235F,"RST","$0008")&&insn(analyzer,0x2360,"RST","$0008")&&insn(analyzer,0x2361,"RST","$0008")&&
        insn(analyzer,0x2379,"LD","HL,$4CC0")&&insn(analyzer,0x237C,"LD","($4C80),HL")&&insn(analyzer,0x237F,"LD","($4C82),HL");
    const std::set<std::uint16_t> ptrProof={0x270F,0x2710,0x2711,0x2712,0x2713,0x2715,0x2716,0x2719,0x271A,0x0879,0x087D,0x087F,0x0883,0x0886,0x0A94,0x0A97,0x0A98,0x0A9A,0x0A9B,0x0A9C,0x272C,0x272E,0x007C,0x008C};
    const bool ptrGate=ptrShape&&tableBytes&&ptrAliases&&ptrSwapClosure&&bootPreInit;
    const auto ptrStart=std::min(seed0,seed1),ptrEnd=std::max(end0,end1);
    auto ptrDomain=domainRange(ptrStart,ptrEnd,1,ptrProof,"two statically selected runtime ROM streams, bytewise advance, bounded by decoded $14 sentinels");
    addProof(out,rom.size(),0x0715,"(HL)",MemoryAliasProofKind::MemoryLifecycle,ptrDomain,ptrProof,{ptr.id,seed.id,shadow.id},"$4E0A/$4E0B lifecycle: initialized from the $4E73 seed selected by the masked two-entry $272C table; zero-fill occurs before exact recomposition; subsequent writer only advances to the next byte and the $14 sentinel stops further advance",ptrGate);
    addProof(out,rom.size(),0x0A97,"(HL)",MemoryAliasProofKind::MemoryLifecycle,ptrDomain,ptrProof,{ptr.id,seed.id,shadow.id},"same complete $4E0A/$4E0B pointer lifecycle as $0715",ptrGate);

    // $4C82 queue pointer: exact $4CC0 initialization and two-byte advance with
    // low-byte wrap to $C0.  Both dereferences are RAM, not ROM consumers.
    const bool queueShape=insn(analyzer,0x2379,"LD","HL,$4CC0")&&insn(analyzer,0x237F,"LD","($4C82),HL")&&insn(analyzer,0x238D,"LD","HL,($4C82)")&&insn(analyzer,0x2390,"LD","A,(HL)")&&insn(analyzer,0x2395,"LD","(HL),$FF")&&insn(analyzer,0x2397,"INC","L")&&insn(analyzer,0x2398,"LD","B,(HL)")&&insn(analyzer,0x2399,"LD","(HL),$FF")&&insn(analyzer,0x239B,"INC","L")&&insn(analyzer,0x239C,"JR","NZ,$23A0")&&insn(analyzer,0x239E,"LD","L,$C0")&&insn(analyzer,0x23A0,"LD","($4C82),HL");
    bool queueAliases=queue.complete&&hasDirectExactly(queue,{0x237F,0x23A0});for(auto pc:queue.indirectWriterPCs)if(pc!=0x0008)queueAliases=false;queueAliases=queueAliases&&bootPreInit;
    const std::set<std::uint16_t> qProof={0x2379,0x237F,0x238D,0x2390,0x2395,0x2397,0x2398,0x2399,0x239B,0x239C,0x239E,0x23A0};
    addProof(out,rom.size(),0x2390,"(HL)",MemoryAliasProofKind::MemoryLifecycle,domainRange(0x4CC0,0x4CFE,2,qProof,"queue command-byte addresses"),qProof,{queue.id},"$4C82/$4C83 queue pointer is initialized to $4CC0 and advances by two bytes with low-byte wrap to $C0",queueShape&&queueAliases);
    addProof(out,rom.size(),0x2398,"(HL)",MemoryAliasProofKind::MemoryLifecycle,domainRange(0x4CC1,0x4CFF,2,qProof,"queue parameter-byte addresses"),qProof,{queue.id},"one INC L after the command-byte read gives the odd queue-byte domain",queueShape&&queueAliases);

    // ------------------------------------------------------------------
    // Tier B: callee/return-barrier repairs.
    // ------------------------------------------------------------------
    // context-sensitive root analysis already proves every $0016/$001D context except the two source
    // families below.  Repair only those failed contexts and union them with
    // the verified finite context facts; do not replace the caller inventory.
    std::set<std::uint16_t> rst10Ead,rst18ScoreLo,rst18ScoreHi;
    for(unsigned n=0;n<=0x14;++n)rst10Ead.insert(static_cast<std::uint16_t>(0x0EFD+3u*n));
    for(unsigned off=0;off<=0xFE;off+=2){rst18ScoreLo.insert(static_cast<std::uint16_t>(0x2B17+off));rst18ScoreHi.insert(static_cast<std::uint16_t>(0x2B18+off));}
    std::set<std::uint16_t> rst16Domain,rst1dDomain,rst16Proof,rst1dProof;
    const bool rst16Contexts=repairedReadDomain(readContexts,0x0016,rom.size(),{{0x0909,rst10Ead},{0x1780,rst18ScoreLo}},rst16Domain,rst16Proof);
    const bool rst1dContexts=repairedReadDomain(readContexts,0x001D,rom.size(),{{0x1780,rst18ScoreHi}},rst1dDomain,rst1dProof);
    const bool rstRepairShape=insn(analyzer,0x0010,"ADD","A,L")&&insn(analyzer,0x0016,"LD","A,(HL)")&&
        insn(analyzer,0x0018,"LD","A,B")&&insn(analyzer,0x0019,"ADD","A,A")&&insn(analyzer,0x001A,"RST","$0010")&&insn(analyzer,0x001C,"INC","HL")&&insn(analyzer,0x001D,"LD","D,(HL)")&&
        insn(analyzer,0x0EDB,"LD","HL,$0EFD")&&insn(analyzer,0x0EE1,"CP","$14")&&insn(analyzer,0x0EE5,"LD","A,$14")&&insn(analyzer,0x0EE8,"ADD","A,A")&&insn(analyzer,0x0EE9,"ADD","A,B")&&insn(analyzer,0x0EEA,"RST","$0010")&&
        insn(analyzer,0x2A60,"LD","HL,$2B17")&&insn(analyzer,0x2A63,"RST","$0018")&&insn(analyzer,0x1780,"CALL","$2A5A");
    rst16Proof.insert({0x0010,0x0016,0x0018,0x0019,0x001A,0x0EDB,0x0EE1,0x0EE5,0x0EE8,0x0EE9,0x0EEA,0x0909,0x1780,0x2A60,0x2A63});
    rst1dProof.insert({0x0010,0x0018,0x0019,0x001A,0x001C,0x001D,0x1780,0x2A60,0x2A63});
    addProof(out,rom.size(),0x0016,"(HL)",MemoryAliasProofKind::CalleeMemoryEffect,domainSet(rst16Domain,rst16Proof,"context-sensitive root analysis finite caller domains plus source-local repairs for $0909 and $1780"),rst16Proof,{},"all previously finite RST helper contexts are retained; $0909 is clamped to 21 three-byte table records and $1780's RST-$18 offset is inherently an even 8-bit value",rst16Contexts&&rstRepairShape);
    addProof(out,rom.size(),0x001D,"(HL)",MemoryAliasProofKind::CalleeMemoryEffect,domainSet(rst1dDomain,rst1dProof,"context-sensitive root analysis finite caller domains plus source-local repair for $1780"),rst1dProof,{},"high-byte RST-$18 read is exactly one byte after the repaired finite low-byte domain",rst1dContexts&&rstRepairShape);

    // $2000/$2007: every rooted direct call either sets IY immediately to a
    // work-RAM record or enters through $200F.  The three $200F callers use
    // $4D39/$4D3E, and its $0065->$202D helper preserves IY.
    const std::set<std::uint16_t> calls2000={0x0C5E,0x0CB8,0x0CC9,0x0D23,0x0D3C,0x0D61,0x0DB9,0x0DD0,0x0DF2,0x10DA,0x1132,0x1176,0x1197,0x11E3,0x1204,0x1958,0x1A4A,0x1A64,0x1C24,0x1C3E,0x1CFB,0x1D15,0x1DD2,0x1DEC,0x1EA9,0x1EC3,0x200F,0x298F};
    const std::set<std::uint16_t> calls200f={0x18EC,0x191A,0x2944};
    const std::set<std::uint16_t> iy0={0x4D00,0x4D02,0x4D04,0x4D06,0x4D08,0x4D0A,0x4D0C,0x4D0E,0x4D10,0x4D12,0x4D39,0x4D3E};
    std::set<std::uint16_t> iy1;for(auto a:iy0)iy1.insert(static_cast<std::uint16_t>(a+1));
    const bool movementCalls=directCallsTo(analyzer,rooted,0x2000)==calls2000&&directCallsTo(analyzer,rooted,0x200F)==calls200f;
    const std::pair<std::uint16_t,std::uint16_t> iyLoads[]={{0x0C5A,0x4D00},{0x0CB4,0x4D02},{0x0CC5,0x4D02},{0x0D1F,0x4D04},{0x0D38,0x4D04},{0x0D5D,0x4D04},{0x0DB5,0x4D06},{0x0DCC,0x4D06},{0x0DEE,0x4D06},{0x10D6,0x4D00},{0x112E,0x4D02},{0x1172,0x4D04},{0x1193,0x4D04},{0x11DF,0x4D06},{0x1200,0x4D06},{0x1954,0x4D08},{0x1A46,0x4D12},{0x1A60,0x4D08},{0x1C20,0x4D0A},{0x1C3A,0x4D00},{0x1CF7,0x4D0C},{0x1D11,0x4D02},{0x1DCE,0x4D0E},{0x1DE8,0x4D04},{0x1EA5,0x4D10},{0x1EBF,0x4D06},{0x297F,0x4D3E}};
    bool movementShape=insn(analyzer,0x2000,"LD","A,(IY+0)")&&insn(analyzer,0x2007,"LD","A,(IY+1)")&&insn(analyzer,0x200F,"CALL","$2000")&&insn(analyzer,0x2012,"CALL","$0065")&&insn(analyzer,0x0065,"JP","$202D")&&insn(analyzer,0x202D,"PUSH","AF")&&insn(analyzer,0x2051,"RET","")&&insn(analyzer,0x18E8,"LD","IY,$4D39")&&insn(analyzer,0x1916,"LD","IX,$4D1C")&&insn(analyzer,0x2939,"LD","IY,$4D3E");
    std::set<std::uint16_t> movementProof={0x2000,0x2007,0x200F,0x2012,0x0065,0x202D,0x2051,0x18E8,0x1916,0x2939};
    for(const auto&x:iyLoads){movementShape=movementShape&&insn(analyzer,x.first,"LD","IY,"+Z80Disassembler::hex16(x.second));movementProof.insert(x.first);}
    movementProof.insert(calls2000.begin(),calls2000.end());movementProof.insert(calls200f.begin(),calls200f.end());
    addProof(out,rom.size(),0x2000,"(IY+0)",MemoryAliasProofKind::CalleeMemoryEffect,domainSet(iy0,movementProof,"complete rooted call inventory pins IY to finite movement-record bases"),movementProof,{},"$200F and $0065/$202D preserve IY; no failed context-sensitive root analysis return barrier is allowed to erase the source-local record base",movementCalls&&movementShape);
    addProof(out,rom.size(),0x2007,"(IY+1)",MemoryAliasProofKind::CalleeMemoryEffect,domainSet(iy1,movementProof,"same finite movement-record bases plus one"),movementProof,{},"second coordinate byte is exactly IY+1 for the complete rooted caller set",movementCalls&&movementShape);

    // ------------------------------------------------------------------
    // Tier D: score/display DE lifecycle.
    // ------------------------------------------------------------------
    std::set<std::uint16_t> scoreBytes={0x4E80,0x4E81,0x4E82,0x4E84,0x4E85,0x4E86};
    const std::set<std::uint16_t> scoreProof={0x2A65,0x2A68,0x2A6C,0x2A72,0x2A79,0x2A86,0x2A89,0x2A8A,0x2A8B,0x2A8C,0x2A8F,0x2A91,0x2A96,0x2A98,0x2AAF,0x2AB2,0x2AB5,0x2AB9,0x2ABB,0x2ABE,0x2AC6,0x2ACA,0x2ACB,0x2B0B,0x2B0E,0x2B12,0x2B13,0x2B16};
    const bool scoreShape=insn(analyzer,0x2A65,"CALL","$2B0B")&&insn(analyzer,0x2A79,"EX","DE,HL")&&insn(analyzer,0x2A86,"CALL","$2AAF")&&insn(analyzer,0x2A89,"INC","DE")&&insn(analyzer,0x2A8A,"INC","DE")&&insn(analyzer,0x2A8B,"INC","DE")&&insn(analyzer,0x2A8F,"LD","B,$03")&&insn(analyzer,0x2A91,"LD","A,(DE)")&&insn(analyzer,0x2A96,"DEC","DE")&&insn(analyzer,0x2A98,"DJNZ","$2A91")&&
        insn(analyzer,0x2B0B,"LD","A,($4E09)")&&insn(analyzer,0x2B0E,"LD","HL,$4E80")&&insn(analyzer,0x2B12,"RET","Z")&&insn(analyzer,0x2B13,"LD","HL,$4E84")&&insn(analyzer,0x2B16,"RET","")&&
        insn(analyzer,0x2AB2,"LD","BC,$0304")&&insn(analyzer,0x2ABE,"LD","A,(DE)")&&insn(analyzer,0x2AC6,"LD","A,(DE)")&&insn(analyzer,0x2ACA,"DEC","DE")&&insn(analyzer,0x2ACB,"DJNZ","$2ABE");
    addProof(out,rom.size(),0x2A91,"(DE)",MemoryAliasProofKind::LoopCarriedState,domainSet(scoreBytes,scoreProof,"two three-byte BCD score buffers"),scoreProof,{},"$2B0B chooses $4E80 or $4E84; EX DE,HL makes DE point at +2, $2AAF decrements exactly three times, and the caller increments exactly three times before comparison",scoreShape);
    addProof(out,rom.size(),0x2ABE,"(DE)",MemoryAliasProofKind::LoopCarriedState,domainSet(scoreBytes,scoreProof,"display loop reads the selected three-byte BCD score buffer"),scoreProof,{},"B=$03 and DEC DE once per iteration bound all display-loop reads to the selected three-byte score buffer",scoreShape);
    addProof(out,rom.size(),0x2AC6,"(DE)",MemoryAliasProofKind::LoopCarriedState,domainSet(scoreBytes,scoreProof,"second nibble read uses the same byte before DEC DE"),scoreProof,{},"the second read occurs before the loop's single DEC DE and therefore has the identical finite domain",scoreShape);

    // ------------------------------------------------------------------
    // Tier F: power-on memory self-test.  This is deliberately non-ROM and
    // must never be promoted into semantic ROM closure.
    // ------------------------------------------------------------------
    std::set<std::uint16_t> selfTestDomain;for(unsigned a=0x4000;a<=0x47FF;++a)selfTestDomain.insert(static_cast<std::uint16_t>(a));for(unsigned a=0x4C00;a<=0x4FFF;++a)selfTestDomain.insert(static_cast<std::uint16_t>(a));
    const std::set<std::uint16_t> selfTestProof={0x3042,0x3047,0x3066,0x3067,0x3068,0x306B,0x306F,0x3070,0x3072,0x3078,0x3081,0x3082,0x3083,0x3085,0x3094,0x3095,0x3096,0x3099,0x30A3,0x3154,0x3158,0x315C,0x3160,0x3164,0x3168};
    const std::set<std::uint16_t> allowedSelfTestBases={0x4000,0x4400,0x4C00};
    bool selfTestDescriptors=rom.size()>0x3169;
    for(std::size_t at=0x3154;selfTestDescriptors&&at<=0x3168;at+=4)
        selfTestDescriptors=allowedSelfTestBases.count(readWord(rom,at))!=0;
    const bool selfTestShape=insn(analyzer,0x3042,"LD","SP,$3154")&&insn(analyzer,0x3047,"POP","HL")&&insn(analyzer,0x306F,"POP","HL")&&insn(analyzer,0x3070,"POP","DE")&&insn(analyzer,0x3078,"LD","A,(HL)")&&insn(analyzer,0x3081,"INC","L")&&insn(analyzer,0x3094,"INC","H")&&insn(analyzer,0x3095,"DEC","D")&&insn(analyzer,0x3096,"JP","NZ,$3072")&&selfTestDescriptors;
    addProof(out,rom.size(),0x3078,"(HL)",MemoryAliasProofKind::SelfTestChecksum,domainSet(selfTestDomain,selfTestProof,"power-on RAM/video-RAM self-test descriptors"),selfTestProof,{},"descriptor stack supplies only $4000/$4400/$4C00 bases with D=$04; the nested low-byte/page loops read four 256-byte pages per descriptor, all outside the 16-KiB program ROM",selfTestShape);

    // Tier C ($294D/$2950/$29E1/$29E4) and Tier E command-stream fields remain
    // conservative until their loop/record value induction is complete.

    // Keep all other verified blockers explicit until their Tier B-F invariants
    // meet the same proof standard.  No gap filling or optimistic inheritance.
    for(const auto&p:out.addressProofs)if(p.accepted){if(p.inheritedRootContextBlocker)out.refinedInheritedBlockerPCs.insert(p.pc);if(p.newlyRootedRootContextBlocker)out.refinedNewlyRootedBlockerPCs.insert(p.pc);}
    for(auto pc:out.inheritedBlockerPCs)if(!out.refinedInheritedBlockerPCs.count(pc))out.remainingInheritedBlockerPCs.insert(pc);
    for(auto pc:out.newlyRootedBlockerPCs)if(!out.refinedNewlyRootedBlockerPCs.count(pc))out.remainingNewlyRootedBlockerPCs.insert(pc);
    return out;
}

std::string MemoryAliasAnalysis::proofKindText(MemoryAliasProofKind k){switch(k){case MemoryAliasProofKind::MemoryLifecycle:return"memory-lifecycle";case MemoryAliasProofKind::CalleeMemoryEffect:return"callee-memory-effect";case MemoryAliasProofKind::LoopCarriedState:return"loop-carried-state";case MemoryAliasProofKind::CommandStreamPointer:return"command-stream-pointer";case MemoryAliasProofKind::SelfTestChecksum:return"self-test-checksum";}return"unknown";}
bool MemoryAliasAnalysis::completeWriterInventory(const MemoryAliasWriterAliasRecord&r){return r.complete&&r.unknownAliasWriterPCs.empty();}
bool MemoryAliasAnalysis::semanticRomClosureEligible(const MemoryAliasAddressProofRecord&p){return p.accepted&&p.kind!=MemoryAliasProofKind::SelfTestChecksum&&p.domainClass==RootContextDomainClass::FiniteRom&&!p.address.hasUnknownAlternative&&p.address.staticProof&&!p.address.dynamicOnly;}

} // namespace pacripper
