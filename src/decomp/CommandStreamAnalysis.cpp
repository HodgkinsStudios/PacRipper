// PacRipper command-stream memory analysis byte-value memory lattice / command-stream lifecycle proofs
// Created by Jacob Hodgkins

#include "CommandStreamAnalysis.h"
#include "../disasm/Z80Disassembler.h"

#include <algorithm>
#include <deque>
#include <map>
#include <sstream>
#include <tuple>

namespace pacripper {
namespace {

bool writeDirection(IndirectMemoryDirection d){return d==IndirectMemoryDirection::Write||d==IndirectMemoryDirection::ReadWrite;}
bool writeRef(RefAccess a){return a==RefAccess::Write||a==RefAccess::ReadWrite;}

const std::set<std::uint16_t>& inheritedBlockers(){static const std::set<std::uint16_t>s={0x294D,0x2950,0x29E1,0x29E4};return s;}
const std::set<std::uint16_t>& newlyRootedBlockers(){static const std::set<std::uint16_t>s={0x2D72,0x2F5B,0x2F60,0x2F6B,0x2F7D,0x2F8F,0x2FA1};return s;}

struct ProofKey{std::uint16_t pc=0;std::string operand;IndirectMemoryDirection direction=IndirectMemoryDirection::Write;bool operator<(const ProofKey&o)const{return std::tie(pc,operand,direction)<std::tie(o.pc,o.operand,o.direction);}};

bool finite(const RootContextAddressProofRecord&p,std::set<std::uint16_t>&d){return p.accepted&&RootContextAnalysis::completeFiniteDomain(p.aggregateAddress,d);}
bool intersects(const std::set<std::uint16_t>&a,const std::set<std::uint16_t>&b){for(auto v:a)if(b.count(v))return true;return false;}

CommandStreamWriterAliasRecord inventory(const Analyzer&analyzer,const std::set<std::uint16_t>&rooted,const std::vector<RootContextAddressProofRecord>&writerProofs,const std::set<std::uint16_t>&targets){
    CommandStreamWriterAliasRecord r;r.targetAddresses=targets;Z80Disassembler dis;
    for(auto pc:rooted){const auto in=dis.decode(analyzer.program(),pc);for(const auto&m:in.memoryRefs)if(writeRef(m.access)&&targets.count(m.address)){r.directWriterPCs.insert(pc);r.proofPCs.insert(pc);}}
    std::map<ProofKey,const RootContextAddressProofRecord*>best;
    for(const auto&p:writerProofs){if(!writeDirection(p.direction))continue;ProofKey k{p.pc,p.operand,p.direction};auto it=best.find(k);if(it==best.end()||(p.accepted&&!it->second->accepted)||(p.sourceInvariant&&!it->second->sourceInvariant))best[k]=&p;}
    for(const auto&kv:best){const auto&p=*kv.second;std::set<std::uint16_t>d;if(!finite(p,d)){r.unknownAliasWriterPCs.insert(p.pc);continue;}if(intersects(d,targets)){r.indirectWriterPCs.insert(p.pc);r.indirectWriterProofIds.insert(p.id);r.proofPCs.insert(p.pc);r.proofPCs.insert(p.proofPCs.begin(),p.proofPCs.end());}}
    r.complete=r.unknownAliasWriterPCs.empty();std::ostringstream n;n<<"rooted exact-target writer inventory: targets="<<targets.size()<<", direct="<<r.directWriterPCs.size()<<", finite indirect="<<r.indirectWriterPCs.size()<<", unresolved aliases="<<r.unknownAliasWriterPCs.size();r.note=n.str();return r;
}

bool exactly(const std::set<std::uint16_t>&got,const std::set<std::uint16_t>&want){return got==want;}
bool insn(const Analyzer&a,std::uint16_t pc,const std::string&m,const std::string&ops){Z80Disassembler d;const auto i=d.decode(a.program(),pc);return i.mnemonic==m&&i.operands==ops;}
std::uint16_t readWord(const std::vector<std::uint8_t>&rom,std::size_t at){
    if(at+1>=rom.size())return 0xFFFFu;
    return static_cast<std::uint16_t>(rom[at]|(static_cast<std::uint16_t>(rom[at+1])<<8));
}

CommandStreamByteValue finiteByte(const std::set<std::uint8_t>&values,const std::set<std::uint16_t>&pcs,const std::string&note){CommandStreamByteValue v;v.values=values;v.kind=values.size()==1?CommandStreamByteValueKind::Exact:CommandStreamByteValueKind::FiniteSet;v.hasUnknownAlternative=values.empty();v.staticProof=!values.empty();v.dynamicOnly=false;v.provenancePCs=pcs;v.note=note;return v;}

AddressLatticeValue addressSet(const std::set<std::uint16_t>&values,const std::set<std::uint16_t>&pcs,const std::string&note){AddressLatticeValue a;if(values.empty()){a.kind=AddressValueKind::Unknown;a.hasUnknownAlternative=true;a.note=note;return a;}a.kind=values.size()==1?AddressValueKind::Exact:AddressValueKind::FiniteSet;a.values=values;a.rangeStart=*values.begin();a.rangeEnd=*values.rbegin();a.stride=values.size()==1?0:1;a.hasUnknownAlternative=false;a.wraparound=false;a.staticProof=true;a.dynamicOnly=false;a.provenancePCs=pcs;a.note=note;return a;}

void addValueProof(CommandStreamAnalysisResult&out,const std::string&name,const std::set<std::uint16_t>&targets,const CommandStreamByteValue&value,const std::set<std::size_t>&aliases,const std::set<std::uint16_t>&pcs,bool gate,const std::string&note){CommandStreamValueProofRecord p;p.id=out.valueProofs.size();p.name=name;p.targetAddresses=targets;p.value=value;p.writerAliasRecordIds=aliases;p.proofPCs=pcs;p.accepted=gate&&value.staticProof&&!value.dynamicOnly&&!value.hasUnknownAlternative;p.note=note;out.valueProofs.push_back(std::move(p));}

void addAddressProof(CommandStreamAnalysisResult&out,std::size_t romSize,std::uint16_t pc,const std::string&operand,CommandStreamProofKind kind,const std::set<std::uint16_t>&domain,const std::set<std::size_t>&valueIds,const std::set<std::size_t>&aliasIds,const std::set<std::size_t>&streamIds,const std::set<std::uint16_t>&pcs,bool gate,const std::string&note){CommandStreamAddressProofRecord p;p.id=out.addressProofs.size();p.pc=pc;p.operand=operand;p.kind=kind;p.address=addressSet(domain,pcs,note);p.domainClass=RootContextAnalysis::classifyDomain(p.address,romSize);p.inheritedMemoryAliasBlocker=out.inheritedBlockerPCs.count(pc)!=0;p.newlyRootedMemoryAliasBlocker=out.newlyRootedBlockerPCs.count(pc)!=0;p.valueProofIds=valueIds;p.writerAliasRecordIds=aliasIds;p.commandStreamRecordIds=streamIds;p.proofPCs=pcs;p.proofPCs.insert(pc);p.accepted=gate&&p.domainClass==RootContextDomainClass::FiniteRom&&!p.address.hasUnknownAlternative&&p.address.staticProof&&!p.address.dynamicOnly;p.note=note;out.addressProofs.push_back(std::move(p));}

std::set<std::uint16_t> directCallsTo(const Analyzer&analyzer,const std::set<std::uint16_t>&rooted,std::uint16_t target){Z80Disassembler d;std::set<std::uint16_t>out;for(auto pc:rooted){const auto in=d.decode(analyzer.program(),pc);if(in.flow==FlowKind::Call&&!in.indirect&&in.target==target)out.insert(pc);}return out;}

bool rst08SourceInvariantComplete(const std::vector<RootContextAddressProofRecord>&writerProofs){
    const std::set<std::uint16_t> callers={0x087F,0x0A88,0x2358,0x235E,0x235F,0x2360,0x2361,0x2367,0x2386,0x23FB,0x2408,0x2414,0x24D0,0x24D5,0x24E7,0x24F2,0x2661,0x2AEB};
    for(const auto&p:writerProofs){
        if(p.pc==0x0008&&p.sourceInvariant&&p.accepted){
            bool all=true;
            for(auto pc:callers) all=all&&p.proofPCs.count(pc);
            if(all) return true;
        }
    }
    return false;
}

bool rst08FillShape(const Analyzer&a){
    return insn(a,0x0008,"LD","(HL),A")&&insn(a,0x0009,"INC","HL")&&insn(a,0x000A,"DJNZ","$0008")&&
        insn(a,0x0879,"LD","HL,$4E09")&&insn(a,0x087C,"XOR","A")&&insn(a,0x087D,"LD","B,$0B")&&insn(a,0x087F,"RST","$0008")&&
        insn(a,0x0A7C,"XOR","A")&&insn(a,0x0A83,"LD","B,$07")&&insn(a,0x0A85,"LD","HL,$4E0C")&&insn(a,0x0A88,"RST","$0008")&&
        insn(a,0x2351,"XOR","A")&&insn(a,0x2352,"LD","HL,$5000")&&insn(a,0x2355,"LD","BC,$0808")&&insn(a,0x2358,"RST","$0008")&&insn(a,0x2359,"LD","HL,$4C00")&&insn(a,0x235C,"LD","B,$BE")&&insn(a,0x235E,"RST","$0008")&&insn(a,0x235F,"RST","$0008")&&insn(a,0x2360,"RST","$0008")&&insn(a,0x2361,"RST","$0008")&&insn(a,0x2362,"LD","HL,$5040")&&insn(a,0x2365,"LD","B,$40")&&insn(a,0x2367,"RST","$0008")&&
        insn(a,0x2379,"LD","HL,$4CC0")&&insn(a,0x2382,"LD","A,$FF")&&insn(a,0x2384,"LD","B,$40")&&insn(a,0x2386,"RST","$0008")&&
        insn(a,0x23F3,"LD","A,$40")&&insn(a,0x23F5,"LD","BC,$0004")&&insn(a,0x23F8,"LD","HL,$4000")&&insn(a,0x23FB,"RST","$0008")&&insn(a,0x23FC,"DEC","C")&&insn(a,0x23FD,"JR","NZ,$23FB")&&
        insn(a,0x2400,"LD","A,$40")&&insn(a,0x2402,"LD","HL,$4040")&&insn(a,0x2405,"LD","BC,$8004")&&insn(a,0x2408,"RST","$0008")&&insn(a,0x2409,"DEC","C")&&insn(a,0x240A,"JR","NZ,$2408")&&
        insn(a,0x240D,"XOR","A")&&insn(a,0x240E,"LD","BC,$0004")&&insn(a,0x2411,"LD","HL,$4400")&&insn(a,0x2414,"RST","$0008")&&insn(a,0x2415,"DEC","C")&&insn(a,0x2416,"JR","NZ,$2414")&&
        insn(a,0x24C9,"LD","HL,$4E16")&&insn(a,0x24CC,"LD","A,$FF")&&insn(a,0x24CE,"LD","B,$1E")&&insn(a,0x24D0,"RST","$0008")&&insn(a,0x24D1,"LD","A,$14")&&insn(a,0x24D3,"LD","B,$04")&&insn(a,0x24D5,"RST","$0008")&&
        insn(a,0x24E1,"LD","HL,$4440")&&insn(a,0x24E4,"LD","BC,$8004")&&insn(a,0x24E7,"RST","$0008")&&insn(a,0x24EB,"LD","A,$0F")&&insn(a,0x24ED,"LD","B,$40")&&insn(a,0x24EF,"LD","HL,$47C0")&&insn(a,0x24F2,"RST","$0008")&&
        insn(a,0x265A,"LD","HL,$4D28")&&insn(a,0x265D,"LD","A,$02")&&insn(a,0x265F,"LD","B,$09")&&insn(a,0x2661,"RST","$0008")&&
        insn(a,0x2AE5,"XOR","A")&&insn(a,0x2AE6,"LD","HL,$4E80")&&insn(a,0x2AE9,"LD","B,$08")&&insn(a,0x2AEB,"RST","$0008");
}

bool decodeStream(const std::vector<std::uint8_t>&rom,std::uint16_t objectBase,std::uint8_t selector,std::uint16_t root,CommandStreamCommandStreamRecord&rec){
    rec.objectBase=objectBase;rec.selector=selector;rec.root=root;std::deque<std::uint16_t>q;q.push_back(root);std::set<std::uint16_t>seen;std::size_t guard=0;
    while(!q.empty()){
        const auto pc=q.front();q.pop_front();if(seen.count(pc)){rec.hasCycle=true;continue;}if(pc>=rom.size()||++guard>rom.size()){rec.note="stream graph escaped ROM or exceeded finite graph guard";return false;}seen.insert(pc);rec.tokenAddresses.insert(pc);const std::uint8_t op=rom[pc];
        if(op==0xFF)continue;
        if(op==0xF0){if(static_cast<std::size_t>(pc)+2>=rom.size()){rec.note="truncated F0 pointer replacement";return false;}const std::uint16_t lo=static_cast<std::uint16_t>(pc+1),hi=static_cast<std::uint16_t>(pc+2);rec.f0PayloadAddresses.insert(lo);rec.f0PayloadAddresses.insert(hi);const std::uint16_t target=static_cast<std::uint16_t>(rom[lo]|(static_cast<std::uint16_t>(rom[hi])<<8));if(target>=rom.size()){rec.note="F0 replacement target leaves program ROM";return false;}rec.replacementTargets.insert(target);if(seen.count(target))rec.hasCycle=true;q.push_back(target);continue;}
        if(op>=0xF1&&op<=0xF4){if(static_cast<std::size_t>(pc)+1>=rom.size()){rec.note="truncated one-byte command payload";return false;}const std::uint16_t payload=static_cast<std::uint16_t>(pc+1);if(op==0xF1)rec.f1PayloadAddresses.insert(payload);if(op==0xF2)rec.f2PayloadAddresses.insert(payload);if(op==0xF3)rec.f3PayloadAddresses.insert(payload);if(op==0xF4)rec.f4PayloadAddresses.insert(payload);q.push_back(static_cast<std::uint16_t>(pc+2));continue;}
        q.push_back(static_cast<std::uint16_t>(pc+1));
    }
    rec.complete=true;rec.note="closed finite command-stream address graph; F0 replacement edges are followed exactly and revisits are cycles, not widened selector guesses";return true;
}

} // namespace

CommandStreamAnalysisResult CommandStreamAnalysis::analyze(const Analyzer&analyzer,const std::vector<SystemRootReachabilityRecord>&rootedReachability,const std::vector<RootContextAddressProofRecord>&writerProofs,const std::vector<MemoryAliasWriterAliasRecord>&memoryAliasWriterAliases){
    CommandStreamAnalysisResult out;out.inheritedBlockerPCs=inheritedBlockers();out.newlyRootedBlockerPCs=newlyRootedBlockers();const auto&rom=analyzer.program();std::set<std::uint16_t>rooted;for(const auto&r:rootedReachability)rooted.insert(r.pc);

    // Exact writer inventories for the three command flags and their split pointer bytes.
    const std::set<std::uint16_t>flag0={0x4ECC},flag1={0x4EDC},flag2={0x4EEC};
    const std::set<std::uint16_t>ptrLo={0x4ED2,0x4EE2,0x4EF2},ptrHi={0x4ED3,0x4EE3,0x4EF3};
    for(const auto&t:{flag0,flag1,flag2,ptrLo,ptrHi}){auto r=inventory(analyzer,rooted,writerProofs,t);r.id=out.writerAliases.size();out.writerAliases.push_back(std::move(r));}
    const std::set<std::uint16_t>directionBytes={0x4D28,0x4D29,0x4D2A,0x4D2B,0x4D2C,0x4D2D,0x4D2E,0x4D2F,0x4D30,0x4D3C};
    const std::set<std::uint16_t>candidateDirection={0x4D3B};
    for(const auto&t:{directionBytes,candidateDirection}){auto r=inventory(analyzer,rooted,writerProofs,t);r.id=out.writerAliases.size();out.writerAliases.push_back(std::move(r));}
    const auto&a0=out.writerAliases[0];const auto&a1=out.writerAliases[1];const auto&a2=out.writerAliases[2];const auto&alo=out.writerAliases[3];const auto&ahi=out.writerAliases[4];const auto&adir=out.writerAliases[5];const auto&acandidate=out.writerAliases[6];

    // Boot zero-fill is proven by the exact four RST-$08 calls after B=$BE. The
    // final three calls run with B=0, hence 256 bytes each, covering through $4FBD.
    const bool fillComplete=rst08SourceInvariantComplete(writerProofs)&&rst08FillShape(analyzer);
    const bool bootZero=fillComplete&&insn(analyzer,0x2351,"XOR","A")&&insn(analyzer,0x2359,"LD","HL,$4C00")&&insn(analyzer,0x235C,"LD","B,$BE")&&insn(analyzer,0x235E,"RST","$0008")&&insn(analyzer,0x235F,"RST","$0008")&&insn(analyzer,0x2360,"RST","$0008")&&insn(analyzer,0x2361,"RST","$0008")&&insn(analyzer,0x0008,"LD","(HL),A")&&insn(analyzer,0x0009,"INC","HL")&&insn(analyzer,0x000A,"DJNZ","$0008");
    // Direct flag writes set only 0/1/2. $2FB4 is clear-only: (~activeBit)&flag.
    const bool flagShape=bootZero&&insn(analyzer,0x0668,"XOR","A")&&insn(analyzer,0x066C,"INC","A")&&insn(analyzer,0x066D,"LD","($4ECC),A")&&insn(analyzer,0x0670,"LD","($4EDC),A")&&insn(analyzer,0x0A33,"LD","A,$02")&&insn(analyzer,0x0A35,"LD","($4ECC),A")&&insn(analyzer,0x0A38,"LD","($4EDC),A")&&insn(analyzer,0x0A74,"XOR","A")&&insn(analyzer,0x0A75,"LD","($4ECC),A")&&insn(analyzer,0x0A78,"LD","($4EDC),A")&&insn(analyzer,0x0A7C,"XOR","A")&&insn(analyzer,0x0A7D,"LD","($4ECC),A")&&insn(analyzer,0x0A80,"LD","($4EDC),A")&&insn(analyzer,0x2FAD,"LD","A,(IX+2)")&&insn(analyzer,0x2FB0,"CPL","")&&insn(analyzer,0x2FB1,"AND","(IX+0)")&&insn(analyzer,0x2FB4,"LD","(IX+0),A");
    const bool flagAliases=a0.complete&&a1.complete&&a2.complete&&exactly(a0.directWriterPCs,{0x066D,0x0A35,0x0A75,0x0A7D})&&exactly(a1.directWriterPCs,{0x0670,0x0A38,0x0A78,0x0A80})&&a2.directWriterPCs.empty()&&exactly(a0.indirectWriterPCs,{0x0008,0x2FB4})&&exactly(a1.indirectWriterPCs,{0x0008,0x2FB4})&&exactly(a2.indirectWriterPCs,{0x0008,0x2FB4});
    const std::set<std::uint16_t>flagProof={0x0008,0x0009,0x000A,0x2351,0x2359,0x235C,0x235E,0x235F,0x2360,0x2361,0x0668,0x066C,0x066D,0x0670,0x0A33,0x0A35,0x0A38,0x0A74,0x0A75,0x0A78,0x0A7C,0x0A7D,0x0A80,0x2FAD,0x2FB0,0x2FB1,0x2FB4};
    addValueProof(out,"command object 0 flag",flag0,finiteByte({0,1,2},flagProof,"boot initializes zero; direct stores are 0/1/2; only indirect runtime update is bit-clearing"),{0},flagProof,flagShape&&flagAliases,"complete writer/value lifecycle for $4ECC");
    addValueProof(out,"command object 1 flag",flag1,finiteByte({0,1,2},flagProof,"boot initializes zero; direct stores are 0/1/2; only indirect runtime update is bit-clearing"),{1},flagProof,flagShape&&flagAliases,"complete writer/value lifecycle for $4EDC");
    addValueProof(out,"command object 2 flag",flag2,finiteByte({0},flagProof,"boot initializes zero and the only later writer can only clear already-set bits"),{2},flagProof,flagShape&&flagAliases,"complete writer/value lifecycle for $4EEC; it can never acquire a set selector bit");

    // Complete mutation inventory for the split command stream pointer fields.
    const std::set<std::uint16_t>loWriters={0x0008,0x2D74,0x2F5C,0x2F6D,0x2F7F,0x2F91,0x2FA3};
    const std::set<std::uint16_t>hiWriters={0x0008,0x2D77,0x2F61,0x2F70,0x2F82,0x2F94,0x2FA6};
    const bool pointerAliases=alo.complete&&ahi.complete&&alo.directWriterPCs.empty()&&ahi.directWriterPCs.empty()&&exactly(alo.indirectWriterPCs,loWriters)&&exactly(ahi.indirectWriterPCs,hiWriters);
    const bool interpreterShape=insn(analyzer,0x2D44,"LD","A,(IX+0)")&&insn(analyzer,0x2D4B,"LD","C,A")&&insn(analyzer,0x2D4C,"LD","B,$08")&&insn(analyzer,0x2D4E,"LD","E,$80")&&insn(analyzer,0x2D54,"SRL","E")&&insn(analyzer,0x2D56,"DJNZ","$2D50")&&insn(analyzer,0x2D5F,"LD","(IX+2),E")&&insn(analyzer,0x2D63,"RST","$0018")&&insn(analyzer,0x2D6C,"LD","L,(IX+6)")&&insn(analyzer,0x2D6F,"LD","H,(IX+7)")&&insn(analyzer,0x2D72,"LD","A,(HL)")&&insn(analyzer,0x2D73,"INC","HL")&&insn(analyzer,0x2D74,"LD","(IX+6),L")&&insn(analyzer,0x2D77,"LD","(IX+7),H")&&insn(analyzer,0x2D7A,"CP","$F0")&&insn(analyzer,0x2D82,"AND","$0F")&&insn(analyzer,0x2D84,"RST","$0020");
    const bool callerShape=insn(analyzer,0x2CC1,"LD","HL,$3BC8")&&insn(analyzer,0x2CC4,"LD","IX,$4ECC")&&insn(analyzer,0x2CCC,"CALL","$2D44")&&insn(analyzer,0x2CDA,"LD","HL,$3BCC")&&insn(analyzer,0x2CDD,"LD","IX,$4EDC")&&insn(analyzer,0x2CE5,"CALL","$2D44")&&insn(analyzer,0x2CF3,"LD","HL,$3BD0")&&insn(analyzer,0x2CF6,"LD","IX,$4EEC")&&insn(analyzer,0x2CFE,"CALL","$2D44");
    const bool handlers=insn(analyzer,0x2F55,"LD","L,(IX+6)")&&insn(analyzer,0x2F58,"LD","H,(IX+7)")&&insn(analyzer,0x2F5B,"LD","A,(HL)")&&insn(analyzer,0x2F5C,"LD","(IX+6),A")&&insn(analyzer,0x2F5F,"INC","HL")&&insn(analyzer,0x2F60,"LD","A,(HL)")&&insn(analyzer,0x2F61,"LD","(IX+7),A")&&insn(analyzer,0x2F65,"LD","L,(IX+6)")&&insn(analyzer,0x2F6B,"LD","A,(HL)")&&insn(analyzer,0x2F77,"LD","L,(IX+6)")&&insn(analyzer,0x2F7D,"LD","A,(HL)")&&insn(analyzer,0x2F89,"LD","L,(IX+6)")&&insn(analyzer,0x2F8F,"LD","A,(HL)")&&insn(analyzer,0x2F9B,"LD","L,(IX+6)")&&insn(analyzer,0x2FA1,"LD","A,(HL)");
    // The six command-stream roots are read from the authenticated user ROM.
    // Validate only structural properties here; do not duplicate table payload.
    const bool tableShape=rom.size()>0x3BD3&&
        readWord(rom,0x3BC8)<rom.size()&&readWord(rom,0x3BCA)<rom.size()&&
        readWord(rom,0x3BCC)<rom.size()&&readWord(rom,0x3BCE)<rom.size()&&
        readWord(rom,0x3BD0)<rom.size()&&readWord(rom,0x3BD2)<rom.size();
    const bool valueGate=out.valueProofs.size()==3&&out.valueProofs[0].accepted&&out.valueProofs[1].accepted&&out.valueProofs[2].accepted;
    const bool streamGate=pointerAliases&&interpreterShape&&callerShape&&handlers&&tableShape&&valueGate;

    // Only selector bit 0 or 1 can be active for objects 0/1; object 2 is always zero.
    const std::pair<std::uint16_t,std::uint16_t> roots[]={
        {0x4ECC,readWord(rom,0x3BC8)},{0x4ECC,readWord(rom,0x3BCA)},
        {0x4EDC,readWord(rom,0x3BCC)},{0x4EDC,readWord(rom,0x3BCE)}
    };
    std::set<std::uint16_t>allTokens,f1,f2,f3,f4,replacements;bool allComplete=streamGate;
    for(std::size_t i=0;i<4;++i){CommandStreamCommandStreamRecord r;r.id=out.commandStreams.size();const std::uint8_t selector=static_cast<std::uint8_t>(i&1);bool ok=streamGate&&decodeStream(rom,roots[i].first,selector,roots[i].second,r);r.proofPCs={0x2CC1,0x2CC4,0x2CCC,0x2CDA,0x2CDD,0x2CE5,0x2CF3,0x2CF6,0x2CFE,0x2D44,0x2D4B,0x2D4C,0x2D4E,0x2D54,0x2D56,0x2D5F,0x2D63,0x2D6C,0x2D6F,0x2D72,0x2D73,0x2D74,0x2D77,0x2D7A,0x2D82,0x2D84,0x2F55,0x2F5B,0x2F60,0x2F65,0x2F6B,0x2F77,0x2F7D,0x2F89,0x2F8F,0x2F9B,0x2FA1};r.complete=ok;if(!ok&&r.note.empty())r.note="static command lifecycle gate failed";if(ok){allTokens.insert(r.tokenAddresses.begin(),r.tokenAddresses.end());f1.insert(r.f1PayloadAddresses.begin(),r.f1PayloadAddresses.end());f2.insert(r.f2PayloadAddresses.begin(),r.f2PayloadAddresses.end());f3.insert(r.f3PayloadAddresses.begin(),r.f3PayloadAddresses.end());f4.insert(r.f4PayloadAddresses.begin(),r.f4PayloadAddresses.end());replacements.insert(r.replacementTargets.begin(),r.replacementTargets.end());}else allComplete=false;out.commandStreams.push_back(std::move(r));}
    // Regression trap: the old broad 0..7 selector hypothesis produced these words.
    if(replacements.count(0x7082)||replacements.count(0x8269))allComplete=false;
    const std::set<std::size_t>streamIds={0,1,2,3};const std::set<std::size_t>valueIds={0,1,2};const std::set<std::size_t>aliasIds={0,1,2,3,4};
    std::set<std::uint16_t>streamProof={0x2D44,0x2D4B,0x2D4C,0x2D4E,0x2D54,0x2D56,0x2D5F,0x2D63,0x2D6C,0x2D6F,0x2D72,0x2D73,0x2D74,0x2D77,0x2D7A,0x2D82,0x2D84,0x2F55,0x2F5B,0x2F60,0x2F65,0x2F6B,0x2F77,0x2F7D,0x2F89,0x2F8F,0x2F9B,0x2FA1,0x2FAD,0x2FB4,0x3BC8,0x3BCC};
    std::set<std::uint16_t> f0lo,f0hi;
    for(const auto&r:out.commandStreams) if(r.complete) for(auto a:r.tokenAddresses) if(a<rom.size()&&rom[a]==0xF0){f0lo.insert(static_cast<std::uint16_t>(a+1));f0hi.insert(static_cast<std::uint16_t>(a+2));}
    addAddressProof(out,rom.size(),0x2D72,"(HL)",CommandStreamProofKind::CommandStreamGraph,allTokens,valueIds,aliasIds,streamIds,streamProof,allComplete,"finite token-address domain from the four statically reachable command roots and exact F0/F1-F4 grammar");
    addAddressProof(out,rom.size(),0x2F5B,"(HL)",CommandStreamProofKind::CommandStreamGraph,f0lo,valueIds,aliasIds,streamIds,streamProof,allComplete,"F0 low-byte replacement-pointer payloads only");
    addAddressProof(out,rom.size(),0x2F60,"(HL)",CommandStreamProofKind::CommandStreamGraph,f0hi,valueIds,aliasIds,streamIds,streamProof,allComplete,"F0 high-byte replacement-pointer payloads only");
    addAddressProof(out,rom.size(),0x2F6B,"(HL)",CommandStreamProofKind::CommandStreamGraph,f1,valueIds,aliasIds,streamIds,streamProof,allComplete,"F1 one-byte payload domain");
    addAddressProof(out,rom.size(),0x2F7D,"(HL)",CommandStreamProofKind::CommandStreamGraph,f2,valueIds,aliasIds,streamIds,streamProof,allComplete,"F2 one-byte payload domain");
    addAddressProof(out,rom.size(),0x2F8F,"(HL)",CommandStreamProofKind::CommandStreamGraph,f3,valueIds,aliasIds,streamIds,streamProof,allComplete,"F3 one-byte payload domain");
    addAddressProof(out,rom.size(),0x2FA1,"(HL)",CommandStreamProofKind::CommandStreamGraph,f4,valueIds,aliasIds,streamIds,streamProof,allComplete,"F4 one-byte payload domain");

    // Direction bytes are a mutually-inductive four-state lattice.  Complete
    // rooted aliasing contains only direct stores plus RST-$08; the only fills
    // intersecting this family are the boot-zero fill and $2661's exact $02 fill.
    const std::set<std::uint16_t> expectedDirectionDirect={0x05B3,0x0C66,0x0C69,0x0C85,0x0C88,0x0CAD,0x0CD1,0x0CD4,0x0CF0,0x0CF3,0x0D18,0x0D43,0x0D46,0x0D69,0x0D6C,0x0D88,0x0D8B,0x0DAE,0x0DD8,0x0DDB,0x0DFA,0x0DFD,0x0E17,0x0E1A,0x10E2,0x10E5,0x113A,0x113D,0x117E,0x1181,0x119F,0x11A2,0x11B6,0x11B9,0x11EB,0x11EE,0x120B,0x120E,0x1222,0x1225,0x1890,0x18A2,0x194D,0x1A59,0x1ACE,0x1ADD,0x1AED,0x1AFD,0x1C33,0x1D0A,0x1DE1,0x1EB8,0x1F0F,0x1F21,0x1F36,0x1F48,0x1F5D,0x1F6F,0x1F84,0x1F96,0x2166,0x25F1,0x25F4,0x25FA,0x25FD,0x2602,0x2605,0x2662,0x2754,0x2768,0x278A,0x27A5,0x27C7,0x27ED,0x280F,0x2837,0x2851,0x2861,0x287B,0x288B,0x28A5,0x28B5,0x28CF,0x28DF,0x28FA,0x291A};
    const bool dirAliases=adir.complete&&exactly(adir.directWriterPCs,expectedDirectionDirect)&&exactly(adir.indirectWriterPCs,{0x0008});
    const bool dirConstants=insn(analyzer,0x0C64,"LD","A,$03")&&insn(analyzer,0x0C83,"LD","A,$02")&&insn(analyzer,0x0CCF,"LD","A,$03")&&insn(analyzer,0x0CEE,"LD","A,$02")&&insn(analyzer,0x0D42,"XOR","A")&&insn(analyzer,0x0D67,"LD","A,$03")&&insn(analyzer,0x0D86,"LD","A,$02")&&insn(analyzer,0x0DD6,"LD","A,$02")&&insn(analyzer,0x0DF8,"LD","A,$03")&&insn(analyzer,0x0E15,"LD","A,$02")&&insn(analyzer,0x10E0,"LD","A,$01")&&insn(analyzer,0x1138,"LD","A,$01")&&insn(analyzer,0x117C,"LD","A,$01")&&insn(analyzer,0x119D,"LD","A,$02")&&insn(analyzer,0x11B4,"LD","A,$01")&&insn(analyzer,0x11E9,"LD","A,$01")&&insn(analyzer,0x120A,"XOR","A")&&insn(analyzer,0x1220,"LD","A,$01")&&insn(analyzer,0x188E,"LD","A,$02")&&insn(analyzer,0x18A1,"XOR","A")&&insn(analyzer,0x1ACC,"LD","A,$02")&&insn(analyzer,0x1ADC,"XOR","A")&&insn(analyzer,0x1AEB,"LD","A,$03")&&insn(analyzer,0x1AFB,"LD","A,$01")&&insn(analyzer,0x25EE,"LD","HL,$0102")&&insn(analyzer,0x25F1,"LD","($4D28),HL")&&insn(analyzer,0x25F4,"LD","($4D2C),HL")&&insn(analyzer,0x25F7,"LD","HL,$0303")&&insn(analyzer,0x25FA,"LD","($4D2A),HL")&&insn(analyzer,0x25FD,"LD","($4D2E),HL")&&insn(analyzer,0x2600,"LD","A,$02")&&insn(analyzer,0x265D,"LD","A,$02")&&insn(analyzer,0x2661,"RST","$0008")&&insn(analyzer,0x2662,"LD","($4D3C),A");
    const bool dirCopies=insn(analyzer,0x0CAA,"LD","A,($4D2D)")&&insn(analyzer,0x0CAD,"LD","($4D29),A")&&insn(analyzer,0x0D15,"LD","A,($4D2E)")&&insn(analyzer,0x0D18,"LD","($4D2A),A")&&insn(analyzer,0x0DAB,"LD","A,($4D2F)")&&insn(analyzer,0x0DAE,"LD","($4D2B),A")&&insn(analyzer,0x194A,"LD","A,($4D3C)")&&insn(analyzer,0x194D,"LD","($4D30),A")&&insn(analyzer,0x1A56,"LD","A,($4D3C)")&&insn(analyzer,0x1A59,"LD","($4D30),A")&&insn(analyzer,0x1C30,"LD","A,($4D2C)")&&insn(analyzer,0x1C33,"LD","($4D28),A")&&insn(analyzer,0x1D07,"LD","A,($4D2D)")&&insn(analyzer,0x1D0A,"LD","($4D29),A")&&insn(analyzer,0x1DDE,"LD","A,($4D2E)")&&insn(analyzer,0x1DE1,"LD","($4D2A),A")&&insn(analyzer,0x1EB5,"LD","A,($4D2F)")&&insn(analyzer,0x1EB8,"LD","($4D2B),A")&&insn(analyzer,0x2163,"LD","A,($4D3C)")&&insn(analyzer,0x2166,"LD","($4D30),A");
    const bool dirXor=insn(analyzer,0x05AE,"LD","A,($4D30)")&&insn(analyzer,0x05B1,"XOR","$02")&&insn(analyzer,0x05B3,"LD","($4D3C),A")&&insn(analyzer,0x1F0A,"LD","A,($4D28)")&&insn(analyzer,0x1F0D,"XOR","$02")&&insn(analyzer,0x1F0F,"LD","($4D2C),A")&&insn(analyzer,0x1F20,"LD","A,B")&&insn(analyzer,0x1F21,"LD","($4D28),A")&&insn(analyzer,0x1F31,"LD","A,($4D29)")&&insn(analyzer,0x1F34,"XOR","$02")&&insn(analyzer,0x1F36,"LD","($4D2D),A")&&insn(analyzer,0x1F47,"LD","A,B")&&insn(analyzer,0x1F48,"LD","($4D29),A")&&insn(analyzer,0x1F58,"LD","A,($4D2A)")&&insn(analyzer,0x1F5B,"XOR","$02")&&insn(analyzer,0x1F5D,"LD","($4D2E),A")&&insn(analyzer,0x1F6E,"LD","A,B")&&insn(analyzer,0x1F6F,"LD","($4D2A),A")&&insn(analyzer,0x1F7F,"LD","A,($4D2B)")&&insn(analyzer,0x1F82,"XOR","$02")&&insn(analyzer,0x1F84,"LD","($4D2F),A")&&insn(analyzer,0x1F95,"LD","A,B")&&insn(analyzer,0x1F96,"LD","($4D2B),A");
    const std::set<std::uint16_t> calls2966={0x274E,0x2762,0x2784,0x279F,0x27C1,0x27E7,0x2809,0x2831,0x284B,0x2875,0x289F,0x28C9,0x28F4,0x2914};
    const std::set<std::uint16_t> calls291e={0x285B,0x2885,0x28AF,0x28D9};
    const bool dirCalls=directCallsTo(analyzer,rooted,0x2966)==calls2966&&directCallsTo(analyzer,rooted,0x291E)==calls291e;
    const std::pair<std::uint16_t,std::uint16_t> callInputs[]={{0x2748,0x4D2C},{0x275F,0x4D2C},{0x277E,0x4D2D},{0x279C,0x4D2D},{0x27BB,0x4D2E},{0x27E4,0x4D2E},{0x2803,0x4D2F},{0x282E,0x4D2F},{0x2848,0x4D2C},{0x2872,0x4D2D},{0x289C,0x4D2E},{0x28C6,0x4D2F},{0x28F1,0x4D3C},{0x2911,0x4D3C}};
    bool dirCallInputs=true;for(const auto&x:callInputs)dirCallInputs=dirCallInputs&&insn(analyzer,x.first,"LD","A,("+Z80Disassembler::hex16(x.second)+")");
    const bool chooserReturns=insn(analyzer,0x2929,"AND","$03")&&insn(analyzer,0x292E,"LD","(HL),A")&&insn(analyzer,0x295E,"LD","A,(HL)")&&insn(analyzer,0x295F,"INC","A")&&insn(analyzer,0x2960,"AND","$03")&&insn(analyzer,0x2962,"LD","(HL),A")&&insn(analyzer,0x2953,"LD","A,($4D3B)")&&
        insn(analyzer,0x296D,"LD","($4D3B),A")&&insn(analyzer,0x2983,"LD","HL,$4DC7")&&insn(analyzer,0x2986,"LD","(HL),$00")&&insn(analyzer,0x29C0,"LD","A,($4DC7)")&&insn(analyzer,0x29C3,"LD","($4D3B),A")&&insn(analyzer,0x29CD,"INC","(HL)")&&insn(analyzer,0x29CE,"LD","A,$04")&&insn(analyzer,0x29D0,"CP","(HL)")&&insn(analyzer,0x29D1,"JP","NZ,$2988")&&insn(analyzer,0x29D4,"LD","A,($4D3B)");
    const bool resultStores=insn(analyzer,0x2754,"LD","($4D2C),A")&&insn(analyzer,0x2768,"LD","($4D2C),A")&&insn(analyzer,0x278A,"LD","($4D2D),A")&&insn(analyzer,0x27A5,"LD","($4D2D),A")&&insn(analyzer,0x27C7,"LD","($4D2E),A")&&insn(analyzer,0x27ED,"LD","($4D2E),A")&&insn(analyzer,0x280F,"LD","($4D2F),A")&&insn(analyzer,0x2837,"LD","($4D2F),A")&&insn(analyzer,0x2851,"LD","($4D2C),A")&&insn(analyzer,0x2861,"LD","($4D2C),A")&&insn(analyzer,0x287B,"LD","($4D2D),A")&&insn(analyzer,0x288B,"LD","($4D2D),A")&&insn(analyzer,0x28A5,"LD","($4D2E),A")&&insn(analyzer,0x28B5,"LD","($4D2E),A")&&insn(analyzer,0x28CF,"LD","($4D2F),A")&&insn(analyzer,0x28DF,"LD","($4D2F),A")&&insn(analyzer,0x28FA,"LD","($4D3C),A")&&insn(analyzer,0x291A,"LD","($4D3C),A");
    std::set<std::uint16_t> dirProof=expectedDirectionDirect;dirProof.insert({0x0008,0x2359,0x235C,0x235F,0x265A,0x265D,0x265F,0x2661,0x2929,0x2953,0x295E,0x295F,0x2960,0x2962,0x296D,0x2983,0x2986,0x29C0,0x29C3,0x29CD,0x29CE,0x29D0,0x29D1,0x29D4});
    const bool directionGate=fillComplete&&dirAliases&&dirConstants&&dirCopies&&dirXor&&dirCalls&&dirCallInputs&&chooserReturns&&resultStores;
    addValueProof(out,"movement direction byte family",directionBytes,finiteByte({0,1,2,3},dirProof,"least fixed point from boot/initial constants: copies preserve, XOR $02 permutes, $291E masks with $03, and $2966 returns either its finite input or the explicit 0..3 loop counter"),{5},dirProof,directionGate,"complete finite-value induction for movement-direction RAM bytes");

    const bool candidateAliases=acandidate.complete&&exactly(acandidate.directWriterPCs,{0x296D,0x29C3})&&exactly(acandidate.indirectWriterPCs,{0x0008});
    std::set<std::uint16_t>candidateProof={0x2359,0x235C,0x235F,0x296D,0x2983,0x2986,0x29C0,0x29C3,0x29CD,0x29CE,0x29D0,0x29D1,0x29D4};
    const bool directionAccepted=out.valueProofs.size()>3&&out.valueProofs[3].accepted;
    addValueProof(out,"$4D3B candidate direction",candidateDirection,finiteByte({0,1,2,3},candidateProof,"boot writes zero; $296D receives only a proven direction byte; $29C3 receives the loop counter before its 4 terminator"),{6},candidateProof,fillComplete&&candidateAliases&&directionAccepted&&chooserReturns,"complete writer/value lifecycle for $4D3B");
    const bool candidateAccepted=out.valueProofs.size()>4&&out.valueProofs[4].accepted;
    const std::set<std::uint16_t>lowWords={0x32FF,0x3301,0x3303,0x3305},highWords={0x3300,0x3302,0x3304,0x3306};
    const std::set<std::uint16_t>indexedProof={0x29D4,0x29D7,0x29D8,0x29D9,0x29DB,0x29DF,0x29E1,0x29E4};
    const bool indexedShape=insn(analyzer,0x29D4,"LD","A,($4D3B)")&&insn(analyzer,0x29D7,"ADD","A,A")&&insn(analyzer,0x29D8,"LD","E,A")&&insn(analyzer,0x29D9,"LD","D,$00")&&insn(analyzer,0x29DB,"LD","IX,$32FF")&&insn(analyzer,0x29DF,"ADD","IX,DE")&&insn(analyzer,0x29E1,"LD","L,(IX+0)")&&insn(analyzer,0x29E4,"LD","H,(IX+1)");
    addAddressProof(out,rom.size(),0x29E1,"(IX+0)",CommandStreamProofKind::LoopCarriedIndex,lowWords,{3,4},{5,6},{},indexedProof,candidateAccepted&&indexedShape,"$4D3B is exactly 0..3 at loop exit; doubled selector indexes the four low bytes at $32FF/$3301/$3303/$3305");
    addAddressProof(out,rom.size(),0x29E4,"(IX+1)",CommandStreamProofKind::LoopCarriedIndex,highWords,{3,4},{5,6},{},indexedProof,candidateAccepted&&indexedShape,"same four-entry direction table, high byte of each two-byte record");

    // $294D/$2950 remain intentionally unresolved: IX advances by two on every
    // rejected candidate while $4D3B wraps modulo four.  Closing them requires
    // a proof that every reachable maze coordinate exits within four candidates.
    (void)memoryAliasWriterAliases;

    for(const auto&p:out.addressProofs)if(p.accepted){if(p.inheritedMemoryAliasBlocker)out.refinedInheritedBlockerPCs.insert(p.pc);if(p.newlyRootedMemoryAliasBlocker)out.refinedNewlyRootedBlockerPCs.insert(p.pc);}
    for(auto pc:out.inheritedBlockerPCs)if(!out.refinedInheritedBlockerPCs.count(pc))out.remainingInheritedBlockerPCs.insert(pc);
    for(auto pc:out.newlyRootedBlockerPCs)if(!out.refinedNewlyRootedBlockerPCs.count(pc))out.remainingNewlyRootedBlockerPCs.insert(pc);
    return out;
}

std::string CommandStreamAnalysis::byteValueKindText(CommandStreamByteValueKind k){switch(k){case CommandStreamByteValueKind::Unknown:return"unknown";case CommandStreamByteValueKind::Exact:return"exact";case CommandStreamByteValueKind::FiniteSet:return"finite-set";case CommandStreamByteValueKind::ContiguousRange:return"contiguous-range";}return"unknown";}
std::string CommandStreamAnalysis::proofKindText(CommandStreamProofKind k){switch(k){case CommandStreamProofKind::ByteValueLifecycle:return"byte-value-lifecycle";case CommandStreamProofKind::LoopCarriedIndex:return"loop-carried-index";case CommandStreamProofKind::CommandObjectFlags:return"command-object-flags";case CommandStreamProofKind::CommandStreamGraph:return"command-stream-graph";}return"unknown";}
bool CommandStreamAnalysis::semanticRomClosureEligible(const CommandStreamAddressProofRecord&p){return p.accepted&&p.domainClass==RootContextDomainClass::FiniteRom&&!p.address.hasUnknownAlternative&&p.address.staticProof&&!p.address.dynamicOnly;}

} // namespace pacripper
