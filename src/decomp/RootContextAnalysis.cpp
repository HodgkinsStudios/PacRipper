// PacRipper context-sensitive root analysis context-sensitive system-root address flow
// Created by Jacob Hodgkins

#include "RootContextAnalysis.h"

#include <algorithm>
#include <cctype>
#include <deque>
#include <iomanip>
#include <functional>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <tuple>

namespace pacripper {
namespace {

struct V {
    unsigned bits=16;
    std::set<std::uint16_t> values;
    bool unknown=true;
    bool widened=false;
    std::set<std::uint16_t> proof;
};

struct FlagFact {
    bool valid=false;
    std::string reg;
    std::uint8_t equals=0;
};

struct State {
    std::map<std::string,V> regs;
    std::map<std::uint16_t,V> mem8; // entries exist only when every represented path has a finite known byte value
    bool dataStackKnown=true;
    std::vector<V> dataStack;
    FlagFact zflag;
};

struct Frame {
    std::uint16_t callSite=0;
    std::uint16_t returnPC=0;
    bool preciseReturn=false;
    bool operator<(const Frame& o) const { return std::tie(callSite,returnPC,preciseReturn)<std::tie(o.callSite,o.returnPC,o.preciseReturn); }
    bool operator==(const Frame& o) const { return callSite==o.callSite&&returnPC==o.returnPC&&preciseReturn==o.preciseReturn; }
};

struct Context {
    std::vector<Frame> frames;
    std::size_t barrierDepth=0;
    bool widened=false;
    bool historyTruncated=false;
    bool operator<(const Context& o) const {
        if(frames!=o.frames)return std::lexicographical_compare(frames.begin(),frames.end(),o.frames.begin(),o.frames.end());
        return std::tie(barrierDepth,widened,historyTruncated)<std::tie(o.barrierDepth,o.widened,o.historyTruncated);
    }
};

struct NodeKey {
    std::uint16_t pc=0;
    Context context;
    bool operator<(const NodeKey& o) const { if(pc!=o.pc)return pc<o.pc;return context<o.context; }
};

struct AccessKey {
    std::uint16_t pc=0;
    std::string operand;
    IndirectMemoryDirection direction=IndirectMemoryDirection::Read;
    bool operator<(const AccessKey& o) const { return std::tie(pc,operand,direction)<std::tie(o.pc,o.operand,o.direction); }
};

std::string hex4(std::uint16_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(4)<<std::setfill('0')<<(unsigned)v;return o.str();}
std::string trim(std::string s){while(!s.empty()&&std::isspace(static_cast<unsigned char>(s.front())))s.erase(s.begin());while(!s.empty()&&std::isspace(static_cast<unsigned char>(s.back())))s.pop_back();return s;}
std::vector<std::string> splitOps(const std::string& s){std::vector<std::string> o;std::string c;int d=0;for(char ch:s){if(ch=='(')++d;else if(ch==')')--d;if(ch==','&&d==0){o.push_back(trim(c));c.clear();}else c+=ch;}if(!c.empty()||!s.empty())o.push_back(trim(c));return o;}
bool isPair(const std::string&r){return r=="BC"||r=="DE"||r=="HL"||r=="IX"||r=="IY"||r=="SP";}
bool isByte(const std::string&r){return r=="A"||r=="B"||r=="C"||r=="D"||r=="E"||r=="H"||r=="L"||r=="IXH"||r=="IXL"||r=="IYH"||r=="IYL";}
std::pair<std::string,std::string> pairBytes(const std::string&r){if(r=="BC")return{"B","C"};if(r=="DE")return{"D","E"};if(r=="HL")return{"H","L"};if(r=="IX")return{"IXH","IXL"};if(r=="IY")return{"IYH","IYL"};return{};}
std::string bytePair(const std::string&r){if(r=="B"||r=="C")return"BC";if(r=="D"||r=="E")return"DE";if(r=="H"||r=="L")return"HL";if(r=="IXH"||r=="IXL")return"IX";if(r=="IYH"||r=="IYL")return"IY";return{};}

V unknownV(unsigned bits=16){V v;v.bits=bits;return v;}
V exactV(std::uint16_t x,unsigned bits,std::uint16_t pc=0){V v;v.bits=bits;v.unknown=false;v.values.insert(bits==8?static_cast<std::uint8_t>(x):x);if(pc)v.proof.insert(pc);return v;}
// Proof-PC provenance is metadata, not part of the abstract value lattice.
// Re-enqueueing solely because provenance grew can make loops iterate once per
// provenance bit even after the value domain has converged.  Keep unioning the
// proof set in mergeV(), but fixed-point equality is intentionally semantic.
bool sameV(const V&a,const V&b){return a.bits==b.bits&&a.values==b.values&&a.unknown==b.unknown&&a.widened==b.widened;}
V mergeV(V a,const V&b,std::size_t cap,std::size_t& widenEvents){
    a.bits=std::max(a.bits,b.bits);a.unknown=a.unknown||b.unknown;a.widened=a.widened||b.widened;a.proof.insert(b.proof.begin(),b.proof.end());
    if(!a.widened){for(auto x:b.values){a.values.insert(x);if(a.values.size()>cap){a.values.clear();a.unknown=true;a.widened=true;++widenEvents;break;}}}
    return a;
}
V shifted(V a,int delta,unsigned bits,std::size_t cap,std::size_t& widenEvents){
    a.bits=bits;if(a.widened)return a;std::set<std::uint16_t> o;const std::uint32_t mod=bits==8?256u:65536u;for(auto x:a.values){long raw=static_cast<long>(x)+delta;o.insert(static_cast<std::uint16_t>((raw%static_cast<long>(mod)+mod)%mod));if(o.size()>cap){a.values.clear();a.unknown=true;a.widened=true;++widenEvents;return a;}}a.values=o;return a;
}
V binary(V a,const V&b,unsigned bits,std::size_t cap,std::size_t& widenEvents,const std::function<std::uint16_t(std::uint16_t,std::uint16_t)>&fn){
    V o;o.bits=bits;o.unknown=a.unknown||b.unknown;o.widened=a.widened||b.widened;o.proof=a.proof;o.proof.insert(b.proof.begin(),b.proof.end());if(o.widened||a.unknown||b.unknown)return o;
    const std::uint32_t mask=bits==8?0xFFu:0xFFFFu;for(auto x:a.values)for(auto y:b.values){o.values.insert(static_cast<std::uint16_t>(fn(x,y)&mask));if(o.values.size()>cap){o.values.clear();o.unknown=true;o.widened=true;++widenEvents;return o;}}return o;
}
V addV(const V&a,const V&b,unsigned bits,std::size_t cap,std::size_t&w){return binary(a,b,bits,cap,w,[](std::uint16_t x,std::uint16_t y){return static_cast<std::uint16_t>(x+y);});}
V subV(const V&a,const V&b,unsigned bits,std::size_t cap,std::size_t&w){return binary(a,b,bits,cap,w,[](std::uint16_t x,std::uint16_t y){return static_cast<std::uint16_t>(x-y);});}
V map8(V a,std::size_t cap,std::size_t&w,const std::function<std::uint8_t(std::uint8_t)>&fn){a.bits=8;if(a.widened)return a;if(a.unknown){a.values.clear();return a;}std::set<std::uint16_t> o;for(auto x:a.values){o.insert(fn(static_cast<std::uint8_t>(x)));if(o.size()>cap){a.values.clear();a.unknown=true;a.widened=true;++w;return a;}}a.values=o;return a;}
V mask8(const V&in,std::uint8_t mask,std::size_t cap,std::size_t&w){
    V o;o.bits=8;o.unknown=false;o.proof=in.proof;std::set<std::uint16_t> image;if(in.unknown){for(unsigned x=0;x<256;++x)image.insert(static_cast<std::uint8_t>(x&mask));}else for(auto x:in.values)image.insert(static_cast<std::uint8_t>(x)&mask);
    if(image.size()>cap){o.unknown=true;o.widened=true;++w;}else o.values=image;return o;
}
V orImm8(const V&in,std::uint8_t imm,std::size_t cap,std::size_t&w){V o;o.bits=8;o.unknown=false;o.proof=in.proof;std::set<std::uint16_t> image;if(in.unknown){for(unsigned x=0;x<256;++x)image.insert(static_cast<std::uint8_t>(x|imm));}else for(auto x:in.values)image.insert(static_cast<std::uint8_t>(x)|imm);if(image.size()>cap){o.unknown=true;o.widened=true;++w;}else o.values=image;return o;}
V xorImm8(const V&in,std::uint8_t imm,std::size_t cap,std::size_t&w){if(in.unknown)return unknownV(8);return map8(in,cap,w,[&](std::uint8_t x){return static_cast<std::uint8_t>(x^imm);});}
V getReg(const State&s,const std::string&r){auto i=s.regs.find(r);return i==s.regs.end()?unknownV(isByte(r)?8:16):i->second;}
V combineBytes(const V&hi,const V&lo,std::size_t cap,std::size_t&w){V o;o.bits=16;o.unknown=hi.unknown||lo.unknown;o.widened=hi.widened||lo.widened;o.proof=hi.proof;o.proof.insert(lo.proof.begin(),lo.proof.end());if(o.unknown||o.widened)return o;for(auto h:hi.values)for(auto l:lo.values){o.values.insert(static_cast<std::uint16_t>(((h&0xFFu)<<8)|(l&0xFFu)));if(o.values.size()>cap){o.values.clear();o.unknown=true;o.widened=true;++w;return o;}}return o;}
void setPair(State&s,const std::string&r,V v,std::size_t cap,std::size_t&w){v.bits=16;s.regs[r]=v;const auto b=pairBytes(r);if(b.first.empty())return;V hi;hi.bits=8;hi.unknown=v.unknown;hi.widened=v.widened;hi.proof=v.proof;V lo=hi;for(auto x:v.values){hi.values.insert(static_cast<std::uint8_t>(x>>8));lo.values.insert(static_cast<std::uint8_t>(x));if(hi.values.size()>cap||lo.values.size()>cap){hi=unknownV(8);lo=unknownV(8);hi.widened=lo.widened=true;++w;break;}}s.regs[b.first]=hi;s.regs[b.second]=lo;}
void setByte(State&s,const std::string&r,V v,std::size_t cap,std::size_t&w){v.bits=8;s.regs[r]=v;const auto p=bytePair(r);if(p.empty())return;const auto b=pairBytes(p);s.regs[p]=combineBytes(getReg(s,b.first),getReg(s,b.second),cap,w);}

bool parseHex(std::string t,std::uint16_t&v){t=trim(t);if(t.empty())return false;if(t[0]=='$')t.erase(t.begin());if(t.empty()||t.size()>4)return false;unsigned x=0;for(char c:t){x<<=4;if(c>='0'&&c<='9')x+=c-'0';else if(c>='A'&&c<='F')x+=10+c-'A';else if(c>='a'&&c<='f')x+=10+c-'a';else return false;}v=static_cast<std::uint16_t>(x);return true;}
bool parseAbsMem(const std::string&o,std::uint16_t&v){if(o.size()<4||o.front()!='('||o.back()!=')')return false;return parseHex(o.substr(1,o.size()-2),v);}

std::string contextText(const Context&c){std::ostringstream o;o<<"barrier="<<c.barrierDepth<<" frames=[";for(std::size_t i=0;i<c.frames.size();++i){if(i)o<<";";o<<"$"<<hex4(c.frames[i].callSite)<<"->$"<<hex4(c.frames[i].returnPC)<<(c.frames[i].preciseReturn?"!":"?");}o<<"]";if(c.widened)o<<" widened";if(c.historyTruncated)o<<" call-history-truncated";return o.str();}
void contextSets(const Context&c,std::set<std::uint16_t>&calls,std::set<std::uint16_t>&rets){for(const auto&f:c.frames){calls.insert(f.callSite);rets.insert(f.returnPC);}}


bool mergeState(State&dst,const State&src,bool initialized,std::size_t cap,std::size_t&w){
    if(!initialized){dst=src;return true;}
    bool changed=false;
    std::set<std::string> regs;
    for(const auto&x:dst.regs)regs.insert(x.first);
    for(const auto&x:src.regs)regs.insert(x.first);
    for(const auto&r:regs){
        const V before=getReg(dst,r);
        V merged=mergeV(before,getReg(src,r),cap,w);
        if(!sameV(before,merged))changed=true;
        dst.regs[r]=std::move(merged);
    }
    for(auto it=dst.mem8.begin();it!=dst.mem8.end();){
        auto si=src.mem8.find(it->first);
        if(si==src.mem8.end()){changed=true;it=dst.mem8.erase(it);continue;}
        const V before=it->second;
        V merged=mergeV(before,si->second,cap,w);
        if(merged.unknown||merged.widened){changed=true;it=dst.mem8.erase(it);continue;}
        if(!sameV(before,merged))changed=true;
        it->second=std::move(merged);++it;
    }
    if(!src.dataStackKnown||!dst.dataStackKnown||src.dataStack.size()!=dst.dataStack.size()){
        if(dst.dataStackKnown||!dst.dataStack.empty())changed=true;
        dst.dataStackKnown=false;dst.dataStack.clear();
    }else{
        for(std::size_t i=0;i<dst.dataStack.size();++i){
            const V before=dst.dataStack[i];
            V merged=mergeV(before,src.dataStack[i],cap,w);
            if(!sameV(before,merged))changed=true;
            dst.dataStack[i]=std::move(merged);
        }
    }
    if(!(dst.zflag.valid&&src.zflag.valid&&dst.zflag.reg==src.zflag.reg&&dst.zflag.equals==src.zflag.equals)){
        if(dst.zflag.valid)changed=true;
        dst.zflag={};
    }
    return changed;
}

AddressLatticeValue toAddress(const V&v){AddressLatticeValue a;a.values=v.values;a.hasUnknownAlternative=v.unknown;a.wraparound=false;a.staticProof=true;a.dynamicOnly=false;a.provenancePCs=v.proof;a.note=v.widened?"context-sensitive root analysis finite-value cap widened to explicit unknown alternative":"context-sensitive root analysis context-sensitive finite address flow";if(v.values.empty()&&v.unknown)a.kind=AddressValueKind::Unknown;else a=IndirectAddressAnalysis::classifyKnownValues(a);return a;}

V loadByte(const State&s,const V&addr,const std::vector<std::uint8_t>&rom,std::size_t cap,std::size_t&w){
    V out; out.bits=8; out.unknown=addr.unknown; out.widened=addr.widened; out.proof=addr.proof;
    if(addr.widened)return out;
    bool have=false;
    for(auto a:addr.values){
        V b;
        if(a<rom.size())b=exactV(rom[a],8,a);
        else{auto i=s.mem8.find(a);b=i==s.mem8.end()?unknownV(8):i->second;}
        if(!have){out.values=b.values;out.unknown=out.unknown||b.unknown;out.widened=out.widened||b.widened;out.proof.insert(b.proof.begin(),b.proof.end());have=true;}
        else out=mergeV(out,b,cap,w);
    }
    if(!have)out.unknown=true;
    return out;
}
V loadWord(const State&s,std::uint16_t addr,const std::vector<std::uint8_t>&rom,std::size_t cap,std::size_t&w){V av=exactV(addr,16);V lo=loadByte(s,av,rom,cap,w);V hi=loadByte(s,shifted(av,1,16,cap,w),rom,cap,w);return combineBytes(hi,lo,cap,w);}
void storeByte(State&s,const V&addr,const V&value){
    if(addr.unknown||addr.widened){s.mem8.clear();return;}
    if(addr.values.size()!=1){for(auto a:addr.values)s.mem8.erase(a);return;}
    const auto a=*addr.values.begin();
    if(value.unknown||value.widened||value.values.empty())s.mem8.erase(a);else s.mem8[a]=value;
}
void storeAbsByte(State&s,std::uint16_t a,const V&v,const std::vector<std::uint8_t>&rom){if(a<rom.size())return;if(v.unknown||v.widened||v.values.empty())s.mem8.erase(a);else s.mem8[a]=v;}
void storeAbsWord(State&s,std::uint16_t a,const V&v,const std::vector<std::uint8_t>&rom,std::size_t cap,std::size_t&w){if(v.unknown||v.widened){s.mem8.erase(a);s.mem8.erase(static_cast<std::uint16_t>(a+1));return;}V lo;lo.bits=8;lo.unknown=false;lo.proof=v.proof;V hi=lo;for(auto x:v.values){lo.values.insert(static_cast<std::uint8_t>(x));hi.values.insert(static_cast<std::uint8_t>(x>>8));if(lo.values.size()>cap||hi.values.size()>cap){lo=unknownV(8);hi=unknownV(8);++w;break;}}storeAbsByte(s,a,lo,rom);storeAbsByte(s,static_cast<std::uint16_t>(a+1),hi,rom);}

bool readDirection(IndirectMemoryDirection d){return d==IndirectMemoryDirection::Read||d==IndirectMemoryDirection::ReadWrite;}
bool writeDirection(IndirectMemoryDirection d){return d==IndirectMemoryDirection::Write||d==IndirectMemoryDirection::ReadWrite;}
IndirectMemoryDirection operandDirection(const Instruction&in,std::size_t index,const std::vector<std::string>&ops){
    (void)ops;if(in.mnemonic=="LD")return index==0?IndirectMemoryDirection::Write:IndirectMemoryDirection::Read;
    if(in.mnemonic=="BIT"||in.mnemonic=="CP")return IndirectMemoryDirection::Read;
    if(in.mnemonic=="SET"||in.mnemonic=="RES"||in.mnemonic=="INC"||in.mnemonic=="DEC")return IndirectMemoryDirection::ReadWrite;
    return IndirectMemoryDirection::Read;
}

struct Engine {
    const Analyzer& analyzer;
    const std::vector<std::uint8_t>& rom;
    std::set<std::uint16_t> rootedPCs;
    std::map<std::uint16_t,const SystemRootInlineDataRecord*> inlineBySource;
    std::size_t maxValues=64,maxContexts=512,maxDepth=16;
    RootContextAnalysisResult out;
    Z80Disassembler dis;
    std::map<NodeKey,State> states;
    std::map<NodeKey,bool> initialized;
    std::map<std::uint16_t,std::set<Context>> contextsAtPC;
    std::deque<NodeKey> work;
    std::map<AccessKey,std::vector<std::size_t>> accessContexts;
    std::map<AccessKey,std::vector<std::size_t>> writerAccessContexts;
    std::map<std::uint16_t,bool> preciseLeafCache;
    std::size_t widenEvents=0;
    std::size_t writerWidenEvents=0;

    Engine(const Analyzer&a,const std::vector<SystemRootReachabilityRecord>&reach,const std::vector<SystemRootInlineDataRecord>&inl,const std::vector<SystemRootNegativeReferenceRecord>&neg,std::size_t mv,std::size_t mc,std::size_t md):analyzer(a),rom(a.program()),maxValues(mv),maxContexts(mc),maxDepth(md){
        for(const auto&r:reach)rootedPCs.insert(r.pc);
        for(const auto&d:inl)inlineBySource[d.sourcePC]=&d;
        for(const auto&n:neg){
            out.inheritedBlockerPCs.insert(n.remainingOriginalBlockerPCs.begin(),n.remainingOriginalBlockerPCs.end());
            out.newlyRootedBlockerPCs.insert(n.newlyRootedUnknownBlockerPCs.begin(),n.newlyRootedUnknownBlockerPCs.end());
        }
    }

    void seed(std::uint16_t pc,const Context&ctx,const State&s){
        if(!rootedPCs.count(pc))return;
        NodeKey k{pc,ctx};
        auto& set=contextsAtPC[pc];
        if(!set.count(ctx)&&set.size()>=maxContexts){
            out.contextOverflowPCs.insert(pc);++out.contextOverflowEvents;out.callerInventoryComplete=false;return;
        }
        set.insert(ctx);
        out.maxObservedCallDepth=std::max(out.maxObservedCallDepth,ctx.frames.size());
        const bool init=initialized[k];
        if(mergeState(states[k],s,init,maxValues,widenEvents)){
            initialized[k]=true;++out.stateMergeUpdates;work.push_back(k);
        }
    }

    V indirectAddress(const State&s,const std::string&op,int&disp,std::string&reg){if(!IndirectAddressAnalysis::parseIndirectOperand(op,reg,disp)||(!isPair(reg)))return unknownV(16);V v=getReg(s,reg);v=shifted(v,disp,16,maxValues,widenEvents);return v;}

    void addAccess(std::uint16_t pc,const std::string&operand,IndirectMemoryDirection dir,const V&addr,const Context&ctx,bool synthetic,const std::set<std::uint16_t>&extraProof,const std::string&note){
        if(!readDirection(dir))return;
        RootContextAddressContextRecord r;
        r.id=out.contextRecords.size();r.pc=pc;r.operand=operand;r.direction=dir;r.contextKey=contextText(ctx);
        r.callDepth=ctx.frames.size();r.returnBarrierDepth=ctx.barrierDepth;
        contextSets(ctx,r.callSites,r.returnPCs);r.address=toAddress(addr);
        r.contextWidened=ctx.widened||addr.widened;r.syntheticRestartSummary=synthetic;r.proofPCs=addr.proof;
        r.proofPCs.insert(extraProof.begin(),extraProof.end());r.proofPCs.insert(pc);r.note=note;
        out.contextRecords.push_back(r);accessContexts[{pc,operand,dir}].push_back(r.id);
    }

    void addWriteAccess(std::uint16_t pc,const std::string&operand,IndirectMemoryDirection dir,const V&addr,const Context&ctx,bool synthetic,const std::set<std::uint16_t>&extraProof,const std::string&note){
        if(!writeDirection(dir))return;
        RootContextAddressContextRecord r;
        r.id=out.writerContextRecords.size();r.pc=pc;r.operand=operand;r.direction=dir;r.contextKey=contextText(ctx);
        r.callDepth=ctx.frames.size();r.returnBarrierDepth=ctx.barrierDepth;
        contextSets(ctx,r.callSites,r.returnPCs);r.address=toAddress(addr);
        r.contextWidened=ctx.widened||addr.widened;r.syntheticRestartSummary=synthetic;r.proofPCs=addr.proof;
        r.proofPCs.insert(extraProof.begin(),extraProof.end());r.proofPCs.insert(pc);r.note=note;
        out.writerContextRecords.push_back(r);writerAccessContexts[{pc,operand,dir}].push_back(r.id);
    }

    void recordInstructionMemory(const Instruction&in,const State&s,const Context&ctx){
        const bool block = in.mnemonic=="LDIR"||in.mnemonic=="LDDR"||in.mnemonic=="CPIR"||in.mnemonic=="CPDR"||
                           in.mnemonic=="LDI"||in.mnemonic=="LDD"||in.mnemonic=="CPI"||in.mnemonic=="CPD";
        if(block){
            const bool repeat=in.mnemonic.size()==4&&in.mnemonic.back()=='R';
            const bool copy=in.mnemonic=="LDIR"||in.mnemonic=="LDDR"||in.mnemonic=="LDI"||in.mnemonic=="LDD";
            auto expand=[&](const std::string&reg,std::size_t&counter)->V{
                V base=getReg(s,reg);V domain=base;
                if(!repeat)return domain;
                V bc=getReg(s,"BC");
                if(base.unknown||bc.unknown||base.widened||bc.widened)return unknownV(16);
                V expanded;expanded.bits=16;expanded.unknown=false;expanded.proof=base.proof;expanded.proof.insert(bc.proof.begin(),bc.proof.end());
                const int step=(in.mnemonic=="LDDR"||in.mnemonic=="CPDR")?-1:1;bool overflow=false;
                for(auto h:base.values){for(auto n:bc.values){if(n>512){overflow=true;break;}for(std::uint32_t i=0;i<n;++i){expanded.values.insert(static_cast<std::uint16_t>(h+step*static_cast<int>(i)));if(expanded.values.size()>maxValues){overflow=true;break;}}if(overflow)break;}if(overflow)break;}
                if(overflow){expanded.values.clear();expanded.unknown=true;expanded.widened=true;++counter;}return expanded;
            };
            addAccess(in.address,"(HL repeated)",IndirectMemoryDirection::Read,expand("HL",widenEvents),ctx,false,{in.address},"block/string instruction source domain with caller-specific HL and finite BC when available");
            if(copy)addWriteAccess(in.address,"(DE repeated)",IndirectMemoryDirection::Write,expand("DE",writerWidenEvents),ctx,false,{in.address},"block/string instruction destination domain with caller-specific DE and finite BC when available");
            return;
        }
        const auto ops=splitOps(in.operands);
        for(std::size_t i=0;i<ops.size();++i){
            std::string reg;int disp=0;
            if(!IndirectAddressAnalysis::parseIndirectOperand(ops[i],reg,disp)||!isPair(reg))continue;
            const auto dir=operandDirection(in,i,ops);
            if(readDirection(dir)){
                V a=shifted(getReg(s,reg),disp,16,maxValues,widenEvents);a.proof.insert(in.address);
                addAccess(in.address,ops[i],dir,a,ctx,false,{in.address},"indirect read address before instruction transfer");
                if(writeDirection(dir))addWriteAccess(in.address,ops[i],dir,a,ctx,false,{in.address},"indirect write address before instruction transfer");
            }else if(writeDirection(dir)){
                V a=shifted(getReg(s,reg),disp,16,maxValues,writerWidenEvents);a.proof.insert(in.address);
                addWriteAccess(in.address,ops[i],dir,a,ctx,false,{in.address},"indirect write address before instruction transfer");
            }
        }
    }

    void invalidateFlag(State&s){s.zflag={};}
    void flagRegEq(State&s,const std::string&r,std::uint8_t c){s.zflag.valid=true;s.zflag.reg=r;s.zflag.equals=c;}

    void transfer(const Instruction&in,State&s){
        const auto ops=splitOps(in.operands);
        if(in.mnemonic=="LD"&&ops.size()==2){const auto&dst=ops[0];const auto&src=ops[1];std::uint16_t imm=0,abs=0;
            if(isPair(dst)&&parseHex(src,imm)){V v=exactV(imm,16,in.address);setPair(s,dst,v,maxValues,widenEvents);return;}
            if(isByte(dst)&&parseHex(src,imm)){V v=exactV(imm,8,in.address);setByte(s,dst,v,maxValues,widenEvents);return;}
            if(isPair(dst)&&isPair(src)){V v=getReg(s,src);v.proof.insert(in.address);setPair(s,dst,v,maxValues,widenEvents);return;}
            if(isByte(dst)&&isByte(src)){V v=getReg(s,src);v.proof.insert(in.address);setByte(s,dst,v,maxValues,widenEvents);return;}
            if(isPair(dst)&&parseAbsMem(src,abs)){V v=loadWord(s,abs,rom,maxValues,widenEvents);v.proof.insert(in.address);setPair(s,dst,v,maxValues,widenEvents);return;}
            if(isByte(dst)&&parseAbsMem(src,abs)){V av=exactV(abs,16,in.address);V v=loadByte(s,av,rom,maxValues,widenEvents);v.proof.insert(in.address);setByte(s,dst,v,maxValues,widenEvents);return;}
            std::string reg;int disp=0;if(isByte(dst)&&IndirectAddressAnalysis::parseIndirectOperand(src,reg,disp)&&isPair(reg)){V a=shifted(getReg(s,reg),disp,16,maxValues,widenEvents);V v=loadByte(s,a,rom,maxValues,widenEvents);v.proof.insert(in.address);setByte(s,dst,v,maxValues,widenEvents);return;}
            if(parseAbsMem(dst,abs)){V v;if(isByte(src))v=getReg(s,src);else if(isPair(src)){storeAbsWord(s,abs,getReg(s,src),rom,maxValues,widenEvents);return;}else if(parseHex(src,imm))v=exactV(imm,8,in.address);else v=unknownV(8);storeAbsByte(s,abs,v,rom);return;}
            if(IndirectAddressAnalysis::parseIndirectOperand(dst,reg,disp)&&isPair(reg)){V a=shifted(getReg(s,reg),disp,16,maxValues,widenEvents);V v;if(isByte(src))v=getReg(s,src);else if(parseHex(src,imm))v=exactV(imm,8,in.address);else v=unknownV(8);storeByte(s,a,v);return;}
            if(isByte(dst)){setByte(s,dst,unknownV(8),maxValues,widenEvents);return;}if(isPair(dst)){setPair(s,dst,unknownV(16),maxValues,widenEvents);return;}
        }
        if(in.mnemonic=="XOR"&&ops.size()==1&&ops[0]=="A"){setByte(s,"A",exactV(0,8,in.address),maxValues,widenEvents);flagRegEq(s,"A",0);return;}
        if(in.mnemonic=="AND"&&ops.size()==1){if(ops[0]=="A"){flagRegEq(s,"A",0);return;}std::uint16_t imm=0;if(parseHex(ops[0],imm)){V v=mask8(getReg(s,"A"),static_cast<std::uint8_t>(imm),maxValues,widenEvents);v.proof.insert(in.address);setByte(s,"A",v,maxValues,widenEvents);flagRegEq(s,"A",0);return;}V rhs;if(isByte(ops[0]))rhs=getReg(s,ops[0]);else{std::string r;int d=0;if(IndirectAddressAnalysis::parseIndirectOperand(ops[0],r,d)&&isPair(r))rhs=loadByte(s,shifted(getReg(s,r),d,16,maxValues,widenEvents),rom,maxValues,widenEvents);else rhs=unknownV(8);}V v=binary(getReg(s,"A"),rhs,8,maxValues,widenEvents,[](std::uint16_t x,std::uint16_t y){return static_cast<std::uint8_t>(x&y);});v.proof.insert(in.address);setByte(s,"A",v,maxValues,widenEvents);flagRegEq(s,"A",0);return;}
        if(in.mnemonic=="OR"&&ops.size()==1){std::uint16_t imm=0;V v;if(parseHex(ops[0],imm))v=orImm8(getReg(s,"A"),static_cast<std::uint8_t>(imm),maxValues,widenEvents);else{V rhs=isByte(ops[0])?getReg(s,ops[0]):unknownV(8);v=binary(getReg(s,"A"),rhs,8,maxValues,widenEvents,[](std::uint16_t x,std::uint16_t y){return static_cast<std::uint8_t>(x|y);});}v.proof.insert(in.address);setByte(s,"A",v,maxValues,widenEvents);flagRegEq(s,"A",0);return;}
        if(in.mnemonic=="XOR"&&ops.size()==1){std::uint16_t imm=0;V v;if(parseHex(ops[0],imm))v=xorImm8(getReg(s,"A"),static_cast<std::uint8_t>(imm),maxValues,widenEvents);else{V rhs=isByte(ops[0])?getReg(s,ops[0]):unknownV(8);v=binary(getReg(s,"A"),rhs,8,maxValues,widenEvents,[](std::uint16_t x,std::uint16_t y){return static_cast<std::uint8_t>(x^y);});}v.proof.insert(in.address);setByte(s,"A",v,maxValues,widenEvents);flagRegEq(s,"A",0);return;}
        if((in.mnemonic=="INC"||in.mnemonic=="DEC")&&ops.size()==1){const int d=in.mnemonic=="INC"?1:-1;if(isPair(ops[0])){V v=shifted(getReg(s,ops[0]),d,16,maxValues,widenEvents);v.proof.insert(in.address);setPair(s,ops[0],v,maxValues,widenEvents);return;}if(isByte(ops[0])){V v=shifted(getReg(s,ops[0]),d,8,maxValues,widenEvents);v.proof.insert(in.address);setByte(s,ops[0],v,maxValues,widenEvents);flagRegEq(s,ops[0],0);return;}std::string r;int disp=0;if(IndirectAddressAnalysis::parseIndirectOperand(ops[0],r,disp)&&isPair(r)){V a=shifted(getReg(s,r),disp,16,maxValues,widenEvents);V v=loadByte(s,a,rom,maxValues,widenEvents);v=shifted(v,d,8,maxValues,widenEvents);storeByte(s,a,v);invalidateFlag(s);return;}}
        if(in.mnemonic=="ADD"&&ops.size()==2){if(ops[0]=="A"){V rhs;std::uint16_t imm=0;if(isByte(ops[1]))rhs=getReg(s,ops[1]);else if(parseHex(ops[1],imm))rhs=exactV(imm,8,in.address);else{std::string r;int d=0;if(IndirectAddressAnalysis::parseIndirectOperand(ops[1],r,d)&&isPair(r))rhs=loadByte(s,shifted(getReg(s,r),d,16,maxValues,widenEvents),rom,maxValues,widenEvents);else rhs=unknownV(8);}V v=addV(getReg(s,"A"),rhs,8,maxValues,widenEvents);v.proof.insert(in.address);setByte(s,"A",v,maxValues,widenEvents);flagRegEq(s,"A",0);return;}if(isPair(ops[0])&&isPair(ops[1])){V v=addV(getReg(s,ops[0]),getReg(s,ops[1]),16,maxValues,widenEvents);v.proof.insert(in.address);setPair(s,ops[0],v,maxValues,widenEvents);invalidateFlag(s);return;}}
        if((in.mnemonic=="ADC"||in.mnemonic=="SBC")&&ops.size()>=1){if(ops.size()==2&&ops[0]=="A"){V rhs;std::uint16_t imm=0;if(isByte(ops[1]))rhs=getReg(s,ops[1]);else if(parseHex(ops[1],imm))rhs=exactV(imm,8,in.address);else{std::string r;int d=0;if(IndirectAddressAnalysis::parseIndirectOperand(ops[1],r,d)&&isPair(r))rhs=loadByte(s,shifted(getReg(s,r),d,16,maxValues,widenEvents),rom,maxValues,widenEvents);else rhs=unknownV(8);}V base=in.mnemonic=="ADC"?addV(getReg(s,"A"),rhs,8,maxValues,widenEvents):subV(getReg(s,"A"),rhs,8,maxValues,widenEvents);V alt=shifted(base,in.mnemonic=="ADC"?1:-1,8,maxValues,widenEvents);V v=mergeV(base,alt,maxValues,widenEvents);v.proof.insert(in.address);setByte(s,"A",v,maxValues,widenEvents);invalidateFlag(s);return;}if(ops.size()==2&&isPair(ops[0])&&isPair(ops[1])){setPair(s,ops[0],unknownV(16),maxValues,widenEvents);invalidateFlag(s);return;}}
        if(in.mnemonic=="SUB"&&ops.size()==1){V rhs;std::uint16_t imm=0;if(isByte(ops[0]))rhs=getReg(s,ops[0]);else if(parseHex(ops[0],imm))rhs=exactV(imm,8,in.address);else{std::string r;int d=0;if(IndirectAddressAnalysis::parseIndirectOperand(ops[0],r,d)&&isPair(r))rhs=loadByte(s,shifted(getReg(s,r),d,16,maxValues,widenEvents),rom,maxValues,widenEvents);else rhs=unknownV(8);}V v=subV(getReg(s,"A"),rhs,8,maxValues,widenEvents);v.proof.insert(in.address);setByte(s,"A",v,maxValues,widenEvents);flagRegEq(s,"A",0);return;}
        if(in.mnemonic=="CP"&&ops.size()==1){std::uint16_t imm=0;if(parseHex(ops[0],imm)){s.zflag.valid=true;s.zflag.reg="A";s.zflag.equals=static_cast<std::uint8_t>(imm);}else invalidateFlag(s);return;}
        if(in.mnemonic=="RLCA"||in.mnemonic=="RRCA"){V v=map8(getReg(s,"A"),maxValues,widenEvents,[&](std::uint8_t x){return in.mnemonic=="RLCA"?static_cast<std::uint8_t>((x<<1)|(x>>7)):static_cast<std::uint8_t>((x>>1)|(x<<7));});v.proof.insert(in.address);setByte(s,"A",v,maxValues,widenEvents);return;}
        if((in.mnemonic=="SRL"||in.mnemonic=="SLA"||in.mnemonic=="SRA")&&ops.size()==1&&isByte(ops[0])){V v=map8(getReg(s,ops[0]),maxValues,widenEvents,[&](std::uint8_t x){if(in.mnemonic=="SRL")return static_cast<std::uint8_t>(x>>1);if(in.mnemonic=="SLA")return static_cast<std::uint8_t>(x<<1);return static_cast<std::uint8_t>((x>>1)|(x&0x80));});v.proof.insert(in.address);setByte(s,ops[0],v,maxValues,widenEvents);flagRegEq(s,ops[0],0);return;}
        if(in.mnemonic=="CPL"){V v=map8(getReg(s,"A"),maxValues,widenEvents,[](std::uint8_t x){return static_cast<std::uint8_t>(~x);});v.proof.insert(in.address);setByte(s,"A",v,maxValues,widenEvents);return;}
        if(in.mnemonic=="NEG"){V z=exactV(0,8,in.address);V v=subV(z,getReg(s,"A"),8,maxValues,widenEvents);setByte(s,"A",v,maxValues,widenEvents);flagRegEq(s,"A",0);return;}
        if(in.mnemonic=="EX"&&ops.size()==2&&((ops[0]=="DE"&&ops[1]=="HL")||(ops[0]=="HL"&&ops[1]=="DE"))){V de=getReg(s,"DE"),hl=getReg(s,"HL");setPair(s,"DE",hl,maxValues,widenEvents);setPair(s,"HL",de,maxValues,widenEvents);return;}
        if(in.mnemonic=="EXX"){for(const auto&r:{"BC","DE","HL"})setPair(s,r,unknownV(16),maxValues,widenEvents);return;}
        if(in.mnemonic=="EX"&&ops.size()>=1&&ops[0]=="AF"){setByte(s,"A",unknownV(8),maxValues,widenEvents);invalidateFlag(s);return;}
        if(in.mnemonic=="PUSH"&&ops.size()==1){V v=isPair(ops[0])?getReg(s,ops[0]):unknownV(16);if(s.dataStackKnown&&s.dataStack.size()<32)s.dataStack.push_back(v);else{s.dataStackKnown=false;s.dataStack.clear();}return;}
        if(in.mnemonic=="POP"&&ops.size()==1){V v=unknownV(16);if(s.dataStackKnown&&!s.dataStack.empty()){v=s.dataStack.back();s.dataStack.pop_back();}else{V sp=getReg(s,"SP");if(!sp.unknown&&!sp.widened&&!sp.values.empty()){V agg;agg.bits=16;agg.unknown=false;bool first=true;for(auto a:sp.values){V one=loadWord(s,a,rom,maxValues,widenEvents);if(first){agg=one;first=false;}else agg=mergeV(agg,one,maxValues,widenEvents);}v=agg;setPair(s,"SP",shifted(sp,2,16,maxValues,widenEvents),maxValues,widenEvents);}s.dataStackKnown=false;s.dataStack.clear();}if(isPair(ops[0]))setPair(s,ops[0],v,maxValues,widenEvents);else if(ops[0]=="AF"){V hi;hi.bits=8;hi.unknown=v.unknown;hi.widened=v.widened;hi.proof=v.proof;for(auto x:v.values)hi.values.insert(static_cast<std::uint8_t>(x>>8));setByte(s,"A",hi,maxValues,widenEvents);invalidateFlag(s);}return;}
        if(in.mnemonic=="DJNZ"){V v=shifted(getReg(s,"B"),-1,8,maxValues,widenEvents);v.proof.insert(in.address);setByte(s,"B",v,maxValues,widenEvents);flagRegEq(s,"B",0);return;}
        if(in.mnemonic=="LDI"||in.mnemonic=="LDD"||in.mnemonic=="CPI"||in.mnemonic=="CPD"){const int d=(in.mnemonic=="LDI"||in.mnemonic=="CPI")?1:-1;setPair(s,"HL",shifted(getReg(s,"HL"),d,16,maxValues,widenEvents),maxValues,widenEvents);if(in.mnemonic=="LDI"||in.mnemonic=="LDD")setPair(s,"DE",shifted(getReg(s,"DE"),d,16,maxValues,widenEvents),maxValues,widenEvents);setPair(s,"BC",shifted(getReg(s,"BC"),-1,16,maxValues,widenEvents),maxValues,widenEvents);invalidateFlag(s);return;}
        if(in.mnemonic=="LDIR"||in.mnemonic=="LDDR"){const int d=in.mnemonic=="LDIR"?1:-1;V bc=getReg(s,"BC"),hl=getReg(s,"HL"),de=getReg(s,"DE");if(!bc.unknown&&!bc.widened&&bc.values.size()==1){auto n=*bc.values.begin();if(n<=512){if(hl.values.size()==1&&de.values.size()==1&&!hl.unknown&&!de.unknown){auto ha=*hl.values.begin(),da=*de.values.begin();for(std::uint32_t i=0;i<n;++i){V av=exactV(static_cast<std::uint16_t>(ha+d*static_cast<int>(i)),16,in.address);V byte=loadByte(s,av,rom,maxValues,widenEvents);storeByte(s,exactV(static_cast<std::uint16_t>(da+d*static_cast<int>(i)),16,in.address),byte);}}setPair(s,"HL",shifted(hl,d*static_cast<int>(n),16,maxValues,widenEvents),maxValues,widenEvents);setPair(s,"DE",shifted(de,d*static_cast<int>(n),16,maxValues,widenEvents),maxValues,widenEvents);setPair(s,"BC",exactV(0,16,in.address),maxValues,widenEvents);invalidateFlag(s);return;}}setPair(s,"HL",unknownV(16),maxValues,widenEvents);setPair(s,"DE",unknownV(16),maxValues,widenEvents);setPair(s,"BC",unknownV(16),maxValues,widenEvents);invalidateFlag(s);return;}
        if(in.mnemonic=="DAA"){setByte(s,"A",unknownV(8),maxValues,widenEvents);invalidateFlag(s);return;}
        if(in.mnemonic=="BIT"){invalidateFlag(s);return;}
        if(in.mnemonic=="SET"||in.mnemonic=="RES"){
            if(!ops.empty()){std::string base;int disp=0;const std::string& dst=ops.back();if(IndirectAddressAnalysis::parseIndirectOperand(dst,base,disp)){V addr=shifted(getReg(s,base),disp,16,maxValues,widenEvents);storeByte(s,addr,unknownV(8));}}
            invalidateFlag(s);return;
        }
        if(in.mnemonic=="SCF"||in.mnemonic=="CCF"){return;}
        // Conservatively invalidate obvious register destinations for unmodeled ALU/data instructions.
        if(!ops.empty()&&isByte(ops[0])&&(in.mnemonic=="RLC"||in.mnemonic=="RRC"||in.mnemonic=="RL"||in.mnemonic=="RR")){setByte(s,ops[0],unknownV(8),maxValues,widenEvents);invalidateFlag(s);return;}
    }


    bool transferPreservationModeled(const Instruction& in) const {
        const auto ops=splitOps(in.operands);
        if(in.mnemonic=="NOP"||in.mnemonic=="DI"||in.mnemonic=="EI"||in.mnemonic=="SCF"||in.mnemonic=="CCF")return true;
        if(in.mnemonic=="LD")return true; // transfer() invalidates tracked byte/pair destinations it cannot resolve
        if(in.mnemonic=="XOR"||in.mnemonic=="AND"||in.mnemonic=="OR"||in.mnemonic=="INC"||in.mnemonic=="DEC"||in.mnemonic=="ADD"||in.mnemonic=="ADC"||in.mnemonic=="SBC"||in.mnemonic=="SUB"||in.mnemonic=="CP")return true;
        if(in.mnemonic=="RLCA"||in.mnemonic=="RRCA"||in.mnemonic=="CPL"||in.mnemonic=="NEG"||in.mnemonic=="DAA"||in.mnemonic=="BIT"||in.mnemonic=="SET"||in.mnemonic=="RES"||in.mnemonic=="DJNZ")return true;
        if((in.mnemonic=="SRL"||in.mnemonic=="SLA"||in.mnemonic=="SRA")&&ops.size()==1&&isByte(ops[0]))return true;
        if(in.mnemonic=="EXX")return true;
        if(in.mnemonic=="EX"&&ops.size()==2&&((ops[0]=="DE"&&ops[1]=="HL")||(ops[0]=="HL"&&ops[1]=="DE")||ops[0]=="AF"))return true;
        if((in.mnemonic=="PUSH"||in.mnemonic=="POP")&&ops.size()==1)return true;
        if(in.mnemonic=="LDI"||in.mnemonic=="LDD"||in.mnemonic=="LDIR"||in.mnemonic=="LDDR")return true;
        if(in.flow==FlowKind::Jump||in.flow==FlowKind::RelativeJump||in.flow==FlowKind::Return)return !in.indirect;
        return false;
    }

    bool preciseLeaf(std::uint16_t target){
        auto ci=preciseLeafCache.find(target);if(ci!=preciseLeafCache.end())return ci->second;
        std::deque<std::uint16_t> q;q.push_back(target);std::set<std::uint16_t> seen;bool sawReturn=false;std::size_t guard=0;
        bool ok=true;
        while(!q.empty()&&ok){
            const auto pc=q.front();q.pop_front();if(!seen.insert(pc).second)continue;
            if(++guard>512||!rootedPCs.count(pc)){ok=false;break;}
            Instruction in=dis.decode(rom,pc);if(in.bytes.empty()||in.mnemonic=="DB"||!transferPreservationModeled(in)){ok=false;break;}
            const auto next=static_cast<std::uint16_t>(pc+in.length());
            if(in.flow==FlowKind::Call||in.flow==FlowKind::Restart||in.flow==FlowKind::Halt){ok=false;break;}
            if(in.flow==FlowKind::Return){sawReturn=true;if(in.conditional)q.push_back(next);continue;}
            if(in.flow==FlowKind::Jump||in.flow==FlowKind::RelativeJump){
                if(in.indirect||in.target<0||static_cast<std::size_t>(in.target)>=rom.size()){ok=false;break;}
                q.push_back(static_cast<std::uint16_t>(in.target));if(in.conditional)q.push_back(next);continue;
            }
            q.push_back(next);
        }
        ok=ok&&sawReturn;preciseLeafCache[target]=ok;return ok;
    }

    bool finiteAdd(const V&base,const V&offset,V&outv){outv=addV(base,offset,16,maxValues,widenEvents);return !outv.unknown&&!outv.widened&&!outv.values.empty();}

    bool insn(std::uint16_t pc,const char* mnemonic,const char* operands="") const {
        if(static_cast<std::size_t>(pc)>=rom.size())return false;
        const Instruction in=dis.decode(rom,pc);
        return in.mnemonic==mnemonic&&in.operands==operands;
    }

    bool explicitEntryOnly(std::uint16_t target,const std::set<std::uint16_t>& allowedSources) const {
        // Caller-completeness guard for source-local invariants.  Every explicit
        // control transfer in the independently rooted graph must either be one
        // of the structurally expected loop backedges/calls or not target the
        // invariant body at all.  RST $20 targets are included because they are
        // statically recovered indirect transfers rather than ordinary targets.
        for(auto pc:rootedPCs){
            const Instruction in=dis.decode(rom,pc);
            if(in.target==static_cast<int>(target)&&!allowedSources.count(pc))return false;
        }
        for(const auto&kv:inlineBySource){
            const auto*d=kv.second;
            if(d&&d->dispatchTargets.count(target)&&!allowedSources.count(kv.first))return false;
        }
        return true;
    }

    AddressLatticeValue sourceDomain(std::uint16_t start,std::uint16_t end,std::uint16_t stride,const std::set<std::uint16_t>& proof,const std::string& note) const {
        AddressLatticeValue a;
        a.rangeStart=start;a.rangeEnd=end;a.stride=stride?stride:1;a.staticProof=true;a.dynamicOnly=false;a.hasUnknownAlternative=false;a.wraparound=false;a.provenancePCs=proof;a.note=note;
        if(start==end){a.kind=AddressValueKind::Exact;a.values.insert(start);}
        else if(a.stride==1)a.kind=AddressValueKind::ContiguousRange;
        else a.kind=AddressValueKind::StridedRange;
        return a;
    }

    AddressLatticeValue sourceFiniteSet(const std::set<std::uint16_t>& values,const std::set<std::uint16_t>& proof,const std::string& note) const {
        AddressLatticeValue a;a.staticProof=true;a.dynamicOnly=false;a.hasUnknownAlternative=false;a.wraparound=false;a.provenancePCs=proof;a.note=note;a.values=values;
        if(values.empty()){a.kind=AddressValueKind::Unknown;a.hasUnknownAlternative=true;return a;}
        if(values.size()==1){a.kind=AddressValueKind::Exact;a.rangeStart=a.rangeEnd=*values.begin();a.stride=1;return a;}
        a.kind=AddressValueKind::FiniteSet;a.rangeStart=*values.begin();a.rangeEnd=*values.rbegin();a.stride=0;return a;
    }

    void addWriterSourceInvariantProof(std::uint16_t pc,const std::string& operand,IndirectMemoryDirection direction,const AddressLatticeValue& domain,const std::set<std::uint16_t>& proofPCs,const std::string& note){
        if(!writeDirection(direction))return;
        RootContextAddressProofRecord p;p.id=out.writerAddressProofs.size();p.pc=pc;p.operand=operand;p.direction=direction;p.aggregateAddress=domain;p.sourceInvariant=true;
        for(const auto&kv:writerAccessContexts){if(kv.first.pc!=pc)continue;for(auto id:kv.second){p.contextRecordIds.insert(id);const auto&r=out.writerContextRecords[id];p.callSites.insert(r.callSites.begin(),r.callSites.end());p.proofPCs.insert(r.proofPCs.begin(),r.proofPCs.end());}}
        p.proofPCs.insert(proofPCs.begin(),proofPCs.end());p.proofPCs.insert(pc);p.callerComplete=out.callerInventoryComplete&&out.contextOverflowPCs.empty()&&out.guardTrips==0&&out.unresolvedIndirectControlPCs.empty();p.domainClass=RootContextAnalysis::classifyDomain(p.aggregateAddress,rom.size());p.finiteRomOnly=p.domainClass==RootContextDomainClass::FiniteRom;p.finiteNonRomOnly=p.domainClass==RootContextDomainClass::FiniteNonRom;p.mixedRomNonRom=p.domainClass==RootContextDomainClass::Mixed;std::set<std::uint16_t>finite;p.exactSingleton=RootContextAnalysis::completeFiniteDomain(p.aggregateAddress,finite)&&finite.size()==1;p.accepted=p.callerComplete&&(p.domainClass==RootContextDomainClass::FiniteRom||p.domainClass==RootContextDomainClass::FiniteNonRom||p.domainClass==RootContextDomainClass::Mixed)&&!p.aggregateAddress.hasUnknownAlternative;p.note="memory-alias analysis writer source-local invariant: "+note;out.writerAddressProofs.push_back(std::move(p));
    }

    void addSourceInvariantProof(std::uint16_t pc,const std::string& operand,IndirectMemoryDirection direction,const AddressLatticeValue& domain,const std::set<std::uint16_t>& proofPCs,const std::string& note){
        if(!readDirection(direction))return;
        RootContextAddressProofRecord p;
        p.id=out.addressProofs.size();p.pc=pc;p.operand=operand;p.direction=direction;p.aggregateAddress=domain;p.sourceInvariant=true;
        p.inheritedSystemRootBlocker=out.inheritedBlockerPCs.count(pc)!=0;p.newlyRootedSystemRootBlocker=out.newlyRootedBlockerPCs.count(pc)!=0;
        // Attach every context record already enumerated for this PC.  The
        // structural invariant is caller-independent, so these IDs are provenance
        // rather than a sampled subset of callers.
        for(const auto&kv:accessContexts){
            if(kv.first.pc!=pc)continue;
            for(auto id:kv.second){
                p.contextRecordIds.insert(id);
                const auto&r=out.contextRecords[id];p.callSites.insert(r.callSites.begin(),r.callSites.end());p.proofPCs.insert(r.proofPCs.begin(),r.proofPCs.end());
            }
        }
        p.proofPCs.insert(proofPCs.begin(),proofPCs.end());p.proofPCs.insert(pc);
        p.callerComplete=out.callerInventoryComplete&&out.contextOverflowPCs.empty()&&out.guardTrips==0&&out.unresolvedIndirectControlPCs.empty();
        p.domainClass=RootContextAnalysis::classifyDomain(p.aggregateAddress,rom.size());p.finiteRomOnly=p.domainClass==RootContextDomainClass::FiniteRom;p.finiteNonRomOnly=p.domainClass==RootContextDomainClass::FiniteNonRom;p.mixedRomNonRom=p.domainClass==RootContextDomainClass::Mixed;
        std::set<std::uint16_t> finite;p.exactSingleton=RootContextAnalysis::completeFiniteDomain(p.aggregateAddress,finite)&&finite.size()==1;
        p.accepted=p.callerComplete&&(p.domainClass==RootContextDomainClass::FiniteRom||p.domainClass==RootContextDomainClass::FiniteNonRom||p.domainClass==RootContextDomainClass::Mixed)&&!p.aggregateAddress.hasUnknownAlternative;
        p.note="source-local invariant: "+note;
        out.addressProofs.push_back(std::move(p));
        addWriterSourceInvariantProof(pc,operand,direction,domain,proofPCs,note);
    }

    bool screenAddressContract() const {
        // $0065 is a jump veneer for $202D.  The body subtracts $20 from each
        // coordinate byte, forms ((H-$20)&$1F)*32 + (L-$20), and adds $4040.
        // Therefore every returned HL is within $4040-$451F regardless of input.
        return insn(0x0065,"JP","$202D")&&insn(0x202D,"PUSH","AF")&&insn(0x202E,"PUSH","BC")&&
               insn(0x202F,"LD","A,L")&&insn(0x2030,"SUB","$20")&&insn(0x2032,"LD","L,A")&&
               insn(0x2033,"LD","A,H")&&insn(0x2034,"SUB","$20")&&insn(0x2036,"LD","H,A")&&
               insn(0x2037,"LD","B,$00")&&insn(0x2039,"SLA","H")&&insn(0x203B,"SLA","H")&&
               insn(0x203D,"SLA","H")&&insn(0x203F,"SLA","H")&&insn(0x2041,"RL","B")&&
               insn(0x2043,"SLA","H")&&insn(0x2045,"RL","B")&&insn(0x2047,"LD","C,H")&&
               insn(0x2048,"LD","H,$00")&&insn(0x204A,"ADD","HL,BC")&&insn(0x204B,"LD","BC,$4040")&&
               insn(0x204E,"ADD","HL,BC")&&insn(0x204F,"POP","BC")&&insn(0x2050,"POP","AF")&&insn(0x2051,"RET","");
    }

    void addSourceInvariantProofs(){
        // $01DC: four-iteration paired RAM/ROM comparison loop.  The only
        // explicit re-entry to $01E9 is its own DJNZ backedge; the caller enters
        // at $01DC and initializes HL=$4C86, DE=$0219, B=4.
        const bool loop01=insn(0x018C,"CALL","$01DC")&&insn(0x01DC,"LD","HL,$4C84")&&insn(0x01E3,"LD","DE,$0219")&&
            insn(0x01E6,"LD","BC,$0401")&&insn(0x01ED,"EX","DE,HL")&&insn(0x01F8,"INC","HL")&&insn(0x01FD,"EX","DE,HL")&&
            insn(0x0200,"INC","HL")&&insn(0x0201,"INC","DE")&&insn(0x0202,"DJNZ","$01E9")&&explicitEntryOnly(0x01E9,{0x0202})&&
            explicitEntryOnly(0x01EA,{})&&explicitEntryOnly(0x01EE,{})&&explicitEntryOnly(0x01F2,{})&&explicitEntryOnly(0x01F9,{});
        if(loop01){
            const std::set<std::uint16_t> q={0x018C,0x01DC,0x01E3,0x01E6,0x01ED,0x01F8,0x01FD,0x0200,0x0201,0x0202};
            addSourceInvariantProof(0x01E9,"(HL)",IndirectMemoryDirection::ReadWrite,sourceDomain(0x4C86,0x4C89,1,q,"four-iteration local loop RAM domain"),q,"B=4 bounds loop-start HL to $4C86-$4C89");
            addSourceInvariantProof(0x01EA,"(HL)",IndirectMemoryDirection::Read,sourceDomain(0x4C86,0x4C89,1,q,"four-iteration local loop RAM domain"),q,"same loop-start HL domain as $01E9");
            addSourceInvariantProof(0x01EE,"(HL)",IndirectMemoryDirection::Read,sourceDomain(0x0219,0x021F,2,q,"paired ROM compare table domain"),q,"EX DE,HL maps the four loop iterations to $0219,$021B,$021D,$021F");
            addSourceInvariantProof(0x01F2,"(DE)",IndirectMemoryDirection::Read,sourceDomain(0x4C86,0x4C89,1,q,"paired RAM update domain"),q,"after EX DE,HL, DE is the bounded RAM iterator");
            addSourceInvariantProof(0x01F9,"(HL)",IndirectMemoryDirection::Read,sourceDomain(0x021A,0x0220,2,q,"paired ROM compare table domain"),q,"one INC HL after the first ROM compare yields $021A,$021C,$021E,$0220");
            addWriterSourceInvariantProof(0x01F7,"(DE)",IndirectMemoryDirection::Write,sourceDomain(0x4C86,0x4C89,1,q,"paired RAM update domain"),q,"DE is the same bounded RAM iterator used by the preceding read");
            addWriterSourceInvariantProof(0x01FE,"(HL)",IndirectMemoryDirection::Write,sourceDomain(0x4C86,0x4C89,1,q,"paired RAM clear domain"),q,"EX DE,HL restores the bounded RAM iterator before the zero store");
        }

        // $0221: exactly 16 3-byte RAM records.  BC and HL are saved across the
        // RST $20 dispatch and restored at $025B/$025C, so the dispatch cannot
        // perturb the iterator used by the $025D-$0260 loop tail.
        auto di=inlineBySource.find(0x0246);
        const bool inline20=di!=inlineBySource.end()&&di->second&&di->second->kind==SystemRootInlineDataKind::Rst20DispatchTable&&di->second->end==0x025B;
        const bool loop02=insn(0x018F,"CALL","$0221")&&insn(0x0221,"LD","HL,$4C90")&&insn(0x0228,"LD","B,$10")&&
            insn(0x023C,"PUSH","BC")&&insn(0x023D,"PUSH","HL")&&insn(0x0246,"RST","$0020")&&inline20&&
            insn(0x025B,"POP","HL")&&insn(0x025C,"POP","BC")&&insn(0x025D,"INC","L")&&insn(0x025E,"INC","L")&&insn(0x025F,"INC","L")&&
            insn(0x0260,"DJNZ","$022A")&&explicitEntryOnly(0x022A,{0x0260})&&explicitEntryOnly(0x0235,{})&&explicitEntryOnly(0x0236,{})&&explicitEntryOnly(0x023F,{})&&explicitEntryOnly(0x0241,{});
        if(loop02){
            const std::set<std::uint16_t> q={0x018F,0x0221,0x0228,0x023C,0x023D,0x0246,0x025B,0x025C,0x025D,0x025E,0x025F,0x0260};
            const auto base=sourceDomain(0x4C90,0x4CBD,3,q,"16 x 3-byte RAM record bases");
            addSourceInvariantProof(0x022A,"(HL)",IndirectMemoryDirection::Read,base,q,"record base is $4C90+3*i for 0<=i<16");
            addSourceInvariantProof(0x0235,"(HL)",IndirectMemoryDirection::ReadWrite,base,q,"same bounded record base as $022A");
            addSourceInvariantProof(0x0236,"(HL)",IndirectMemoryDirection::Read,base,q,"same bounded record base as $022A");
            addSourceInvariantProof(0x023F,"(HL)",IndirectMemoryDirection::Read,sourceDomain(0x4C91,0x4CBE,3,q,"16 x record byte +1"),q,"saved/restored HL then INC L selects record byte +1");
            addSourceInvariantProof(0x0241,"(HL)",IndirectMemoryDirection::Read,sourceDomain(0x4C92,0x4CBF,3,q,"16 x record byte +2"),q,"second INC L selects record byte +2");
            addWriterSourceInvariantProof(0x023B,"(HL)",IndirectMemoryDirection::Write,base,q,"zero store uses the same 16 x 3-byte record base domain");
        }

        // memory-alias analysis writer-only invariants.  These do not alter the verified context-sensitive root analysis
        // read proof stream; they are an additive alias-audit side channel.
        // RST $08 is the firmware fill primitive.  Every rooted entry is either
        // its own DJNZ backedge or one of the statically enumerated RST callers.
        // Their initialized HL/B pairs stay inside $4000-$507F.  This deliberately
        // includes the startup work-RAM clear, so tracked lifecycle proofs still
        // have to account for that pre-initialization alias rather than hiding it.
        const std::set<std::uint16_t> rst08Callers={0x087F,0x0A88,0x2358,0x235E,0x235F,0x2360,0x2361,0x2367,0x2386,0x23FB,0x2408,0x2414,0x24D0,0x24D5,0x24E7,0x24F2,0x2661,0x2AEB};
        std::set<std::uint16_t> rst08Entries=rst08Callers;rst08Entries.insert(0x000A);
        bool rst08Shape=insn(0x0008,"LD","(HL),A")&&insn(0x0009,"INC","HL")&&insn(0x000A,"DJNZ","$0008")&&insn(0x000C,"RET","")&&explicitEntryOnly(0x0008,rst08Entries);
        for(auto pc:rst08Callers)rst08Shape=rst08Shape&&insn(pc,"RST","$0008");
        if(rst08Shape){
            auto q=rst08Entries;q.insert(0x0008);q.insert(0x0009);q.insert(0x000C);
            addWriterSourceInvariantProof(0x0008,"(HL)",IndirectMemoryDirection::Write,sourceDomain(0x4000,0x507F,1,q,"complete rooted RST $08 fill envelope"),q,"all rooted fill callsites initialize HL/B inside the $4000-$507F hardware/work-RAM envelope; B=0 correctly denotes 256 DJNZ iterations");
        }

        // Producer queue pointer $4C80/$4C81 is initialized alongside the
        // consumer pointer at $237C and advances by exactly two bytes, wrapping
        // only the low byte from $00 to $C0.  Therefore the two indirect writes
        // are the even/odd bytes of the fixed $4CC0-$4CFF queue ring.
        const bool queueProducer=insn(0x2379,"LD","HL,$4CC0")&&insn(0x237C,"LD","($4C80),HL")&&
            insn(0x0042,"LD","HL,($4C80)")&&insn(0x0045,"LD","(HL),B")&&insn(0x0046,"INC","L")&&
            insn(0x0047,"LD","(HL),C")&&insn(0x0048,"INC","L")&&insn(0x0049,"JR","NZ,$004D")&&
            insn(0x004B,"LD","L,$C0")&&insn(0x004D,"LD","($4C80),HL");
        if(queueProducer){
            const std::set<std::uint16_t> q={0x2379,0x237C,0x0042,0x0045,0x0046,0x0047,0x0048,0x0049,0x004B,0x004D};
            addWriterSourceInvariantProof(0x0045,"(HL)",IndirectMemoryDirection::Write,sourceDomain(0x4CC0,0x4CFE,2,q,"queue producer command-byte ring"),q,"$4C80 producer pointer starts at $4CC0 and advances by two with low-byte wrap");
            addWriterSourceInvariantProof(0x0047,"(HL)",IndirectMemoryDirection::Write,sourceDomain(0x4CC1,0x4CFF,2,q,"queue producer parameter-byte ring"),q,"one INC L after the command store selects the odd queue byte");
        }

        // $0AA6: 46-byte swap between two fixed work-RAM windows.
        const bool loop0A=insn(0x0AA6,"LD","B,$2E")&&insn(0x0AA8,"LD","IX,$4E0A")&&insn(0x0AAC,"LD","IY,$4E38")&&
            insn(0x0ABC,"INC","IX")&&insn(0x0ABE,"INC","IY")&&insn(0x0AC0,"DJNZ","$0AB0")&&explicitEntryOnly(0x0AB0,{0x0AC0})&&explicitEntryOnly(0x0AB3,{});
        if(loop0A){
            const std::set<std::uint16_t> q={0x0AA6,0x0AA8,0x0AAC,0x0ABC,0x0ABE,0x0AC0};
            addSourceInvariantProof(0x0AB0,"(IX+0)",IndirectMemoryDirection::Read,sourceDomain(0x4E0A,0x4E37,1,q,"46-byte fixed IX RAM window"),q,"IX starts at $4E0A and increments exactly once for each of B=$2E iterations");
            addSourceInvariantProof(0x0AB3,"(IY+0)",IndirectMemoryDirection::Read,sourceDomain(0x4E38,0x4E65,1,q,"46-byte fixed IY RAM window"),q,"IY starts at $4E38 and increments exactly once for each of B=$2E iterations");
            addWriterSourceInvariantProof(0x0AB6,"(IY+0)",IndirectMemoryDirection::Write,sourceDomain(0x4E38,0x4E65,1,q,"46-byte fixed IY RAM window"),q,"swap destination is the same bounded IY window");
            addWriterSourceInvariantProof(0x0AB9,"(IX+0)",IndirectMemoryDirection::Write,sourceDomain(0x4E0A,0x4E37,1,q,"46-byte fixed IX RAM window"),q,"swap destination is the same bounded IX window");
        }

        // Fixed screen-memory writer loops used by the board/display setup.
        const bool screenColumns=insn(0x0508,"LD","DE,$0020")&&insn(0x050B,"LD","B,$1C")&&insn(0x050D,"LD","IX,$4040")&&
            insn(0x0511,"LD","(IX+17),A")&&insn(0x0514,"LD","(IX+19),A")&&insn(0x0517,"ADD","IX,DE")&&insn(0x0519,"DJNZ","$0511")&&explicitEntryOnly(0x0511,{0x0519});
        if(screenColumns){const std::set<std::uint16_t> q={0x0508,0x050B,0x050D,0x0511,0x0514,0x0517,0x0519};
            addWriterSourceInvariantProof(0x0511,"(IX+17)",IndirectMemoryDirection::Write,sourceDomain(0x4051,0x43B1,0x20,q,"28 screen-column writes"),q,"IX=$4040+$20*i for exactly B=$1C iterations");
            addWriterSourceInvariantProof(0x0514,"(IX+19)",IndirectMemoryDirection::Write,sourceDomain(0x4053,0x43B3,0x20,q,"28 screen-column writes"),q,"same loop with fixed +$13 displacement");}

        const bool tileStamp=insn(0x0471,"LD","HL,$4304")&&insn(0x0476,"CALL","$05BF")&&insn(0x048B,"LD","HL,$4307")&&insn(0x0490,"CALL","$05BF")&&
            insn(0x04A5,"LD","HL,$430A")&&insn(0x04AA,"CALL","$05BF")&&insn(0x04BF,"LD","HL,$430D")&&insn(0x04C4,"CALL","$05BF")&&
            explicitEntryOnly(0x05BF,{0x0476,0x0490,0x04AA,0x04C4})&&insn(0x05C7,"LD","BC,$001E")&&insn(0x05D3,"LD","DE,$0400")&&
            insn(0x05DD,"SBC","HL,BC")&&insn(0x05DF,"LD","(HL),A")&&insn(0x05E1,"LD","(HL),A")&&insn(0x05E3,"LD","(HL),A");
        if(tileStamp){const std::set<std::uint16_t> q={0x0471,0x0476,0x048B,0x0490,0x04A5,0x04AA,0x04BF,0x04C4,0x05BF,0x05C7,0x05D3,0x05DD};
            addWriterSourceInvariantProof(0x05DF,"(HL)",IndirectMemoryDirection::Write,sourceDomain(0x4706,0x470F,3,q,"four lower-screen stamp cells +$402"),q,"four exact caller HL bases plus fixed function arithmetic");
            addWriterSourceInvariantProof(0x05E1,"(HL)",IndirectMemoryDirection::Write,sourceDomain(0x4705,0x470E,3,q,"four lower-screen stamp cells +$401"),q,"one DEC L after the +$402 cell");
            addWriterSourceInvariantProof(0x05E3,"(HL)",IndirectMemoryDirection::Write,sourceDomain(0x4704,0x470D,3,q,"four lower-screen stamp cells +$400"),q,"second DEC L after the +$402 cell");}

        const bool stateCopy=insn(0x0889,"LD","HL,$4E0A")&&insn(0x088C,"LD","DE,$4E38")&&insn(0x088F,"LD","BC,$002E")&&insn(0x0892,"LDIR","");
        if(stateCopy){const std::set<std::uint16_t> q={0x0889,0x088C,0x088F,0x0892};addWriterSourceInvariantProof(0x0892,"(DE repeated)",IndirectMemoryDirection::Write,sourceDomain(0x4E38,0x4E65,1,q,"46-byte alternate-player state destination"),q,"LDIR destination is exact $4E38..$4E65 from BC=$002E");}

        // The four $205A callers supply BC=$4D99..$4D9C.  $2052/$0065
        // changes HL only, so either conditional store remains in that fixed RAM set.
        const bool collisionFlags=insn(0x1B46,"LD","BC,$4D99")&&insn(0x1B49,"CALL","$205A")&&insn(0x1C59,"LD","BC,$4D9A")&&insn(0x1C5C,"CALL","$205A")&&
            insn(0x1D30,"LD","BC,$4D9B")&&insn(0x1D33,"CALL","$205A")&&insn(0x1E07,"LD","BC,$4D9C")&&insn(0x1E0A,"CALL","$205A")&&
            explicitEntryOnly(0x205A,{0x1B49,0x1C5C,0x1D33,0x1E0A})&&insn(0x2064,"LD","(BC),A")&&insn(0x2067,"LD","(BC),A");
        if(collisionFlags){const std::set<std::uint16_t> q={0x1B46,0x1B49,0x1C59,0x1C5C,0x1D30,0x1D33,0x1E07,0x1E0A,0x205A,0x2052,0x2064,0x2067};
            const auto d=sourceDomain(0x4D99,0x4D9C,1,q,"four collision-result flag bytes");addWriterSourceInvariantProof(0x2064,"(BC)",IndirectMemoryDirection::Write,d,q,"BC is preserved through the screen-address helper");addWriterSourceInvariantProof(0x2067,"(BC)",IndirectMemoryDirection::Write,d,q,"same four caller-supplied BC alternatives");}

        const bool bootClear=insn(0x230B,"LD","HL,$5000")&&insn(0x230E,"LD","B,$08")&&insn(0x2311,"LD","(HL),A")&&insn(0x2313,"DJNZ","$2311")&&
            insn(0x2315,"LD","HL,$4000")&&insn(0x2318,"LD","B,$04")&&insn(0x2322,"LD","(HL),A")&&insn(0x2324,"JR","NZ,$2322")&&insn(0x2326,"INC","H")&&insn(0x2327,"DJNZ","$231A")&&
            insn(0x2329,"LD","B,$04")&&insn(0x2334,"LD","(HL),A")&&insn(0x2336,"JR","NZ,$2334")&&insn(0x2338,"INC","H")&&insn(0x2339,"DJNZ","$232B");
        if(bootClear){const std::set<std::uint16_t> q={0x230B,0x230E,0x2311,0x2313,0x2315,0x2318,0x2322,0x2324,0x2326,0x2327,0x2329,0x2334,0x2336,0x2338,0x2339};
            addWriterSourceInvariantProof(0x2311,"(HL)",IndirectMemoryDirection::Write,sourceDomain(0x5000,0x5007,1,q,"eight hardware latch bytes"),q,"B=$08 bounds the startup hardware clear");
            addWriterSourceInvariantProof(0x2322,"(HL)",IndirectMemoryDirection::Write,sourceDomain(0x4000,0x43FF,1,q,"four 256-byte video pages"),q,"L wrap plus four H iterations covers exactly $4000-$43FF");
            addWriterSourceInvariantProof(0x2334,"(HL)",IndirectMemoryDirection::Write,sourceDomain(0x4400,0x47FF,1,q,"four 256-byte color/video pages"),q,"second four-page loop starts with HL=$4400 after the first loop");}

        // Score/display writers.  All source entries and loop bounds are
        // statically enumerated; their destinations stay in video RAM and are
        // therefore disjoint from the tracked $4Cxx/$4Dxx/$4Exx lifecycle bytes.
        const bool digitWriter=insn(0x2A8C,"LD","HL,$4E8A")&&insn(0x2A8F,"LD","B,$03")&&insn(0x2AAD,"JR","$2ABE")&&
            insn(0x2AAF,"LD","A,($4E09)")&&insn(0x2AB2,"LD","BC,$0304")&&insn(0x2AB5,"LD","HL,$43FC")&&insn(0x2ABB,"LD","HL,$43E9")&&
            insn(0x2ABE,"LD","A,(DE)")&&insn(0x2AC3,"CALL","$2ACE")&&insn(0x2AC6,"LD","A,(DE)")&&insn(0x2AC7,"CALL","$2ACE")&&
            insn(0x2ACA,"DEC","DE")&&insn(0x2ACB,"DJNZ","$2ABE")&&insn(0x2ADD,"LD","(HL),A")&&insn(0x2ADE,"DEC","HL");
        if(digitWriter){const std::set<std::uint16_t> q={0x2A8C,0x2A8F,0x2AAD,0x2AAF,0x2AB2,0x2AB5,0x2ABB,0x2ABE,0x2AC3,0x2AC6,0x2AC7,0x2ACA,0x2ACB,0x2ACE,0x2ADD,0x2ADE,0x2AF2,0x2AF5,0x2AFE,0x2B05,0x2B09};
            addWriterSourceInvariantProof(0x2ADD,"(HL)",IndirectMemoryDirection::Write,sourceDomain(0x43E4,0x43FC,1,q,"three six-cell score/display windows"),q,"all rooted $2ABE entries use HL=$43E9/$43F2/$43FC with B=3; two calls to $2ACE per iteration only decrement HL");}

        const bool smallGlyphWriters=insn(0x2B4A,"LD","HL,$401A")&&insn(0x2B4D,"LD","C,$05")&&insn(0x2B53,"CP","$06")&&insn(0x2B59,"CALL","$2B8F")&&
            insn(0x2B5F,"DJNZ","$2B57")&&insn(0x2B63,"CALL","$2B7E")&&insn(0x2B7E,"LD","A,$40")&&
            insn(0x2B82,"LD","(HL),A")&&insn(0x2B84,"LD","(HL),A")&&insn(0x2B89,"LD","(HL),A")&&insn(0x2B8B,"LD","(HL),A")&&
            insn(0x2B94,"LD","(HL),A")&&insn(0x2B97,"LD","(HL),A")&&insn(0x2B9A,"LD","(HL),A")&&insn(0x2B9D,"LD","(HL),A")&&
            insn(0x2BFF,"LD","HL,$4004")&&insn(0x2C03,"CALL","$2B8F")&&insn(0x2C0C,"CALL","$2B80")&&insn(0x2C1B,"CALL","$2B7E")&&insn(0x2C23,"CALL","$2B80")&&
            explicitEntryOnly(0x2B7E,{0x2B63,0x2C1B})&&explicitEntryOnly(0x2B80,{0x2C0C,0x2C23})&&explicitEntryOnly(0x2B8F,{0x2B59,0x2C03});
        if(smallGlyphWriters){const std::set<std::uint16_t> q={0x2B4A,0x2B4D,0x2B53,0x2B59,0x2B5F,0x2B63,0x2B7E,0x2B80,0x2B8F,0x2BFF,0x2C03,0x2C0C,0x2C1B,0x2C23};const auto d=sourceDomain(0x4000,0x47FF,1,q,"bounded video-RAM glyph writer envelope");
            for(auto pc:{0x2B82,0x2B84,0x2B89,0x2B8B,0x2B94,0x2B97,0x2B9A,0x2B9D})addWriterSourceInvariantProof(pc,"(HL)",IndirectMemoryDirection::Write,d,q,"all complete callers derive HL from $401A/$4004 bounded screen loops; helper preserves caller HL on return");}

        // $2C5E text renderer: enumerate every static entry and every selector
        // alternative produced by the caller masks/constants.  A descriptor's
        // first word has only bit 15 plus a <=$03FF screen offset.  Both renderer
        // phases move IX monotonically downward by 1 or $20; B is 8-bit and each
        // reachable descriptor has a $2F terminator within 255 bytes.  Thus even
        // a conservative two-phase envelope cannot reach the tracked $4C-$4E RAM.
        const std::set<std::uint16_t> textEntries={0x0629,0x23A7,0x2AE2,0x2BAA,0x2BAF,0x30F5,0x3105,0x31E7,0x31F9,0x3204,0x3209,0x322F,0x323B};
        std::set<unsigned> textSelectors;for(unsigned b=0;b<=0x36;++b)if(b<0x18||b>0x1A)textSelectors.insert(b);
        bool textWriter=explicitEntryOnly(0x2C5E,textEntries)&&insn(0x2C5E,"LD","HL,$36A5")&&insn(0x2C61,"RST","$0018")&&insn(0x2C65,"LD","IX,$4400")&&
            insn(0x2C6D,"LD","DE,$FC00")&&insn(0x2C70,"ADD","IX,DE")&&insn(0x2C72,"LD","DE,$FFFF")&&insn(0x2C79,"LD","DE,$FFE0")&&
            insn(0x2C89,"LD","(IX+0),A")&&insn(0x2C9B,"LD","(IX+0),A")&&insn(0x2CA4,"LD","(IX+0),A")&&insn(0x2CB1,"LD","(IX+0),$40");
        textWriter=textWriter&&insn(0x0623,"LD","B,$09")&&insn(0x0627,"LD","B,$08")&&insn(0x2AE0,"LD","B,$00")&&insn(0x2BA8,"LD","B,$02")&&insn(0x2BAD,"LD","B,$01")&&
            insn(0x30F3,"LD","B,$23")&&insn(0x3103,"LD","B,$24")&&insn(0x31E4,"ADD","A,$25")&&insn(0x31E6,"LD","B,A")&&insn(0x31F7,"LD","B,$2A")&&
            insn(0x3202,"LD","B,$2B")&&insn(0x3207,"LD","B,$2E")&&insn(0x322D,"LD","B,$29")&&insn(0x3238,"ADD","A,$2C")&&insn(0x323A,"LD","B,A");
        // The additional $23A7 entry is dispatch-table index $1C.  Its B
        // parameter is the queue's C byte.  Every command-$1C producer is bounded:
        // $4E75 is masked to 0/1 before the wrapper adds fixed C constants;
        // player-select $4E09 is zero/toggled by XOR 1; and $4DD4 is either zero
        // or the third byte of the clamped 21-entry $0EFD table (6..13).  A
        // conservative superset is every valid text selector $00-$36 excluding
        // the three non-pointer-table slots $18-$1A.
        textWriter=textWriter&&insn(0x23A7,"RST","$0020")&&
            insn(0x0585,"LD","B,$1C")&&insn(0x0598,"LD","B,$1C")&&insn(0x0931,"LD","B,$1C")&&insn(0x19BC,"LD","B,$1C")&&
            insn(0x2707,"LD","A,B")&&insn(0x2708,"RLCA","")&&insn(0x2709,"CPL","")&&insn(0x270A,"AND","$01")&&insn(0x270C,"LD","($4E75),A")&&
            insn(0x0972,"XOR","A")&&insn(0x097C,"LD","($4E09),A")&&insn(0x0964,"LD","A,($4E09)")&&insn(0x0967,"XOR","$01")&&insn(0x0969,"LD","($4E09),A")&&
            insn(0x0EDE,"LD","A,($4E13)")&&insn(0x0EE1,"CP","$14")&&insn(0x0EE5,"LD","A,$14")&&insn(0x0EE8,"ADD","A,A")&&insn(0x0EE9,"ADD","A,B")&&insn(0x0EF5,"LD","($4DD4),A")&&
            insn(0x1000,"XOR","A")&&insn(0x1001,"LD","($4DD4),A")&&
            insn(0x04DB,"LD","C,$12")&&insn(0x04DD,"JP","$0585")&&insn(0x04E0,"LD","C,$13")&&insn(0x04E2,"CALL","$0585");
        if(textWriter){for(unsigned i=0;i<21;++i){const unsigned a=0x0EFFu+3u*i;if(a>=rom.size()||rom[a]<6||rom[a]>13){textWriter=false;break;}}}
        std::set<std::uint16_t> textProof=textEntries;textProof.insert({0x2C5E,0x2C61,0x2C62,0x2C64,0x2C65,0x2C6D,0x2C70,0x2C72,0x2C75,0x2C79,0x2C7C,0x2C84,0x2C89,0x2C92,0x2C95,0x2C9B,0x2CA4,0x2CAC,0x2CB1,0x2CBB});
        if(textWriter){
            for(auto b:textSelectors){const std::size_t tp=0x36A5u+2u*b;if(tp+1>=rom.size()){textWriter=false;break;}const std::uint16_t dp=static_cast<std::uint16_t>(rom[tp]|(static_cast<std::uint16_t>(rom[tp+1])<<8));if(static_cast<std::size_t>(dp)+2>=rom.size()){textWriter=false;break;}const std::uint16_t off=static_cast<std::uint16_t>(rom[dp]|(static_cast<std::uint16_t>(rom[dp+1])<<8));if((off&0x7C00u)!=0){textWriter=false;break;}bool term=false;for(std::size_t j=2;j<257&&static_cast<std::size_t>(dp)+j<rom.size();++j)if(rom[dp+j]==0x2F){term=true;break;}if(!term){textWriter=false;break;}textProof.insert(static_cast<std::uint16_t>(tp));textProof.insert(dp);}
        }
        if(textWriter){std::set<std::uint16_t> env;for(unsigned a=0x0000;a<=0x47FF;++a)env.insert(static_cast<std::uint16_t>(a));for(unsigned a=0x8000;a<=0xC7FF;++a)env.insert(static_cast<std::uint16_t>(a));const auto d=sourceFiniteSet(env,textProof,"conservative two-phase $2C5E renderer envelope excluding $4C-$4E work RAM");
            for(auto pc:{0x2C89,0x2C9B,0x2CA4,0x2CB1})addWriterSourceInvariantProof(pc,"(IX+0)",IndirectMemoryDirection::Write,d,textProof,"complete static selector/descriptor audit bounds renderer stores away from tracked work-RAM lifecycles");}

        // $0EDB: arbitrary level byte is clamped to 0..$14, multiplied by 3,
        // then consumed by RST $10 from base $0EFD.  This gives two exact
        // strided ROM domains even though the incoming level byte is unknown.
        const bool table0E=insn(0x0EDB,"LD","HL,$0EFD")&&insn(0x0EDE,"LD","A,($4E13)")&&insn(0x0EE1,"CP","$14")&&
            insn(0x0EE3,"JR","C,$0EE7")&&insn(0x0EE5,"LD","A,$14")&&insn(0x0EE7,"LD","B,A")&&insn(0x0EE8,"ADD","A,A")&&
            insn(0x0EE9,"ADD","A,B")&&insn(0x0EEA,"RST","$0010")&&insn(0x0EEE,"INC","HL")&&insn(0x0EEF,"LD","A,(HL)")&&
            insn(0x0EF3,"INC","HL")&&insn(0x0EF4,"LD","A,(HL)")&&explicitEntryOnly(0x0EEF,{})&&explicitEntryOnly(0x0EF4,{});
        if(table0E){
            const std::set<std::uint16_t> q={0x0EDB,0x0EDE,0x0EE1,0x0EE3,0x0EE5,0x0EE7,0x0EE8,0x0EE9,0x0EEA,0x0010,0x0016,0x0EEE,0x0EF3};
            addSourceInvariantProof(0x0EEF,"(HL)",IndirectMemoryDirection::Read,sourceDomain(0x0EFE,0x0F3A,3,q,"clamped 21-entry ROM record byte +1"),q,"clamp A to 0..$14 and multiply by 3 before RST $10");
            addSourceInvariantProof(0x0EF4,"(HL)",IndirectMemoryDirection::Read,sourceDomain(0x0EFF,0x0F3B,3,q,"clamped 21-entry ROM record byte +2"),q,"second post-RST increment selects the third byte of the same 3-byte record");
        }

        // $0879 has a caller-independent HL postcondition at its only return.
        if(insn(0x04E5,"CALL","$0879")&&insn(0x0879,"LD","HL,$4E09")&&insn(0x0880,"CALL","$24C9")&&
           insn(0x0894,"LD","HL,$4E04")&&insn(0x0897,"INC","(HL)")&&insn(0x0898,"RET","")&&insn(0x04E8,"DEC","(HL)")&&explicitEntryOnly(0x04E8,{})){
            const std::set<std::uint16_t> q={0x04E5,0x0879,0x0880,0x0894,0x0897,0x0898};
            addSourceInvariantProof(0x04E8,"(HL)",IndirectMemoryDirection::ReadWrite,sourceDomain(0x4E04,0x4E04,1,q,"callee HL postcondition"),q,"$0879 overwrites HL with $4E04 immediately before its sole RET");
        }

        // Screen-address contract.  This proof intentionally does not require a
        // finite input coordinate domain: the transformation itself guarantees
        // a non-ROM output for every 8-bit H/L input combination.
        if(screenAddressContract()){
            const std::set<std::uint16_t> mapq={0x0065,0x202D,0x202F,0x2030,0x2033,0x2034,0x2037,0x2039,0x203B,0x203D,0x203F,0x2041,0x2043,0x2045,0x2047,0x2048,0x204A,0x204B,0x204E,0x2051};
            const auto screen=sourceDomain(0x4040,0x451F,1,mapq,"coordinate mapper output envelope");
            struct Site{std::uint16_t callpc,readpc;};
            const Site baseSites[]={{0x2012,0x2015},{0x2995,0x2998},{0x19D5,0x19D8}};
            for(const auto&s:baseSites)if(insn(s.callpc,"CALL","$0065")&&insn(s.readpc,"LD","A,(HL)")&&explicitEntryOnly(s.readpc,{})){
                auto q=mapq;q.insert(s.callpc);addSourceInvariantProof(s.readpc,"(HL)",IndirectMemoryDirection::Read,screen,q,"immediate read uses $0065 return HL, always within $4040-$451F");
            }
            if(insn(0x19D5,"CALL","$0065")&&insn(0x19D8,"LD","A,(HL)")&&insn(0x19ED,"LD","(HL),B")&&explicitEntryOnly(0x19ED,{})){
                auto q=mapq;q.insert(0x19D5);q.insert(0x19D8);q.insert(0x19ED);addWriterSourceInvariantProof(0x19ED,"(HL)",IndirectMemoryDirection::Write,screen,q,"HL is unchanged after the $0065 screen mapping and tile checks before the store");
            }
            const bool plus4=insn(0x2052,"CALL","$0065")&&insn(0x2055,"LD","DE,$0400")&&insn(0x2058,"ADD","HL,DE")&&insn(0x2059,"RET","");
            if(plus4){
                auto q=mapq;q.insert(0x2052);q.insert(0x2055);q.insert(0x2058);q.insert(0x2059);
                const auto screen2=sourceDomain(0x4440,0x491F,1,q,"coordinate mapper + $0400 output envelope");
                const Site plusSites[]={{0x1C0E,0x1C11},{0x1CE5,0x1CE8},{0x1DBC,0x1DBF},{0x1E93,0x1E96},{0x205A,0x205D}};
                for(const auto&s:plusSites)if(insn(s.callpc,"CALL","$2052")&&insn(s.readpc,"LD","A,(HL)")&&explicitEntryOnly(s.readpc,{})){
                    auto qq=q;qq.insert(s.callpc);addSourceInvariantProof(s.readpc,"(HL)",IndirectMemoryDirection::Read,screen2,qq,"immediate read uses $2052 return HL, always within $4440-$491F");
                }
            }
        }
    }

    bool handleRst10(const Instruction&in,const NodeKey&k,State s){
        V hl=getReg(s,"HL"),a=getReg(s,"A"),addr;V off;off.bits=16;off.unknown=a.unknown;off.widened=a.widened;off.values=a.values;off.proof=a.proof;finiteAdd(hl,off,addr);addr.proof.insert(in.address);addr.proof.insert(0x0016);addAccess(0x0016,"(HL)",IndirectMemoryDirection::Read,addr,k.context,true,{in.address,0x0010,0x0016},"RST $10 summary: effective address is caller HL plus unsigned 8-bit A; all rooted restart callers contribute separately");V byte=loadByte(s,addr,rom,maxValues,widenEvents);setPair(s,"HL",addr,maxValues,widenEvents);setByte(s,"A",byte,maxValues,widenEvents);seed(static_cast<std::uint16_t>(in.address+in.length()),k.context,s);return true;
    }

    bool handleRst18(const Instruction&in,const NodeKey&k,State s){
        V hl=getReg(s,"HL"),bv=getReg(s,"B");V lowAddr;lowAddr.bits=16;lowAddr.unknown=hl.unknown||bv.unknown;lowAddr.widened=hl.widened||bv.widened;lowAddr.proof=hl.proof;lowAddr.proof.insert(bv.proof.begin(),bv.proof.end());if(!lowAddr.unknown&&!lowAddr.widened){for(auto h:hl.values)for(auto b:bv.values){lowAddr.values.insert(static_cast<std::uint16_t>(h+static_cast<std::uint8_t>(2u*static_cast<std::uint8_t>(b))));if(lowAddr.values.size()>maxValues){lowAddr=unknownV(16);lowAddr.widened=true;++widenEvents;break;}}}lowAddr.proof.insert(in.address);V highAddr=shifted(lowAddr,1,16,maxValues,widenEvents);addAccess(0x0016,"(HL)",IndirectMemoryDirection::Read,lowAddr,k.context,true,{in.address,0x0018,0x001A,0x0016},"RST $18 nested RST $10 low-byte address: caller HL + 2*B (8-bit wrapped selector)");addAccess(0x001D,"(HL)",IndirectMemoryDirection::Read,highAddr,k.context,true,{in.address,0x0018,0x001C,0x001D},"RST $18 high-byte address is exactly one byte after the caller-specific low-byte table address");
        V result;result.bits=16;result.unknown=lowAddr.unknown||highAddr.unknown;result.widened=lowAddr.widened||highAddr.widened;result.proof=lowAddr.proof;result.proof.insert(highAddr.proof.begin(),highAddr.proof.end());if(!result.unknown&&!result.widened){for(auto la:lowAddr.values){V lo=loadByte(s,exactV(la,16),rom,maxValues,widenEvents),hi=loadByte(s,exactV(static_cast<std::uint16_t>(la+1),16),rom,maxValues,widenEvents);if(lo.unknown||hi.unknown){result=unknownV(16);break;}for(auto l:lo.values)for(auto h:hi.values){result.values.insert(static_cast<std::uint16_t>(((h&0xFFu)<<8)|(l&0xFFu)));if(result.values.size()>maxValues){result=unknownV(16);result.widened=true;++widenEvents;break;}}}}setPair(s,"HL",result,maxValues,widenEvents);setPair(s,"DE",result,maxValues,widenEvents);V lowByte=loadByte(s,lowAddr,rom,maxValues,widenEvents);setByte(s,"A",lowByte,maxValues,widenEvents);seed(static_cast<std::uint16_t>(in.address+in.length()),k.context,s);return true;
    }

    bool handleRst20(const Instruction&in,const NodeKey&k,State s){
        auto it=inlineBySource.find(in.address);if(it==inlineBySource.end()||it->second->kind!=SystemRootInlineDataKind::Rst20DispatchTable){out.unresolvedIndirectControlPCs.insert(in.address);return true;}const auto*d=it->second;std::set<std::uint16_t> targets=d->dispatchTargets;if(targets.empty()){out.unresolvedIndirectControlPCs.insert(in.address);return true;}V h;h.bits=16;h.unknown=false;h.values=targets;h.proof={in.address,0x0020,0x0027};setPair(s,"HL",h,maxValues,widenEvents);V aval;aval.bits=8;aval.unknown=false;for(auto t:targets)aval.values.insert(static_cast<std::uint8_t>(t));setByte(s,"A",aval,maxValues,widenEvents);Context dc=k.context;dc.barrierDepth=dc.frames.size();for(auto t:targets)seed(t,dc,s);return true;
    }

    bool handleRst28(const Instruction&in,const NodeKey&k,State s){auto it=inlineBySource.find(in.address);if(it==inlineBySource.end()||it->second->kind!=SystemRootInlineDataKind::Rst28InlineArgs||it->second->end-it->second->start!=2){out.unresolvedIndirectControlPCs.insert(in.address);return true;}const auto*d=it->second;setByte(s,"B",exactV(rom[d->start],8,in.address),maxValues,widenEvents);setByte(s,"C",exactV(rom[d->start+1],8,in.address),maxValues,widenEvents);setPair(s,"HL",unknownV(16),maxValues,widenEvents);seed(d->end,k.context,s);return true;}
    bool handleRst30(const Instruction&in,const NodeKey&k,State s){auto it=inlineBySource.find(in.address);if(it==inlineBySource.end()||it->second->kind!=SystemRootInlineDataKind::Rst30InlinePayload||it->second->end-it->second->start!=3){out.unresolvedIndirectControlPCs.insert(in.address);return true;}const auto*d=it->second;setByte(s,"A",unknownV(8),maxValues,widenEvents);setByte(s,"B",unknownV(8),maxValues,widenEvents);setPair(s,"DE",unknownV(16),maxValues,widenEvents);setPair(s,"HL",unknownV(16),maxValues,widenEvents);seed(d->end,k.context,s);return true;}
    bool handleCall5(const Instruction&in,const NodeKey&k,State s){auto it=inlineBySource.find(in.address);if(it==inlineBySource.end()||it->second->kind!=SystemRootInlineDataKind::CallInlineFiveBytes||it->second->end-it->second->start!=5){return false;}const auto*d=it->second;setByte(s,"E",exactV(rom[d->start],8,in.address),maxValues,widenEvents);setByte(s,"D",exactV(rom[d->start+1],8,in.address),maxValues,widenEvents);setByte(s,"C",exactV(rom[d->start+2],8,in.address),maxValues,widenEvents);setByte(s,"B",exactV(rom[d->start+3],8,in.address),maxValues,widenEvents);setByte(s,"A",exactV(rom[d->start+4],8,in.address),maxValues,widenEvents);seed(d->end,k.context,s);return true;}


    void run(){
        if(rootedPCs.empty())return;
        std::uint16_t root=*rootedPCs.begin();
        for(auto pc:rootedPCs)if(pc==0x008D){root=pc;break;}
        State initial;Context ctx;seed(root,ctx,initial);std::size_t guard=0;
        while(!work.empty()){
            if(++guard>300000){++out.guardTrips;out.callerInventoryComplete=false;break;}NodeKey k=work.front();work.pop_front();State s=states[k];Instruction in=dis.decode(rom,k.pc);if(in.bytes.empty()||in.mnemonic=="DB")continue;recordInstructionMemory(in,s,k.context);
            if(in.flow==FlowKind::Restart){if(in.target==0x10){handleRst10(in,k,s);continue;}if(in.target==0x18){handleRst18(in,k,s);continue;}if(in.target==0x20){handleRst20(in,k,s);continue;}if(in.target==0x28){handleRst28(in,k,s);continue;}if(in.target==0x30){handleRst30(in,k,s);continue;}}
            if(in.flow==FlowKind::Call&&in.target==0x2BCD&&handleCall5(in,k,s))continue;
            transfer(in,s);const std::uint16_t next=static_cast<std::uint16_t>(k.pc+in.length());
            if(in.flow==FlowKind::Halt)continue;
            if(in.flow==FlowKind::Return){
                // Only leaf callees whose complete control flow and state-changing instruction
                // set are modeled may propagate a returned abstract state.  All other calls use
                // the conservative continuation seeded at the call site.
                if(in.conditional)seed(next,k.context,s);
                if(!k.context.frames.empty()&&k.context.frames.back().preciseReturn){
                    Context rc=k.context;const Frame f=rc.frames.back();rc.frames.pop_back();
                    if(rc.barrierDepth>rc.frames.size())rc.barrierDepth=rc.frames.size();
                    seed(f.returnPC,rc,s);
                }
                continue;
            }
            if(in.flow==FlowKind::Call||in.flow==FlowKind::Restart){
                if(in.conditional)seed(next,k.context,s); // not-taken path
                if(in.target<0||static_cast<std::size_t>(in.target)>=rom.size()){
                    out.unresolvedIndirectControlPCs.insert(k.pc);State conservativeReturn;seed(next,k.context,conservativeReturn);continue;
                }
                const bool precise=(in.flow==FlowKind::Call)&&preciseLeaf(static_cast<std::uint16_t>(in.target));
                if(!precise){State conservativeReturn;seed(next,k.context,conservativeReturn);}
                Context cc=k.context;
                if(maxDepth==0||cc.frames.size()>=maxDepth){
                    out.contextOverflowPCs.insert(k.pc);++out.contextOverflowEvents;out.callerInventoryComplete=false;
                    State conservativeReturn;seed(next,k.context,conservativeReturn);continue;
                }
                cc.frames.push_back({k.pc,next,precise});seed(static_cast<std::uint16_t>(in.target),cc,s);continue;
            }
            if(in.mnemonic=="DJNZ"&&in.target>=0){
                // transfer() has already applied the architectural decrement. Split only on exact post-decrement B values.
                V b=getReg(s,"B");
                if(!b.unknown&&!b.widened){
                    State taken=s,fall=s;V tv=b,fv=b;tv.values.clear();fv.values.clear();
                    for(auto x:b.values){if((x&0xFFu)!=0)tv.values.insert(x);else fv.values.insert(x);}
                    if(!tv.values.empty()){setByte(taken,"B",tv,maxValues,widenEvents);seed(static_cast<std::uint16_t>(in.target),k.context,taken);}
                    if(!fv.values.empty()){setByte(fall,"B",fv,maxValues,widenEvents);seed(next,k.context,fall);}
                }else{seed(static_cast<std::uint16_t>(in.target),k.context,s);seed(next,k.context,s);}
                continue;
            }
            if((in.flow==FlowKind::Jump||in.flow==FlowKind::RelativeJump)&&in.indirect){
                std::string r;int d=0;const auto ops=splitOps(in.operands);bool resolved=false;
                if(!ops.empty()&&IndirectAddressAnalysis::parseIndirectOperand(ops.back(),r,d)&&isPair(r)){
                    V t=shifted(getReg(s,r),d,16,maxValues,widenEvents);
                    if(!t.unknown&&!t.widened&&!t.values.empty()){
                        resolved=true;for(auto x:t.values)seed(x,k.context,s);
                    }
                }
                if(!resolved){
                    out.unresolvedIndirectControlPCs.insert(k.pc);
                    // An unresolved transfer inside a direct-call context may eventually return
                    // after arbitrary register/RAM effects.  Preserve that possibility explicitly.
                    if(!k.context.frames.empty()){
                        Context rc=k.context;const Frame f=rc.frames.back();rc.frames.pop_back();
                        if(rc.barrierDepth>rc.frames.size())rc.barrierDepth=rc.frames.size();
                        State conservativeReturn;seed(f.returnPC,rc,conservativeReturn);
                    }
                }
                if(in.conditional){seed(next,k.context,s);}
                continue;
            }
            if(in.flow==FlowKind::Jump||in.flow==FlowKind::RelativeJump){
                // Conditional paths stay caller-complete; stale flag facts are never allowed to delete an alternative.
                if(in.conditional){if(in.target>=0)seed(static_cast<std::uint16_t>(in.target),k.context,s);seed(next,k.context,s);}
                else if(in.target>=0)seed(static_cast<std::uint16_t>(in.target),k.context,s);
                continue;
            }
            seed(next,k.context,s);
        }
        out.rootedContextStates=states.size();out.valueWidenEvents=widenEvents;
    }

    void finalize(){
        // Build caller-complete per-PC aggregates from every represented access context.
        for(const auto&kv:accessContexts){RootContextAddressProofRecord p;p.id=out.addressProofs.size();p.pc=kv.first.pc;p.operand=kv.first.operand;p.direction=kv.first.direction;std::vector<AddressLatticeValue> domains;for(auto id:kv.second){const auto&r=out.contextRecords[id];p.contextRecordIds.insert(id);p.callSites.insert(r.callSites.begin(),r.callSites.end());p.proofPCs.insert(r.proofPCs.begin(),r.proofPCs.end());p.contextOverflow=p.contextOverflow||r.contextWidened;domains.push_back(r.address);}p.aggregateAddress=RootContextAnalysis::mergeCallerDomains(domains,maxValues);p.inheritedSystemRootBlocker=out.inheritedBlockerPCs.count(p.pc)!=0;p.newlyRootedSystemRootBlocker=out.newlyRootedBlockerPCs.count(p.pc)!=0;p.callerComplete=out.callerInventoryComplete&&!out.contextOverflowPCs.count(p.pc);p.domainClass=RootContextAnalysis::classifyDomain(p.aggregateAddress,rom.size());p.finiteRomOnly=p.domainClass==RootContextDomainClass::FiniteRom;p.finiteNonRomOnly=p.domainClass==RootContextDomainClass::FiniteNonRom;p.mixedRomNonRom=p.domainClass==RootContextDomainClass::Mixed;p.exactSingleton=p.finiteRomOnly&&p.aggregateAddress.values.size()==1&&!p.aggregateAddress.hasUnknownAlternative;p.accepted=p.callerComplete&&(p.domainClass==RootContextDomainClass::FiniteRom||p.domainClass==RootContextDomainClass::FiniteNonRom||p.domainClass==RootContextDomainClass::Mixed)&&!p.aggregateAddress.hasUnknownAlternative;std::ostringstream n;n<<"caller-complete aggregate over "<<p.contextRecordIds.size()<<" rooted context record(s)";if(p.contextOverflow)n<<"; at least one value/context widened to explicit unknown";if(!p.callerComplete)n<<"; caller inventory incomplete due context/guard overflow";p.note=n.str();out.addressProofs.push_back(p);}
        // memory-alias analysis writer side channel: same converged states, separate records/IDs.
        for(const auto&kv:writerAccessContexts){RootContextAddressProofRecord p;p.id=out.writerAddressProofs.size();p.pc=kv.first.pc;p.operand=kv.first.operand;p.direction=kv.first.direction;std::vector<AddressLatticeValue>domains;for(auto id:kv.second){const auto&r=out.writerContextRecords[id];p.contextRecordIds.insert(id);p.callSites.insert(r.callSites.begin(),r.callSites.end());p.proofPCs.insert(r.proofPCs.begin(),r.proofPCs.end());p.contextOverflow=p.contextOverflow||r.contextWidened;domains.push_back(r.address);}p.aggregateAddress=RootContextAnalysis::mergeCallerDomains(domains,maxValues);p.callerComplete=out.callerInventoryComplete&&!out.contextOverflowPCs.count(p.pc);p.domainClass=RootContextAnalysis::classifyDomain(p.aggregateAddress,rom.size());p.finiteRomOnly=p.domainClass==RootContextDomainClass::FiniteRom;p.finiteNonRomOnly=p.domainClass==RootContextDomainClass::FiniteNonRom;p.mixedRomNonRom=p.domainClass==RootContextDomainClass::Mixed;p.exactSingleton=p.finiteRomOnly&&p.aggregateAddress.values.size()==1&&!p.aggregateAddress.hasUnknownAlternative;p.accepted=p.callerComplete&&(p.domainClass==RootContextDomainClass::FiniteRom||p.domainClass==RootContextDomainClass::FiniteNonRom||p.domainClass==RootContextDomainClass::Mixed)&&!p.aggregateAddress.hasUnknownAlternative;std::ostringstream n;n<<"memory-alias analysis writer aggregate over "<<p.contextRecordIds.size()<<" rooted context record(s)";if(p.contextOverflow)n<<"; at least one value/context widened to explicit unknown";if(!p.callerComplete)n<<"; caller inventory incomplete due context/guard overflow";p.note=n.str();out.writerAddressProofs.push_back(std::move(p));}
        // Add caller-independent, source-pattern-validated invariants only after
        // the generic context inventory is complete, so each proof can attach
        // every enumerated caller/context as provenance.
        addSourceInvariantProofs();
        std::map<std::uint16_t,const RootContextAddressProofRecord*> byPC;for(const auto&p:out.addressProofs){auto i=byPC.find(p.pc);if(i==byPC.end()||(p.accepted&&!i->second->accepted))byPC[p.pc]=&p;}
        for(auto pc:out.inheritedBlockerPCs){auto i=byPC.find(pc);if(i!=byPC.end()&&i->second->accepted){out.refinedInheritedBlockerPCs.insert(pc);}else out.remainingInheritedBlockerPCs.insert(pc);}
        for(auto pc:out.newlyRootedBlockerPCs){auto i=byPC.find(pc);if(i!=byPC.end()&&i->second->accepted){out.refinedNewlyRootedBlockerPCs.insert(pc);}else out.remainingNewlyRootedBlockerPCs.insert(pc);}
        // A target blocker with no access record is necessarily unresolved, never silently absent.
        out.callerInventoryComplete=out.callerInventoryComplete&&out.guardTrips==0;
    }
};

AddressLatticeValue mergeDomainsInternal(const std::vector<AddressLatticeValue>&domains,std::size_t cap){
    AddressLatticeValue out;out.kind=AddressValueKind::Unknown;out.staticProof=true;bool first=true;std::set<std::uint16_t> values;bool unknown=false,widened=false;for(const auto&d:domains){unknown=unknown||d.kind==AddressValueKind::Unknown||d.hasUnknownAlternative||d.dynamicOnly||!d.staticProof;out.provenancePCs.insert(d.provenancePCs.begin(),d.provenancePCs.end());if(d.kind==AddressValueKind::Exact||d.kind==AddressValueKind::FiniteSet||d.kind==AddressValueKind::AmbiguousAlternatives){values.insert(d.values.begin(),d.values.end());}else if(d.kind==AddressValueKind::ContiguousRange||d.kind==AddressValueKind::StridedRange){const std::uint32_t stride=d.kind==AddressValueKind::StridedRange?(d.stride?d.stride:1):1;for(std::uint32_t a=d.rangeStart;a<=d.rangeEnd;a+=stride){values.insert(static_cast<std::uint16_t>(a));if(values.size()>cap){widened=true;break;}if(a+stride>a&&a+stride>d.rangeEnd)break;}}if(values.size()>cap){widened=true;break;}first=false;}
    (void)first;if(widened){out.values.clear();out.kind=AddressValueKind::Unknown;out.hasUnknownAlternative=true;out.note="context-sensitive root analysis caller union exceeded finite-value cap; widened to explicit unknown rather than dropping alternatives";return out;}out.values=values;out.hasUnknownAlternative=unknown;if(values.empty()){out.kind=AddressValueKind::Unknown;out.hasUnknownAlternative=true;}else out=IndirectAddressAnalysis::classifyKnownValues(out);out.note=unknown?"one or more caller contexts retains an unknown alternative":"complete finite union of caller-specific address domains";return out;
}

} // namespace

RootContextAnalysisResult RootContextAnalysis::analyze(const Analyzer& analyzer,const std::vector<SystemRootReachabilityRecord>& rootedReachability,const std::vector<SystemRootInlineDataRecord>& inlineData,const std::vector<SystemRootNegativeReferenceRecord>& systemRootNegativeEvidence,std::size_t maxValues,std::size_t maxContextsPerPC,std::size_t maxCallDepth){Engine e(analyzer,rootedReachability,inlineData,systemRootNegativeEvidence,maxValues,maxContextsPerPC,maxCallDepth);e.run();e.finalize();return e.out;}

RootContextAnalysisResult RootContextAnalysis::analyzeWrites(const Analyzer& analyzer,const std::vector<SystemRootReachabilityRecord>& rootedReachability,const std::vector<SystemRootInlineDataRecord>& inlineData,const std::vector<SystemRootNegativeReferenceRecord>& systemRootNegativeEvidence,std::size_t maxValues,std::size_t maxContextsPerPC,std::size_t maxCallDepth){auto r=analyze(analyzer,rootedReachability,inlineData,systemRootNegativeEvidence,maxValues,maxContextsPerPC,maxCallDepth);r.contextRecords=r.writerContextRecords;r.addressProofs=r.writerAddressProofs;return r;}

AddressLatticeValue RootContextAnalysis::mergeCallerDomains(const std::vector<AddressLatticeValue>& domains,std::size_t maxValues){return mergeDomainsInternal(domains,maxValues);}

RootContextDomainClass RootContextAnalysis::classifyDomain(const AddressLatticeValue&v,std::size_t romSize){if(v.kind==AddressValueKind::Unknown||v.hasUnknownAlternative||v.dynamicOnly||!v.staticProof)return RootContextDomainClass::Unresolved;std::set<std::uint16_t> vals;if(!completeFiniteDomain(v,vals,65536))return RootContextDomainClass::Unresolved;bool rom=false,non=false;for(auto a:vals){if(static_cast<std::size_t>(a)<romSize)rom=true;else non=true;}if(rom&&non)return RootContextDomainClass::Mixed;if(rom)return RootContextDomainClass::FiniteRom;if(non)return RootContextDomainClass::FiniteNonRom;return RootContextDomainClass::Unresolved;}

bool RootContextAnalysis::completeFiniteDomain(const AddressLatticeValue&v,std::set<std::uint16_t>&out,std::size_t cap){out.clear();if(v.kind==AddressValueKind::Unknown||v.hasUnknownAlternative||v.dynamicOnly||!v.staticProof||v.wraparound)return false;if(v.kind==AddressValueKind::Exact||v.kind==AddressValueKind::FiniteSet||v.kind==AddressValueKind::AmbiguousAlternatives){out=v.values;return !out.empty()&&out.size()<=cap;}if(v.kind==AddressValueKind::ContiguousRange||v.kind==AddressValueKind::StridedRange){const std::uint32_t stride=v.kind==AddressValueKind::StridedRange?(v.stride?v.stride:1):1;if(v.rangeStart>v.rangeEnd)return false;for(std::uint32_t a=v.rangeStart;a<=v.rangeEnd;a+=stride){out.insert(static_cast<std::uint16_t>(a));if(out.size()>cap)return false;if(a+stride>a&&a+stride>v.rangeEnd)break;}return !out.empty();}return false;}

bool RootContextAnalysis::supportsUnused(const RootContextNegativeReferenceRecord&r,bool leftBoundaryProven,bool rightBoundaryProven){return r.callerInventoryComplete&&r.exhaustiveModeledStaticAbsence&&leftBoundaryProven&&rightBoundaryProven&&!r.inheritedPositiveReference&&r.remainingInheritedBlockerPCs.empty()&&r.remainingNewlyRootedBlockerPCs.empty()&&r.finitePositiveHitPCs.empty()&&r.dynamicReadEvents==0;}
std::string RootContextAnalysis::domainClassText(RootContextDomainClass k){switch(k){case RootContextDomainClass::FiniteRom:return"finite-rom";case RootContextDomainClass::FiniteNonRom:return"finite-nonrom";case RootContextDomainClass::Mixed:return"mixed";case RootContextDomainClass::Unresolved:return"unresolved";}return"unresolved";}

} // namespace pacripper
