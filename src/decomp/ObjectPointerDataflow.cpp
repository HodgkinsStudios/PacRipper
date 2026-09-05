// PacRipper object/pointer dataflow object + interprocedural pointer/dataflow layer
// Created by Jacob Hodgkins

#include "Decompiler.h"

#include <algorithm>
#include <cstdlib>
#include <iomanip>
#include <queue>
#include <sstream>

namespace pacripper {
namespace {
std::string h16(std::uint16_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(4)<<std::setfill('0')<<(unsigned)v;return o.str();}

std::vector<std::string> splitOps8(const std::string& text){
    std::vector<std::string> out;std::string cur;int depth=0;
    for(char c:text){if(c=='(')++depth;if(c==')')--depth;if(c==','&&depth==0){while(!cur.empty()&&cur.front()==' ')cur.erase(cur.begin());while(!cur.empty()&&cur.back()==' ')cur.pop_back();out.push_back(cur);cur.clear();}else cur+=c;}
    while(!cur.empty()&&cur.front()==' ') cur.erase(cur.begin());
    while(!cur.empty()&&cur.back()==' ') cur.pop_back();
    if(!cur.empty()) out.push_back(cur);
    return out;
}

bool physicalRam8(std::uint16_t a){return (a>=0x4000&&a<=0x47FF)||(a>=0x4C00&&a<=0x4FFF);}

std::set<std::string> pairAliases8(const std::string& pair){
    if(pair=="BC")return {"BC","B","C"};
    if(pair=="DE")return {"DE","D","E"};
    if(pair=="HL")return {"HL","H","L"};
    if(pair=="AF")return {"A"};
    if(pair=="IX")return {"IX"};
    if(pair=="IY")return {"IY"};
    return {pair};
}

bool setIntersects8(const std::set<std::string>& a,const std::set<std::string>& b){for(const auto& x:a)if(b.count(x))return true;return false;}

bool decodeDirectRamPair8(const Instruction& in,std::uint16_t& address,std::string& reg,bool& read,bool& write){
    const auto& b=in.bytes;read=write=false;
    if(b.size()>=3&&(b[0]==0x2A||b[0]==0x22)){
        address=static_cast<std::uint16_t>(b[1]|(static_cast<std::uint16_t>(b[2])<<8));reg="HL";read=b[0]==0x2A;write=!read;return true;
    }
    if(b.size()>=4&&b[0]==0xED&&(b[1]==0x4B||b[1]==0x5B||b[1]==0x6B||b[1]==0x7B||b[1]==0x43||b[1]==0x53||b[1]==0x63||b[1]==0x73)){
        address=static_cast<std::uint16_t>(b[2]|(static_cast<std::uint16_t>(b[3])<<8));const auto op=b[1];
        reg=(op==0x4B||op==0x43)?"BC":(op==0x5B||op==0x53)?"DE":(op==0x6B||op==0x63)?"HL":"SP";
        read=(op&0x08)!=0;write=!read;return true;
    }
    if(b.size()>=4&&(b[0]==0xDD||b[0]==0xFD)&&(b[1]==0x2A||b[1]==0x22)){
        address=static_cast<std::uint16_t>(b[2]|(static_cast<std::uint16_t>(b[3])<<8));reg=b[0]==0xDD?"IX":"IY";read=b[1]==0x2A;write=!read;return true;
    }
    return false;
}

bool parseIndexed8(const std::string& op,std::string& reg,int& disp){
    if(op.size()<4||op.front()!='('||op.back()!=')')return false;
    if(op=="(HL)"||op=="(DE)"||op=="(BC)"){reg=op.substr(1,2);disp=0;return true;}
    if(op.rfind("(IX",0)!=0&&op.rfind("(IY",0)!=0)return false;
    reg=op.substr(1,2);disp=0;const std::string inner=op.substr(3,op.size()-4);if(inner.empty())return true;
    char* end=nullptr;long v=std::strtol(inner.c_str(),&end,10);if(end&&*end=='\0'){disp=static_cast<int>(v);return true;}return false;
}

std::vector<std::string> memoryReadOperands8(const Instruction& in){
    std::vector<std::string> reads;const auto ops=splitOps8(in.operands);
    if(in.mnemonic=="LD") {if(ops.size()>=2&&ops[1].find('(')!=std::string::npos)reads.push_back(ops[1]);}
    else if(in.mnemonic=="INC"||in.mnemonic=="DEC"||in.mnemonic=="BIT"||in.mnemonic=="RES"||in.mnemonic=="SET"||in.mnemonic=="RLC"||in.mnemonic=="RRC"||in.mnemonic=="RL"||in.mnemonic=="RR"||in.mnemonic=="SLA"||in.mnemonic=="SRA"||in.mnemonic=="SLL"||in.mnemonic=="SRL") {if(!ops.empty()&&ops.back().find('(')!=std::string::npos)reads.push_back(ops.back());}
    else if(in.mnemonic=="ADD"||in.mnemonic=="ADC"||in.mnemonic=="SUB"||in.mnemonic=="SBC"||in.mnemonic=="AND"||in.mnemonic=="XOR"||in.mnemonic=="OR"||in.mnemonic=="CP") {for(const auto& op:ops)if(op.find('(')!=std::string::npos)reads.push_back(op);}
    return reads;
}

bool isPair8(const std::string& r){return r=="BC"||r=="DE"||r=="HL"||r=="IX"||r=="IY";}
}

void Decompiler::buildFunctionRegisterSummaries(){
    functionRegisterSummaries_.clear();
    static const std::set<std::string> tracked={"A","B","C","D","E","H","L","BC","DE","HL","IX","IY"};
    static const std::vector<std::string> savePairs={"AF","BC","DE","HL","IX","IY"};

    for(const auto& fk:functions_){
        FunctionRegisterSummary s;s.functionEntry=fk.first;
        std::map<std::string,std::uint16_t> entrySave;
        auto eb=blocks_.find(fk.first);
        if(eb!=blocks_.end()){
            std::map<std::string,bool> dirty;for(const auto& p:savePairs)dirty[p]=false;
            for(auto ia:eb->second.instructions){const auto& in=analyzer_->instructions().at(ia);const auto ops=splitOps8(in.operands);
                if(in.mnemonic=="PUSH"&&!ops.empty()&&!dirty[ops[0]]&&!entrySave.count(ops[0]))entrySave[ops[0]]=in.address;
                const auto writes=ConditionSemantics::writtenRegisters(in);
                for(const auto& p:savePairs)if(setIntersects8(writes,pairAliases8(p)))dirty[p]=true;
                if(in.flow==FlowKind::Call||in.flow==FlowKind::Restart)break;
            }
        }

        bool anyReturn=false;bool allReturnDepthKnown=true;std::map<std::string,bool> restoredAll;for(const auto& p:savePairs)restoredAll[p]=entrySave.count(p)>0;
        for(auto ba:fk.second.blocks){
            const auto bi=blocks_.find(ba);if(bi==blocks_.end())continue;
            for(const auto& e:bi->second.outgoing){
                if((e.kind==CfgEdgeKind::BranchTaken||e.kind==CfgEdgeKind::BranchNotTaken||e.kind==CfgEdgeKind::Fallthrough)&&e.to>=0&&!fk.second.blocks.count(static_cast<std::uint16_t>(e.to)))s.hasNonReturnExit=true;
                if(e.kind==CfgEdgeKind::Indirect||e.kind==CfgEdgeKind::DynamicIndirect)s.hasNonReturnExit=true;
            }
            for(auto ia:bi->second.instructions){const auto& in=analyzer_->instructions().at(ia);
                if(in.flow==FlowKind::Call||in.flow==FlowKind::Restart){
                    if(in.target>=0&&functions_.count(static_cast<std::uint16_t>(in.target)))s.directCallees.insert(static_cast<std::uint16_t>(in.target));
                    else s.hasUnknownCallEffects=true;
                }else{
                    const auto writes=ConditionSemantics::writtenRegisters(in);for(const auto& r:writes)if(tracked.count(r))s.localMayWrite.insert(r);
                }
                for(const auto& mr:in.memoryRefs)if((mr.access==RefAccess::Write||mr.access==RefAccess::ReadWrite)&&physicalRam8(mr.address))s.directRamMayWrite.insert(mr.address);
                if(ConditionSemantics::writesMemory(in)){
                    bool directKnown=false;for(const auto& mr:in.memoryRefs)if(mr.access==RefAccess::Write||mr.access==RefAccess::ReadWrite)directKnown=true;
                    if(!directKnown&&in.mnemonic!="CALL"&&in.mnemonic!="RST")s.hasUnknownMemoryWrite=true;
                }
            }

            // Stack-balance and saved-register restoration are checked at each concrete RET
            // using the already conservative structured-control analysis stack-entry state. A restoration is
            // accepted only when the POP consumes the exact entry PUSH token in the same
            // return block and no later write/call can clobber it.
            const auto sb=stackBlocks_.find(ba);
            StackState stack;bool stackAvailable=sb!=stackBlocks_.end()&&sb->second.entryInitialized;if(stackAvailable)stack=sb->second.entryState;
            std::map<std::string,bool> restoredHere;for(const auto& p:savePairs)restoredHere[p]=false;
            for(auto ia:bi->second.instructions){const auto& in=analyzer_->instructions().at(ia);const auto ops=splitOps8(in.operands);
                bool matchingPop=false;std::string popPair;
                if(stackAvailable&&in.mnemonic=="POP"&&!ops.empty()&&!stack.values.empty()){
                    popPair=ops[0];const auto& top=stack.values.back();auto es=entrySave.find(popPair);
                    matchingPop=es!=entrySave.end()&&top.kind==StackValueKind::RegisterPair&&top.registerPair==popPair&&top.sourceAddress==es->second;
                }
                const auto writes=ConditionSemantics::writtenRegisters(in);
                for(const auto& p:savePairs){if(setIntersects8(writes,pairAliases8(p)))restoredHere[p]=false;}
                if(in.flow==FlowKind::Call||in.flow==FlowKind::Restart)for(const auto& p:savePairs)restoredHere[p]=false;
                if(stackAvailable)StackModel::applyInstruction(in,stack);
                if(matchingPop)restoredHere[popPair]=true;
                if(in.flow==FlowKind::Return){
                    anyReturn=true;
                    // State was inspected before RET above. RET itself changes the conceptual
                    // depth, so use the block-entry replay by reconstructing depth manually:
                    StackState before=sb!=stackBlocks_.end()&&sb->second.entryInitialized?sb->second.entryState:StackState{};bool have=sb!=stackBlocks_.end()&&sb->second.entryInitialized;
                    if(have){for(auto ja:bi->second.instructions){if(ja==ia)break;StackModel::applyInstruction(analyzer_->instructions().at(ja),before);}if(!before.depthKnown||before.relativeDepth!=0)allReturnDepthKnown=false;}else allReturnDepthKnown=false;
                    for(const auto& p:savePairs)restoredAll[p]=restoredAll[p]&&restoredHere[p];
                }
            }
        }
        s.stackBalanced=anyReturn&&allReturnDepthKnown&&!s.hasNonReturnExit;
        if(anyReturn&&!s.hasNonReturnExit)for(const auto& p:savePairs)if(restoredAll[p]){
            const auto aliases=pairAliases8(p);for(const auto& a:aliases)if(tracked.count(a))s.stackRestored.insert(a);
        }
        s.transitiveMayWrite=s.localMayWrite;s.transitiveRamMayWrite=s.directRamMayWrite;s.transitiveUnknownMemoryWrite=s.hasUnknownMemoryWrite;
        functionRegisterSummaries_[fk.first]=s;
    }

    // Fixed point over the recovered direct call/RST graph. This is a machine-effect
    // summary, not a calling convention: every callee's actual recovered instructions
    // contribute to the caller's may-write set.
    bool changed=true;std::size_t guard=0;
    while(changed&&guard++<1000){changed=false;for(auto& kv:functionRegisterSummaries_){auto& s=kv.second;std::set<std::string> w=s.localMayWrite;std::set<std::uint16_t> rw=s.directRamMayWrite;bool unknown=s.hasUnknownMemoryWrite;
            if(s.hasUnknownCallEffects)w.insert(tracked.begin(),tracked.end());
            for(auto c:s.directCallees){auto ci=functionRegisterSummaries_.find(c);if(ci==functionRegisterSummaries_.end()){w.insert(tracked.begin(),tracked.end());unknown=true;continue;}w.insert(ci->second.transitiveMayWrite.begin(),ci->second.transitiveMayWrite.end());rw.insert(ci->second.transitiveRamMayWrite.begin(),ci->second.transitiveRamMayWrite.end());unknown=unknown||ci->second.transitiveUnknownMemoryWrite;}
            // If every return path restores an entry-saved register after all internal
            // clobbers, its externally visible value is preserved despite local writes.
            for(const auto& r:s.stackRestored)w.erase(r);
            if(w!=s.transitiveMayWrite){s.transitiveMayWrite=w;changed=true;}if(rw!=s.transitiveRamMayWrite){s.transitiveRamMayWrite=rw;changed=true;}if(unknown!=s.transitiveUnknownMemoryWrite){s.transitiveUnknownMemoryWrite=unknown;changed=true;}
        }}

    for(auto& kv:functionRegisterSummaries_){auto& s=kv.second;s.preserved.clear();for(const auto& r:tracked)if(!s.transitiveMayWrite.count(r))s.preserved.insert(r);}
}

void Decompiler::buildInterproceduralPointerClosure(){
    if(!analyzer_||romClosureBytes_.empty()) return;
    const auto& program=analyzer_->program();
    const std::vector<std::string> pairs={"BC","DE","HL","IX","IY"};
    struct Fact{bool known=false;std::set<std::uint16_t> values;bool fromRam=false,fromStack=false,acrossCall=false;};
    struct State{std::map<std::string,Fact> regs;std::map<std::uint16_t,Fact> ram;bool stackKnown=true;std::vector<Fact> stack;};
    auto unknown=[](){return Fact{};};
    auto exact=[&](std::uint16_t v){Fact f;if(v<program.size()){f.known=true;f.values.insert(v);}return f;};
    auto get=[&](const State& s,const std::string& r){auto i=s.regs.find(r);return i==s.regs.end()?unknown():i->second;};
    auto put=[&](State& s,const std::string& r,const Fact& f){s.regs[r]=f;};
    auto invalidate=[&](State& s,const std::string& r){s.regs[r]=unknown();};
    auto sameFact=[](const Fact&a,const Fact&b){return a.known==b.known&&a.values==b.values&&a.fromRam==b.fromRam&&a.fromStack==b.fromStack&&a.acrossCall==b.acrossCall;};
    auto mergeFact=[&](Fact& dst,const Fact& src)->bool{
        Fact old=dst;if(!dst.known||!src.known){dst=unknown();return !sameFact(old,dst);}std::set<std::uint16_t> u=dst.values;u.insert(src.values.begin(),src.values.end());if(u.size()>16){dst=unknown();return !sameFact(old,dst);}dst.values=u;dst.fromRam=dst.fromRam||src.fromRam;dst.fromStack=dst.fromStack||src.fromStack;dst.acrossCall=dst.acrossCall||src.acrossCall;return !sameFact(old,dst);
    };
    auto mergeState=[&](State& dst,const State& src,bool initialized)->bool{
        if(!initialized){dst=src;return true;}bool changed=false;
        for(const auto& p:pairs){Fact d=get(dst,p),q=get(src,p);if(mergeFact(d,q)){dst.regs[p]=d;changed=true;}}
        for(auto it=dst.ram.begin();it!=dst.ram.end();){auto si=src.ram.find(it->first);if(si==src.ram.end()){it=dst.ram.erase(it);changed=true;continue;}Fact f=it->second;if(mergeFact(f,si->second)){it->second=f;changed=true;}++it;}
        if(dst.stackKnown&&src.stackKnown&&dst.stack.size()==src.stack.size()){for(std::size_t i=0;i<dst.stack.size();++i)if(mergeFact(dst.stack[i],src.stack[i]))changed=true;}
        else if(dst.stackKnown){dst.stackKnown=false;dst.stack.clear();changed=true;}
        return changed;
    };

    auto pairFromImmediate=[&](const Instruction& in,std::string& reg,std::uint16_t& value)->bool{const auto& b=in.bytes;
        if(b.size()>=3&&(b[0]==0x01||b[0]==0x11||b[0]==0x21)){reg=b[0]==0x01?"BC":b[0]==0x11?"DE":"HL";value=static_cast<std::uint16_t>(b[1]|(static_cast<std::uint16_t>(b[2])<<8));return true;}
        if(b.size()>=4&&(b[0]==0xDD||b[0]==0xFD)&&b[1]==0x21){reg=b[0]==0xDD?"IX":"IY";value=static_cast<std::uint16_t>(b[2]|(static_cast<std::uint16_t>(b[3])<<8));return true;}return false;};

    auto shifted=[&](const Fact& f,int delta){Fact o=f;if(!o.known)return o;std::set<std::uint16_t> v;for(auto x:o.values){const int n=static_cast<int>(x)+delta;if(n<0||static_cast<std::size_t>(n)>=program.size())return unknown();v.insert(static_cast<std::uint16_t>(n));}o.values=v;return o;};
    auto summed=[&](const Fact&a,const Fact&b){Fact o;if(!a.known||!b.known)return o;for(auto x:a.values)for(auto y:b.values){const std::uint32_t z=static_cast<std::uint32_t>(x)+y;if(z>=program.size())return unknown();o.values.insert(static_cast<std::uint16_t>(z));if(o.values.size()>16)return unknown();}o.known=!o.values.empty();o.fromRam=a.fromRam||b.fromRam;o.fromStack=a.fromStack||b.fromStack;o.acrossCall=a.acrossCall||b.acrossCall;return o;};

    std::size_t newlyAdded=0,ramAdded=0,stackAdded=0;
    auto addRead=[&](std::uint16_t pc,const std::string& reg,int disp,const Fact& f){if(!f.known||f.values.empty())return;
        std::set<std::uint16_t> addresses;for(auto v:f.values){const int a=static_cast<int>(v)+disp;if(a<0||static_cast<std::size_t>(a)>=program.size())return;addresses.insert(static_cast<std::uint16_t>(a));}
        if(addresses.empty()) return;
        const auto lo=*addresses.begin(),hi=*addresses.rbegin();
        RomConsumerRecord r;r.pc=pc;r.start=lo;r.end=static_cast<std::uint16_t>(hi+1);r.pointerRegister=reg;r.exact=addresses.size()==1;r.bounded=addresses.size()>1;
        if(f.fromRam)r.kind=RomConsumerKind::RamPointerReloadRead;else if(f.fromStack)r.kind=RomConsumerKind::StackPointerRestoreRead;else r.kind=RomConsumerKind::PreservedCalleeRead;
        std::ostringstream n;n<<"object/pointer dataflow finite ROM pointer provenance through ";if(f.fromRam)n<<"direct 16-bit RAM store/reload";else if(f.fromStack)n<<"PUSH/POP stack restoration";else if(f.acrossCall)n<<"proven callee register preservation";else n<<"interprocedural static dataflow";if(addresses.size()>1)n<<"; finite set of "<<addresses.size()<<" possible addresses represented as conservative bound";r.note=n.str();
        for(const auto& e:romConsumers_)if(e.pc==r.pc&&e.start==r.start&&e.end==r.end&&((e.exact&&r.exact)||(e.bounded&&r.bounded)))return;
        romConsumers_.push_back(r);for(std::size_t a=r.start;a<r.end&&a<romClosureBytes_.size();++a){auto& b=romClosureBytes_[a];b.consumerPCs.insert(r.pc);if(r.exact)b.staticExactDataUse=true;if(r.bounded)b.boundedConsumer=true;}
        ++newlyAdded;if(r.kind==RomConsumerKind::RamPointerReloadRead)++ramAdded;if(r.kind==RomConsumerKind::StackPointerRestoreRead)++stackAdded;
    };

    auto applyCallEffects=[&](State& s,std::uint16_t target){auto si=functionRegisterSummaries_.find(target);if(si==functionRegisterSummaries_.end()){for(const auto&p:pairs)invalidate(s,p);s.ram.clear();s.stackKnown=false;s.stack.clear();return;}
        const auto& sum=si->second;for(const auto& p:pairs)if(!sum.preserved.count(p))invalidate(s,p);else{auto f=get(s,p);if(f.known){f.acrossCall=true;put(s,p,f);}}
        if(sum.transitiveUnknownMemoryWrite)s.ram.clear();else for(auto a:sum.transitiveRamMayWrite)s.ram.erase(a);
        if(!sum.stackBalanced){s.stackKnown=false;s.stack.clear();}
    };

    auto transfer=[&](const Instruction& in,State& s){std::string immReg;std::uint16_t imm=0;if(pairFromImmediate(in,immReg,imm)){put(s,immReg,exact(imm));return;}
        std::uint16_t ra=0;std::string rr;bool rd=false,wr=false;if(decodeDirectRamPair8(in,ra,rr,rd,wr)&&isPair8(rr)&&physicalRam8(ra)&&ra!=0xFFFF&&physicalRam8(static_cast<std::uint16_t>(ra+1))){if(rd){auto ri=s.ram.find(ra);if(ri!=s.ram.end()){Fact f=ri->second;f.fromRam=true;put(s,rr,f);}else invalidate(s,rr);}else if(wr){auto f=get(s,rr);if(f.known)s.ram[ra]=f;else s.ram.erase(ra);}return;}
        const auto ops=splitOps8(in.operands);
        if(in.mnemonic=="PUSH"&&!ops.empty()&&isPair8(ops[0])){if(s.stackKnown){Fact f=get(s,ops[0]);s.stack.push_back(f);}return;}
        if(in.mnemonic=="POP"&&!ops.empty()&&isPair8(ops[0])){if(s.stackKnown&&!s.stack.empty()){Fact f=s.stack.back();s.stack.pop_back();if(f.known)f.fromStack=true;put(s,ops[0],f);}else invalidate(s,ops[0]);return;}
        if(in.mnemonic=="PUSH"||in.mnemonic=="POP"){if(in.mnemonic=="PUSH"&&s.stackKnown)s.stack.push_back(unknown());else if(in.mnemonic=="POP"){if(s.stackKnown&&!s.stack.empty())s.stack.pop_back();else{s.stackKnown=false;s.stack.clear();}}return;}
        const auto& b=in.bytes;
        if(!b.empty()&&b[0]==0xEB){auto de=get(s,"DE"),hl=get(s,"HL");put(s,"DE",hl);put(s,"HL",de);return;}
        if(!b.empty()&&b[0]==0xE3){if(s.stackKnown&&!s.stack.empty()){auto hl=get(s,"HL");auto top=s.stack.back();s.stack.back()=hl;if(top.known)top.fromStack=true;put(s,"HL",top);}else invalidate(s,"HL");return;}
        if(b.size()>=2&&(b[0]==0xDD||b[0]==0xFD)&&b[1]==0xE3){const std::string p=b[0]==0xDD?"IX":"IY";if(s.stackKnown&&!s.stack.empty()){auto x=get(s,p),top=s.stack.back();s.stack.back()=x;if(top.known)top.fromStack=true;put(s,p,top);}else invalidate(s,p);return;}
        if(!b.empty()&&(b[0]==0x03||b[0]==0x0B||b[0]==0x13||b[0]==0x1B||b[0]==0x23||b[0]==0x2B)){const std::string p=(b[0]==0x03||b[0]==0x0B)?"BC":(b[0]==0x13||b[0]==0x1B)?"DE":"HL";const int d=(b[0]==0x03||b[0]==0x13||b[0]==0x23)?1:-1;put(s,p,shifted(get(s,p),d));return;}
        if(b.size()>=2&&(b[0]==0xDD||b[0]==0xFD)&&(b[1]==0x23||b[1]==0x2B)){const std::string p=b[0]==0xDD?"IX":"IY";put(s,p,shifted(get(s,p),b[1]==0x23?1:-1));return;}
        if(!b.empty()&&(b[0]==0x09||b[0]==0x19||b[0]==0x29)){const std::string src=b[0]==0x09?"BC":b[0]==0x19?"DE":"HL";put(s,"HL",summed(get(s,"HL"),get(s,src)));return;}
        if(in.mnemonic=="EXX"){invalidate(s,"BC");invalidate(s,"DE");invalidate(s,"HL");return;}
        if(in.mnemonic=="LDI"||in.mnemonic=="LDIR"||in.mnemonic=="LDD"||in.mnemonic=="LDDR"){invalidate(s,"BC");invalidate(s,"DE");invalidate(s,"HL");return;}
        if(in.mnemonic=="CPI"||in.mnemonic=="CPIR"||in.mnemonic=="CPD"||in.mnemonic=="CPDR"){invalidate(s,"BC");invalidate(s,"HL");return;}
        const auto writes=ConditionSemantics::writtenRegisters(in);for(const auto& p:pairs)if(setIntersects8(writes,pairAliases8(p)))invalidate(s,p);if(writes.count("SP")){s.stackKnown=false;s.stack.clear();}
        if(ConditionSemantics::writesMemory(in)){bool directPair=false;std::uint16_t a=0;std::string q;bool r=false,w=false;directPair=decodeDirectRamPair8(in,a,q,r,w);if(!directPair){ // unknown indirect writes can alias stored pointer cells
                if(in.mnemonic!="CALL"&&in.mnemonic!="RST")s.ram.clear();
            }}
    };

    std::map<std::uint16_t,State> entry;std::map<std::uint16_t,bool> initialized;std::queue<std::uint16_t> q;
    auto seed=[&](std::uint16_t b,const State& s){bool was=initialized[b];bool changed=mergeState(entry[b],s,was);if(!was){initialized[b]=true;changed=true;}if(changed)q.push(b);};
    State empty;
    for(const auto& fk:functions_)if(fk.second.callers.empty()||fk.first==0||fk.first==8||fk.first==0x10||fk.first==0x18||fk.first==0x20||fk.first==0x28||fk.first==0x30||fk.first==0x38)if(blocks_.count(fk.first))seed(fk.first,empty);
    for(const auto& bk:blocks_)if(bk.second.incoming.empty()&&bk.second.functionOwners.empty())seed(bk.first,empty);
    if(q.empty()&&!blocks_.empty())seed(blocks_.begin()->first,empty);

    std::size_t guard=0;
    while(!q.empty()&&guard++<500000){const auto ba=q.front();q.pop();auto bi=blocks_.find(ba);if(bi==blocks_.end())continue;State s=entry[ba];
        for(auto ia:bi->second.instructions){const auto& in=analyzer_->instructions().at(ia);
            for(const auto& op:memoryReadOperands8(in)){std::string reg;int disp=0;if(parseIndexed8(op,reg,disp)&&isPair8(reg))addRead(in.address,reg,disp,get(s,reg));}
            if(in.mnemonic=="LDI"||in.mnemonic=="LDD")addRead(in.address,"HL",0,get(s,"HL"));
            if(in.flow==FlowKind::Call||in.flow==FlowKind::Restart){
                if(in.target>=0&&functions_.count(static_cast<std::uint16_t>(in.target))){State callee=s;callee.stackKnown=false;callee.stack.clear();seed(static_cast<std::uint16_t>(in.target),callee);applyCallEffects(s,static_cast<std::uint16_t>(in.target));}
                else{for(const auto&p:pairs)invalidate(s,p);s.ram.clear();s.stackKnown=false;s.stack.clear();}
            }else transfer(in,s);
        }
        for(const auto& e:bi->second.outgoing){if(e.to<0||!isStructuralEdge(e.kind))continue;seed(static_cast<std::uint16_t>(e.to),s);}
    }
    stats_.romObjects.objectPointerInterproceduralConsumers=newlyAdded;stats_.romObjects.objectPointerRamPointerReloadConsumers=ramAdded;stats_.romObjects.objectPointerStackPointerConsumers=stackAdded;
}

void Decompiler::recomputeRomClosureStats(){
    const auto oldSeeds=stats_.romClosure.immediateRomPointerSeeds,oldDerived=stats_.romClosure.derivedRomPointerTargets;
    for(auto& b:romClosureBytes_)b.primary=RomClosure::classify(b);
    RomClosureStats st;st.romBytes=romClosureBytes_.size();st.consumers=romConsumers_.size();st.immediateRomPointerSeeds=oldSeeds;st.derivedRomPointerTargets=oldDerived;st.ramPairs=ramPairEvidence_.size();
    for(const auto& r:romConsumers_){if(r.dynamic)++st.dynamicConsumers;else if(r.exact)++st.exactStaticConsumers;if(r.bounded)++st.boundedConsumers;}
    for(const auto& r:ramPairEvidence_)if(r.pointerLike)++st.pointerLikeRamPairs;
    for(const auto& b:romClosureBytes_){switch(b.primary){case RomClosurePrimary::Code:++st.codeBytes;break;case RomClosurePrimary::CodeAndDataUse:++st.codeAndDataUseBytes;break;case RomClosurePrimary::HardData:++st.hardDataBytes;break;case RomClosurePrimary::ProvenDataUse:++st.provenDataUseBytes;break;case RomClosurePrimary::BoundedConsumer:++st.boundedConsumerBytes;break;case RomClosurePrimary::Candidate:++st.candidateBytes;break;case RomClosurePrimary::PointerTarget:++st.pointerTargetBytes;break;case RomClosurePrimary::ProvenUnused:++st.provenUnusedBytes;break;case RomClosurePrimary::Unresolved:++st.unresolvedBytes;break;}if(b.code||b.hardData||b.staticExactDataUse||b.dynamicDataUse)++st.evidenceBackedExplainedBytes;if(b.code||b.hardData||b.staticExactDataUse||b.dynamicDataUse||b.boundedConsumer)++st.boundedExplainedBytes;}
    stats_.romClosure=st;
}

void Decompiler::buildObjectPointerObjects(){
    stats_.romObjects={};const std::size_t before=stats_.romClosure.unresolvedBytes;
    buildFunctionRegisterSummaries();buildInterproceduralPointerClosure();recomputeRomClosureStats();
    romObjects_=RomObjects::reconstruct(romConsumers_,analyzer_?analyzer_->program().size():0);romPointerLinks_=RomObjects::decodePointerLinks(romObjects_,analyzer_->program());
    // A decoded word in a statically reconstructed RST18 pointer-table object is itself
    // reproducible pointer-target evidence. Mark the target byte without asserting the
    // pointee's type or exclusive data status.
    for(const auto& link:romPointerLinks_)if(link.target<romClosureBytes_.size()&&!romClosureBytes_[link.target].pointerTarget){romClosureBytes_[link.target].pointerTarget=true;++stats_.romClosure.derivedRomPointerTargets;}
    recomputeRomClosureStats();unresolvedPriority_=RomObjects::prioritizeUnresolved(romClosureBytes_,romObjects_);
    auto& st=stats_.romObjects;st.objects=romObjects_.size();for(const auto&o:romObjects_){if(o.dynamicOnly)++st.dynamicObjects;else if(o.exactBoundary)++st.exactObjects;else if(o.boundedBoundary)++st.boundedObjects;switch(o.kind){case RomObjectKind::ByteLookupTable:++st.byteLookupObjects;break;case RomObjectKind::WordPointerTable:++st.wordPointerObjects;break;case RomObjectKind::SequentialStream:++st.streamObjects;break;case RomObjectKind::RecordTable:++st.recordObjects;break;default:break;}}
    st.pointerLinks=romPointerLinks_.size();for(const auto&l:romPointerLinks_){if(!l.targetObjectIds.empty())++st.pointerLinksToObjects;if(l.pointeeExtentProven)++st.pointeeExtentsProven;}
    st.functionSummaries=functionRegisterSummaries_.size();for(const auto&kv:functionRegisterSummaries_){st.provenPreservedRegisterFacts+=kv.second.preserved.size();st.stackRestoredRegisterFacts+=kv.second.stackRestored.size();}
    st.newlyExplainedBytes=before>stats_.romClosure.unresolvedBytes?before-stats_.romClosure.unresolvedBytes:0;
}

std::vector<std::string> Decompiler::romObjectLines() const{
    std::vector<std::string> o;if(!ready_){o.push_back("Decompiler model not built.");return o;}o.push_back("PacRipper object/pointer dataflow ROM objects");o.push_back("Objects are reconstructed from compatible consumer evidence; overlapping views are preserved rather than flattened.");o.push_back("Objects: "+std::to_string(stats_.romObjects.objects)+"  exact="+std::to_string(stats_.romObjects.exactObjects)+" bounded="+std::to_string(stats_.romObjects.boundedObjects)+" dynamic="+std::to_string(stats_.romObjects.dynamicObjects));o.push_back("");
    for(const auto&r:romObjects_){std::ostringstream x;x<<"obj#"<<r.id<<" $"<<h16(r.start)<<"-$"<<h16(static_cast<std::uint16_t>(r.end-1))<<" len="<<(r.end-r.start)<<"  "<<RomObjects::objectKindText(r.kind);if(r.entrySize)x<<" entry="<<r.entrySize<<" count="<<r.entryCount;x<<"  ["<<(r.dynamicOnly?"dynamic":r.exactBoundary?"exact-static":"bounded-static")<<"]";o.push_back(x.str());std::ostringstream y;y<<"  consumers=";std::size_t n=0;for(auto pc:r.consumerPCs){if(n++)y<<",";y<<"$"<<h16(pc);}if(!r.overlappingObjectIds.empty()){y<<" overlaps=";n=0;for(auto id:r.overlappingObjectIds){if(n++)y<<",";y<<"obj#"<<id;}}o.push_back(y.str());o.push_back("  "+r.note);}
    return o;
}

std::vector<std::string> Decompiler::pointerChainLines() const{
    std::vector<std::string> o;if(!ready_){o.push_back("Decompiler model not built.");return o;}o.push_back("PacRipper object/pointer dataflow pointer-table -> pointee chains");o.push_back("A pointee extent is reported only when a reconstructed consumer object proves the target boundary.");o.push_back("");for(const auto&r:romPointerLinks_){std::ostringstream x;x<<"obj#"<<r.tableObjectId<<"["<<r.tableEntryIndex<<"] @$"<<h16(r.entryAddress)<<" -> $"<<h16(r.target);if(!r.targetObjectIds.empty()){x<<" -> ";std::size_t n=0;for(auto id:r.targetObjectIds){if(n++)x<<",";x<<"obj#"<<id;}}if(r.pointeeExtentProven)x<<"  extent=$"<<h16(r.pointeeStart)<<"-$"<<h16(static_cast<std::uint16_t>(r.pointeeEnd-1));o.push_back(x.str());o.push_back("  "+r.note);}return o;
}

std::vector<std::string> Decompiler::calleeSummaryLines() const{
    std::vector<std::string> o;if(!ready_){o.push_back("Decompiler model not built.");return o;}o.push_back("PacRipper object/pointer dataflow machine-level callee register effects");o.push_back("Preservation is derived from recovered instructions/callees and entry-save restoration; it is not a compiler ABI.");o.push_back("");for(const auto&kv:functionRegisterSummaries_){const auto&s=kv.second;std::ostringstream x;x<<functionName(kv.first)<<" $"<<h16(kv.first)<<" preserved={";std::size_t n=0;for(const auto&r:s.preserved){if(n++)x<<",";x<<r;}x<<"} may-write={";n=0;for(const auto&r:s.transitiveMayWrite){if(n++)x<<",";x<<r;}x<<"} stack="<<(s.stackBalanced?"balanced":"unknown/unbalanced");o.push_back(x.str());if(!s.stackRestored.empty()){std::ostringstream q;q<<"  restored from entry PUSH/POP proof={";n=0;for(const auto&r:s.stackRestored){if(n++)q<<",";q<<r;}q<<"}";o.push_back(q.str());}if(s.hasUnknownCallEffects)o.push_back("  contains call/restart whose target effect could not be summarized");if(s.transitiveUnknownMemoryWrite)o.push_back("  may write unknown memory through stack/indirect addressing");}
    return o;
}

std::vector<std::string> Decompiler::unresolvedPriorityLines() const{
    std::vector<std::string> o;if(!ready_){o.push_back("Decompiler model not built.");return o;}o.push_back("PacRipper object/pointer dataflow unresolved-span priority view");o.push_back("Sorted primarily by unresolved length, with nearby object/pointer/consumer context retained for the next closure analysis.");o.push_back("");for(const auto&r:unresolvedPriority_){std::ostringstream x;x<<"$"<<h16(r.start)<<"-$"<<h16(static_cast<std::uint16_t>(r.end-1))<<" len="<<r.length<<" objects-near="<<r.nearbyObjectCount<<" pointer-targets-near="<<r.nearbyPointerTargetCount<<" consumer-PCs-near="<<r.nearbyConsumerCount;o.push_back(x.str());o.push_back("  "+r.reason);}return o;
}

} // namespace pacripper
