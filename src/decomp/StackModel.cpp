// Created by Jacob Hodgkins
#include "StackModel.h"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace pacripper {
namespace {
std::string hex16(std::uint16_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(4)<<std::setfill('0')<<(unsigned)v;return o.str();}
std::string trim(std::string s){while(!s.empty()&&s.front()==' ')s.erase(s.begin());while(!s.empty()&&s.back()==' ')s.pop_back();return s;}
void invalidateDirectSp(StackState& s){s.depthKnown=false;s.spKnown=false;s.values.clear();}
}

StackState StackModel::initialState(){return StackState{};}

void StackModel::applyInstruction(const Instruction& in,StackState& s,int callContinuation) {
    if(in.mnemonic=="PUSH") {
        if(s.depthKnown) s.relativeDepth-=2;
        if(s.spKnown) s.sp=static_cast<std::uint16_t>(s.sp-2);
        StackValue v;v.kind=StackValueKind::RegisterPair;v.registerPair=trim(in.operands);v.sourceAddress=in.address;s.values.push_back(v);return;
    }
    if(in.mnemonic=="POP") {
        if(s.depthKnown) s.relativeDepth+=2;
        if(s.spKnown) s.sp=static_cast<std::uint16_t>(s.sp+2);
        if(!s.values.empty()) s.values.pop_back();
        return;
    }
    if(in.bytes.size()>=3&&in.bytes[0]==0x31) {
        s.spKnown=true;s.sp=static_cast<std::uint16_t>(in.bytes[1]|(in.bytes[2]<<8));s.depthKnown=false;s.values.clear();return;
    }
    if(in.bytes.size()>=2&&in.bytes[0]==0xED&&in.bytes[1]==0x7B) {invalidateDirectSp(s);return;}
    if(in.bytes.size()>=1&&in.bytes[0]==0xF9) {invalidateDirectSp(s);return;}
    if(in.bytes.size()>=2&&(in.bytes[0]==0xDD||in.bytes[0]==0xFD)&&in.bytes[1]==0xF9) {invalidateDirectSp(s);return;}
    if(in.bytes.size()>=1&&(in.bytes[0]==0x33||in.bytes[0]==0x3B)) {
        const int delta=in.bytes[0]==0x33?1:-1;if(s.depthKnown)s.relativeDepth+=delta;if(s.spKnown)s.sp=static_cast<std::uint16_t>(s.sp+delta);return;
    }
    if(in.flow==FlowKind::Call||in.flow==FlowKind::Restart) {
        // An unconditional CALL/RST definitely pushes a return address. A conditional
        // CALL has both pushed and unpushed outcomes at the instruction boundary, so its
        // exact stack state becomes unknown rather than pretending the call was taken.
        if(in.flow==FlowKind::Call&&in.conditional){s.depthKnown=false;s.spKnown=false;s.values.clear();return;}
        // The caller-continuation transfer is handled separately by Decompiler because
        // the callee's net SP effect is not assumed.
        if(s.depthKnown)s.relativeDepth-=2;
        if(s.spKnown)s.sp=static_cast<std::uint16_t>(s.sp-2);
        StackValue v;v.kind=StackValueKind::ReturnAddress;
        v.value=callContinuation>=0?static_cast<std::uint16_t>(callContinuation):static_cast<std::uint16_t>(in.address+in.length());
        v.sourceAddress=in.address;s.values.push_back(v);return;
    }
    if(in.flow==FlowKind::Return) {
        // For a conditional RET the structural successor is specifically the not-taken
        // path, so no pop may be propagated there. An unconditional RET has no successor
        // but its terminal stack effect is still useful in the block report.
        if(in.conditional)return;
        if(s.depthKnown)s.relativeDepth+=2;
        if(s.spKnown)s.sp=static_cast<std::uint16_t>(s.sp+2);
        if(!s.values.empty())s.values.pop_back();
        return;
    }
}

bool StackModel::merge(StackState& dst,const StackState& src,bool initialized) {
    if(!initialized){dst=src;return true;}bool changed=false;
    const bool depthKnown=dst.depthKnown&&src.depthKnown&&dst.relativeDepth==src.relativeDepth;
    if(dst.depthKnown!=depthKnown){dst.depthKnown=depthKnown;changed=true;}
    if(depthKnown&&dst.relativeDepth!=src.relativeDepth){dst.relativeDepth=src.relativeDepth;changed=true;}
    const bool spKnown=dst.spKnown&&src.spKnown&&dst.sp==src.sp;
    if(dst.spKnown!=spKnown){dst.spKnown=spKnown;changed=true;}
    if(!spKnown&&dst.sp!=0){dst.sp=0;changed=true;}
    if(dst.values!=src.values&&!dst.values.empty()){
        // Once two incoming paths disagree, retain an explicit unknown/empty tracked-value set.
        // Do not report a change again when the destination is already conservatively unknown.
        dst.values.clear();changed=true;
    }
    return changed;
}

std::string StackModel::stateText(const StackState& s) {
    std::ostringstream o;
    if(s.depthKnown)o<<"depth="<<(s.relativeDepth>=0?"+":"")<<s.relativeDepth;else o<<"depth=?";
    o<<"  SP="<<(s.spKnown?("$"+hex16(s.sp)):"?");
    if(!s.values.empty()){o<<"  tracked-top=";const auto&v=s.values.back();if(v.kind==StackValueKind::RegisterPair)o<<v.registerPair;else if(v.kind==StackValueKind::ReturnAddress)o<<"ret:$"<<hex16(v.value);else if(v.kind==StackValueKind::Constant16)o<<"$"<<hex16(v.value);else o<<"?";}
    return o.str();
}

std::vector<ReturnEvidenceMatch> StackModel::matchReturns(const std::vector<CallSiteRecord>& calls,
                                                          const std::vector<ObservedReturnRecord>& returns) {
    std::vector<ReturnEvidenceMatch> out;
    for(const auto& observed:returns) {
        ReturnEvidenceMatch m;m.observed=observed;
        if(observed.calleeFunction>=0) for(const auto& call:calls) {
            if(call.calleeFunction==static_cast<std::uint16_t>(observed.calleeFunction)&&call.continuation==observed.destination)m.matchingCallSites.insert(call.callAddress);
        }
        m.matchesKnownContinuation=!m.matchingCallSites.empty();out.push_back(m);
    }
    return out;
}

} // namespace pacripper
