#pragma once
// Created by Jacob Hodgkins

#include "../disasm/Z80Disassembler.h"

#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace pacripper {

enum class StackValueKind { Unknown, ReturnAddress, Constant16, RegisterPair };

struct StackValue {
    StackValueKind kind = StackValueKind::Unknown;
    std::uint16_t value = 0;
    std::string registerPair;
    std::uint16_t sourceAddress = 0;
    bool operator==(const StackValue& other) const { return kind==other.kind&&value==other.value&&registerPair==other.registerPair&&sourceAddress==other.sourceAddress; }
    bool operator!=(const StackValue& other) const { return !(*this==other); }
};

struct StackState {
    bool depthKnown = true;
    int relativeDepth = 0; // SP displacement in bytes from function entry; PUSH makes this -2.
    bool spKnown = false;
    std::uint16_t sp = 0;
    std::vector<StackValue> values;
};

struct CallSiteRecord {
    std::uint16_t callerFunction = 0;
    std::uint16_t callAddress = 0;
    std::uint16_t calleeFunction = 0;
    std::uint16_t continuation = 0;
};

struct ObservedReturnRecord {
    int calleeFunction = -1;
    std::uint16_t returnAddress = 0;
    std::uint16_t destination = 0;
    std::size_t count = 0;
};

struct ReturnEvidenceMatch {
    ObservedReturnRecord observed;
    std::set<std::uint16_t> matchingCallSites;
    bool matchesKnownContinuation = false;
};

class StackModel {
public:
    static StackState initialState();
    static void applyInstruction(const Instruction& in,StackState& state,int callContinuation=-1);
    static bool merge(StackState& destination,const StackState& source,bool initialized);
    static std::string stateText(const StackState& state);
    static std::vector<ReturnEvidenceMatch> matchReturns(const std::vector<CallSiteRecord>& calls,
                                                         const std::vector<ObservedReturnRecord>& returns);
};

} // namespace pacripper
