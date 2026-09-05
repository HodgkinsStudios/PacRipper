#pragma once
// Created by Jacob Hodgkins

#include "../disasm/Z80Disassembler.h"

#include <cstdint>
#include <string>
#include <set>

namespace pacripper {

enum TrackedFlagMask : unsigned {
    FlagNone = 0,
    FlagZ = 1u << 0,
    FlagC = 1u << 1,
    FlagS = 1u << 2,
    FlagPV = 1u << 3,
    FlagAll = FlagZ | FlagC | FlagS | FlagPV
};

struct FlagEffect {
    unsigned defined = FlagNone;
    unsigned unknown = FlagNone;
};

class ConditionSemantics {
public:
    static unsigned flagMaskForCondition(const std::string& rawCondition);
    static std::string inverseCondition(const std::string& rawCondition);
    static FlagEffect flagEffect(const Instruction& in);
    static std::set<std::string> writtenRegisters(const Instruction& in);
    static bool writesMemory(const Instruction& in);
    static std::set<std::string> expressionDependencies(const std::string& rawCondition,
                                                        const Instruction& producer);

    // Returns an exact, source-level expression only when the relationship between
    // the producer instruction and the tested Z80 flag is unambiguous. Empty means
    // "keep the raw flag condition".
    static std::string expressionFor(const std::string& rawCondition,
                                     const Instruction& producer);
};

} // namespace pacripper
