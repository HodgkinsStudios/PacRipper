#pragma once
// Created by Jacob Hodgkins

#include <cstdint>
#include <string>
#include <vector>

namespace pacripper {

enum class FlowKind {
    Normal,
    Call,
    Jump,
    RelativeJump,
    Return,
    Restart,
    Halt
};

enum class RefAccess { Read, Write, ReadWrite, Address };

struct MemoryReference {
    std::uint16_t address = 0;
    RefAccess access = RefAccess::Address;
};

struct Instruction {
    std::uint16_t address = 0;
    std::vector<std::uint8_t> bytes;
    std::string mnemonic;
    std::string operands;
    std::string comment;
    FlowKind flow = FlowKind::Normal;
    bool conditional = false;
    bool indirect = false;
    int target = -1;
    std::vector<MemoryReference> memoryRefs;

    std::size_t length() const { return bytes.empty() ? 1 : bytes.size(); }
    std::string text() const;
};

class Z80Disassembler {
public:
    Instruction decode(const std::vector<std::uint8_t>& rom, std::uint16_t address) const;

    static std::string hex8(std::uint8_t v);
    static std::string hex16(std::uint16_t v);
    static std::string signedDisp(std::int8_t d);

private:
    Instruction decodeBase(const std::vector<std::uint8_t>& rom, std::uint16_t address,
                           int prefixBytes, int indexMode) const; // 0 HL, 1 IX, 2 IY
    Instruction decodeCB(const std::vector<std::uint8_t>& rom, std::uint16_t address,
                         int prefixBytes, int indexMode, bool indexedCB) const;
    Instruction decodeED(const std::vector<std::uint8_t>& rom, std::uint16_t address,
                         int prefixBytes) const;
};

} // namespace pacripper
