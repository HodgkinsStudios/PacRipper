// PacRipper semantic-oracle analysis test-only independent Z80 oracle source.
// Adapted from an earlier Pac-Man emulator project created and owned by Jacob Hodgkins.
// Validation/corroboration only; never static disassembly proof.
#pragma once

#include "../core/Types.h"
#include "Z80Bus.h"

namespace pacemu {

class Z80TimingObserver {
public:
    virtual ~Z80TimingObserver() {}
    // Called whenever CPU time advances. The core emits bus-cycle sized
    // chunks (M1=4T, memory=3T, I/O=4T) and explicit internal-idle chunks.
    virtual void onCpuTStates(int tstates) = 0;
};

struct Z80Registers {
    u16 af;
    u16 bc;
    u16 de;
    u16 hl;
    u16 af_alt;
    u16 bc_alt;
    u16 de_alt;
    u16 hl_alt;
    u16 ix;
    u16 iy;
    u16 sp;
    u16 pc;
    u8 i;
    u8 r;
    bool iff1;
    bool iff2;
    u8 interrupt_mode;
};

class Z80 {
public:
    Z80();

    void connectBus(Z80Bus* bus);
    void connectTimingObserver(Z80TimingObserver* observer);
    void reset();

    // Executes exactly one instruction, HALT refresh cycle, or accepted interrupt.
    // The returned count is Z80 T-states consumed by that operation.
    int step();

    void requestIrq(u8 vector);
    void clearIrq();
    void requestNmi();

    const Z80Registers& registers() const { return regs_; }
    Z80Registers& registersMutable() { return regs_; }

    bool halted() const { return halted_; }
    bool irqPending() const { return irq_pending_; }
    bool nmiPending() const { return nmi_pending_; }
    u8 irqVector() const { return irq_vector_; }
    u64 totalCycles() const { return total_cycles_; }
    u64 instructionsExecuted() const { return instructions_executed_; }
    u16 lastInstructionPC() const { return last_pc_; }
    u8 lastOpcode() const { return last_opcode_; }
    int eiDelay() const { return ei_delay_; }
    u64 timingOverruns() const { return timing_overruns_; }

private:
    enum IndexMode { NoIndex, UseIX, UseIY };

    enum Flag {
        FlagC  = 0x01,
        FlagN  = 0x02,
        FlagPV = 0x04,
        FlagX  = 0x08,
        FlagH  = 0x10,
        FlagY  = 0x20,
        FlagZ  = 0x40,
        FlagS  = 0x80
    };

    void advanceTStates(int tstates);
    void finishTiming(int expectedTstates);
    u8 read8(u16 address);
    void write8(u16 address, u8 value);
    u8 ioRead(u16 port);
    void ioWrite(u16 port, u8 value);
    u16 read16(u16 address);
    void write16(u16 address, u16 value);
    u8 fetch8();
    u16 fetch16();
    u8 fetchOpcode();
    void incrementR();

    u8 a() const;
    u8 f() const;
    void setA(u8 value);
    void setF(u8 value);
    static u8 hi(u16 value);
    static u8 lo(u16 value);
    static void setHi(u16& pair, u8 value);
    static void setLo(u16& pair, u8 value);

    u16 hlLike(IndexMode mode) const;
    void setHlLike(IndexMode mode, u16 value);
    u16 rp(int p, IndexMode mode) const;
    void setRp(int p, IndexMode mode, u16 value);
    u16 rp2(int p, IndexMode mode) const;
    void setRp2(int p, IndexMode mode, u16 value);
    u8 reg8(int code, IndexMode mode, u16 memoryAddress) const;
    void setReg8(int code, IndexMode mode, u16 memoryAddress, u8 value);

    void push16(u16 value);
    u16 pop16();
    bool condition(int code) const;

    static bool parity(u8 value);
    static u8 szpFlags(u8 value);
    u8 inc8(u8 value);
    u8 dec8(u8 value);
    u8 add8(u8 lhs, u8 rhs, bool withCarry);
    u8 sub8(u8 lhs, u8 rhs, bool withCarry);
    void cp8(u8 value);
    void logicAnd(u8 value);
    void logicXor(u8 value);
    void logicOr(u8 value);
    void add16(u16 value, IndexMode mode);
    void adc16(u16 value);
    void sbc16(u16 value);
    void daa();

    int serviceInterrupt();
    int executeMain(u8 opcode, IndexMode mode);
    int executeCB(u8 opcode);
    int executeIndexedCB(IndexMode mode, s8 displacement, u8 opcode);
    int executeED(u8 opcode);
    int executeBlock(u8 opcode);

    u8 rotateShift(int operation, u8 value);
    void bitTest(int bit, u8 value, bool indexed, u16 indexedAddress);
    void alu(int operation, u8 value);

    Z80Bus* bus_;
    Z80TimingObserver* timing_observer_;
    Z80Registers regs_;
    bool halted_;
    bool irq_pending_;
    bool nmi_pending_;
    u8 irq_vector_;
    int ei_delay_;
    u64 total_cycles_;
    u64 instructions_executed_;
    u16 last_pc_;
    u8 last_opcode_;
    int step_tstates_;
    u64 timing_overruns_;
};

} // namespace pacemu
