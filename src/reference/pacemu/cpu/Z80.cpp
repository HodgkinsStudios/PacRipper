// PacRipper semantic-oracle analysis test-only independent Z80 oracle source.
// Adapted from an earlier Pac-Man emulator project created and owned by Jacob Hodgkins.
// Validation/corroboration only; never static disassembly proof.
#include "Z80.h"
#include <cstring>
#include <utility>

namespace pacemu {

Z80::Z80()
    : bus_(0), timing_observer_(0), halted_(false), irq_pending_(false), nmi_pending_(false),
      irq_vector_(0), ei_delay_(0), total_cycles_(0), instructions_executed_(0),
      last_pc_(0), last_opcode_(0), step_tstates_(0), timing_overruns_(0) {
    reset();
}

void Z80::connectBus(Z80Bus* bus) { bus_ = bus; }
void Z80::connectTimingObserver(Z80TimingObserver* observer) { timing_observer_ = observer; }

void Z80::reset() {
    std::memset(&regs_, 0, sizeof(regs_));
    // SP and general registers are electrically unspecified after RESET on a
    // physical Z80. 0xFFFF gives deterministic tests and Pac-Man initializes
    // its own stack before relying on it.
    regs_.sp = 0xFFFF;
    regs_.pc = 0x0000;
    regs_.interrupt_mode = 0;
    halted_ = false;
    irq_pending_ = false;
    nmi_pending_ = false;
    irq_vector_ = 0;
    ei_delay_ = 0;
    total_cycles_ = 0;
    instructions_executed_ = 0;
    last_pc_ = 0;
    last_opcode_ = 0;
    step_tstates_ = 0;
    timing_overruns_ = 0;
}

u8 Z80::hi(u16 v) { return static_cast<u8>(v >> 8); }
u8 Z80::lo(u16 v) { return static_cast<u8>(v & 0xFF); }
void Z80::setHi(u16& p, u8 v) { p = static_cast<u16>((p & 0x00FF) | (u16(v) << 8)); }
void Z80::setLo(u16& p, u8 v) { p = static_cast<u16>((p & 0xFF00) | v); }

u8 Z80::a() const { return hi(regs_.af); }
u8 Z80::f() const { return lo(regs_.af); }
void Z80::setA(u8 v) { setHi(regs_.af, v); }
void Z80::setF(u8 v) { setLo(regs_.af, v); }

void Z80::advanceTStates(int tstates) {
    if (tstates <= 0) return;
    step_tstates_ += tstates;
    total_cycles_ += static_cast<u64>(tstates);
    if (timing_observer_) timing_observer_->onCpuTStates(tstates);
}

void Z80::finishTiming(int expectedTstates) {
    if (step_tstates_ < expectedTstates) {
        // These are internal Z80 cycles that do not perform an externally
        // visible memory/I/O transfer. They still advance the arcade board.
        advanceTStates(expectedTstates - step_tstates_);
    } else if (step_tstates_ > expectedTstates) {
        // Never hide a timing-model inconsistency by moving time backwards.
        // Tests expose this counter and require zero for covered instructions.
        ++timing_overruns_;
    }
}

u8 Z80::read8(u16 address) {
    // A normal Z80 memory-read M-cycle consumes 3 T-states. Sample the bus at
    // the end of the cycle so board edges crossed during the cycle occur first.
    advanceTStates(3);
    return bus_ ? bus_->read8(address) : 0xFF;
}

void Z80::write8(u16 address, u8 value) {
    // WR becomes externally meaningful late in the M-cycle; advance time first.
    advanceTStates(3);
    if (bus_) bus_->write8(address, value);
}

u8 Z80::ioRead(u16 port) {
    advanceTStates(4);
    return bus_ ? bus_->ioRead(port) : 0xFF;
}

void Z80::ioWrite(u16 port, u8 value) {
    advanceTStates(4);
    if (bus_) bus_->ioWrite(port, value);
}

u16 Z80::read16(u16 address) {
    const u8 l = read8(address);
    const u8 h = read8(static_cast<u16>(address + 1));
    return static_cast<u16>(l | (u16(h) << 8));
}

void Z80::write16(u16 address, u16 value) {
    write8(address, lo(value));
    write8(static_cast<u16>(address + 1), hi(value));
}

u8 Z80::fetch8() {
    const u8 value = read8(regs_.pc);
    regs_.pc = static_cast<u16>(regs_.pc + 1);
    return value;
}

u16 Z80::fetch16() {
    const u8 l = fetch8();
    const u8 h = fetch8();
    return static_cast<u16>(l | (u16(h) << 8));
}

void Z80::incrementR() {
    regs_.r = static_cast<u8>((regs_.r & 0x80) | ((regs_.r + 1) & 0x7F));
}

u8 Z80::fetchOpcode() {
    // M1 opcode fetch/refresh is 4 T-states, not a normal 3T memory read.
    advanceTStates(4);
    const u8 value = bus_ ? bus_->read8(regs_.pc) : 0xFF;
    regs_.pc = static_cast<u16>(regs_.pc + 1);
    incrementR();
    return value;
}

u16 Z80::hlLike(IndexMode mode) const {
    return mode == UseIX ? regs_.ix : (mode == UseIY ? regs_.iy : regs_.hl);
}

void Z80::setHlLike(IndexMode mode, u16 value) {
    if (mode == UseIX) regs_.ix = value;
    else if (mode == UseIY) regs_.iy = value;
    else regs_.hl = value;
}

u16 Z80::rp(int p, IndexMode mode) const {
    switch (p & 3) {
        case 0: return regs_.bc;
        case 1: return regs_.de;
        case 2: return hlLike(mode);
        default: return regs_.sp;
    }
}

void Z80::setRp(int p, IndexMode mode, u16 value) {
    switch (p & 3) {
        case 0: regs_.bc = value; break;
        case 1: regs_.de = value; break;
        case 2: setHlLike(mode, value); break;
        default: regs_.sp = value; break;
    }
}

u16 Z80::rp2(int p, IndexMode mode) const {
    if ((p & 3) == 3) return regs_.af;
    return rp(p, mode);
}

void Z80::setRp2(int p, IndexMode mode, u16 value) {
    if ((p & 3) == 3) regs_.af = value;
    else setRp(p, mode, value);
}

u8 Z80::reg8(int code, IndexMode mode, u16 mem) const {
    switch (code & 7) {
        case 0: return hi(regs_.bc);
        case 1: return lo(regs_.bc);
        case 2: return hi(regs_.de);
        case 3: return lo(regs_.de);
        case 4: return mode == UseIX ? hi(regs_.ix) : (mode == UseIY ? hi(regs_.iy) : hi(regs_.hl));
        case 5: return mode == UseIX ? lo(regs_.ix) : (mode == UseIY ? lo(regs_.iy) : lo(regs_.hl));
        case 6: return const_cast<Z80*>(this)->read8(mem);
        default: return a();
    }
}

void Z80::setReg8(int code, IndexMode mode, u16 mem, u8 value) {
    switch (code & 7) {
        case 0: setHi(regs_.bc, value); break;
        case 1: setLo(regs_.bc, value); break;
        case 2: setHi(regs_.de, value); break;
        case 3: setLo(regs_.de, value); break;
        case 4:
            if (mode == UseIX) setHi(regs_.ix, value);
            else if (mode == UseIY) setHi(regs_.iy, value);
            else setHi(regs_.hl, value);
            break;
        case 5:
            if (mode == UseIX) setLo(regs_.ix, value);
            else if (mode == UseIY) setLo(regs_.iy, value);
            else setLo(regs_.hl, value);
            break;
        case 6: write8(mem, value); break;
        default: setA(value); break;
    }
}

void Z80::push16(u16 value) {
    regs_.sp = static_cast<u16>(regs_.sp - 1);
    write8(regs_.sp, hi(value));
    regs_.sp = static_cast<u16>(regs_.sp - 1);
    write8(regs_.sp, lo(value));
}

u16 Z80::pop16() {
    const u8 l = read8(regs_.sp);
    regs_.sp = static_cast<u16>(regs_.sp + 1);
    const u8 h = read8(regs_.sp);
    regs_.sp = static_cast<u16>(regs_.sp + 1);
    return static_cast<u16>(l | (u16(h) << 8));
}

bool Z80::parity(u8 v) {
    v ^= static_cast<u8>(v >> 4);
    v &= 0x0F;
    return ((0x6996 >> v) & 1) == 0;
}

u8 Z80::szpFlags(u8 v) {
    u8 flags = static_cast<u8>(v & (FlagS | FlagY | FlagX));
    if (v == 0) flags |= FlagZ;
    if (parity(v)) flags |= FlagPV;
    return flags;
}

u8 Z80::inc8(u8 v) {
    const u8 result = static_cast<u8>(v + 1);
    u8 flags = static_cast<u8>(f() & FlagC);
    flags |= static_cast<u8>(result & (FlagS | FlagY | FlagX));
    if (result == 0) flags |= FlagZ;
    if ((v & 0x0F) == 0x0F) flags |= FlagH;
    if (v == 0x7F) flags |= FlagPV;
    setF(flags);
    return result;
}

u8 Z80::dec8(u8 v) {
    const u8 result = static_cast<u8>(v - 1);
    u8 flags = static_cast<u8>((f() & FlagC) | FlagN);
    flags |= static_cast<u8>(result & (FlagS | FlagY | FlagX));
    if (result == 0) flags |= FlagZ;
    if ((v & 0x0F) == 0x00) flags |= FlagH;
    if (v == 0x80) flags |= FlagPV;
    setF(flags);
    return result;
}

u8 Z80::add8(u8 lhs, u8 rhs, bool withCarry) {
    const unsigned carry = withCarry && (f() & FlagC) ? 1u : 0u;
    const unsigned sum = unsigned(lhs) + unsigned(rhs) + carry;
    const u8 result = static_cast<u8>(sum);
    u8 flags = static_cast<u8>(result & (FlagS | FlagY | FlagX));
    if (result == 0) flags |= FlagZ;
    if (((lhs ^ rhs ^ result) & 0x10) != 0) flags |= FlagH;
    if (((~(lhs ^ rhs) & (lhs ^ result)) & 0x80) != 0) flags |= FlagPV;
    if (sum & 0x100) flags |= FlagC;
    setF(flags);
    return result;
}

u8 Z80::sub8(u8 lhs, u8 rhs, bool withCarry) {
    const unsigned carry = withCarry && (f() & FlagC) ? 1u : 0u;
    const unsigned sub = unsigned(rhs) + carry;
    const u8 result = static_cast<u8>(unsigned(lhs) - sub);
    u8 flags = static_cast<u8>(FlagN | (result & (FlagS | FlagY | FlagX)));
    if (result == 0) flags |= FlagZ;
    if (((lhs ^ rhs ^ result) & 0x10) != 0) flags |= FlagH;
    if ((((lhs ^ rhs) & (lhs ^ result)) & 0x80) != 0) flags |= FlagPV;
    if (unsigned(lhs) < sub) flags |= FlagC;
    setF(flags);
    return result;
}

void Z80::cp8(u8 value) {
    const u8 oldA = a();
    const u8 result = static_cast<u8>(oldA - value);
    u8 flags = static_cast<u8>(FlagN | (result & FlagS) | (value & (FlagY | FlagX)));
    if (result == 0) flags |= FlagZ;
    if (((oldA ^ value ^ result) & 0x10) != 0) flags |= FlagH;
    if ((((oldA ^ value) & (oldA ^ result)) & 0x80) != 0) flags |= FlagPV;
    if (oldA < value) flags |= FlagC;
    setF(flags);
}

void Z80::logicAnd(u8 value) { setA(static_cast<u8>(a() & value)); setF(static_cast<u8>(szpFlags(a()) | FlagH)); }
void Z80::logicXor(u8 value) { setA(static_cast<u8>(a() ^ value)); setF(szpFlags(a())); }
void Z80::logicOr(u8 value)  { setA(static_cast<u8>(a() | value)); setF(szpFlags(a())); }

void Z80::add16(u16 value, IndexMode mode) {
    const u16 lhs = hlLike(mode);
    const u32 result32 = u32(lhs) + u32(value);
    const u16 result = static_cast<u16>(result32);
    u8 flags = static_cast<u8>(f() & (FlagS | FlagZ | FlagPV));
    flags |= static_cast<u8>(hi(result) & (FlagY | FlagX));
    if (((lhs ^ value ^ result) & 0x1000) != 0) flags |= FlagH;
    if (result32 & 0x10000) flags |= FlagC;
    setHlLike(mode, result);
    setF(flags);
}

void Z80::adc16(u16 value) {
    const u16 lhs = regs_.hl;
    const u32 carry = (f() & FlagC) ? 1u : 0u;
    const u32 result32 = u32(lhs) + u32(value) + carry;
    const u16 result = static_cast<u16>(result32);
    u8 flags = static_cast<u8>(hi(result) & (FlagS | FlagY | FlagX));
    if (result == 0) flags |= FlagZ;
    if (((lhs ^ value ^ result) & 0x1000) != 0) flags |= FlagH;
    if (((~(lhs ^ value) & (lhs ^ result)) & 0x8000) != 0) flags |= FlagPV;
    if (result32 & 0x10000) flags |= FlagC;
    regs_.hl = result;
    setF(flags);
}

void Z80::sbc16(u16 value) {
    const u16 lhs = regs_.hl;
    const u32 carry = (f() & FlagC) ? 1u : 0u;
    const u32 sub = u32(value) + carry;
    const u16 result = static_cast<u16>(u32(lhs) - sub);
    u8 flags = static_cast<u8>(FlagN | (hi(result) & (FlagS | FlagY | FlagX)));
    if (result == 0) flags |= FlagZ;
    if (((lhs ^ value ^ result) & 0x1000) != 0) flags |= FlagH;
    if ((((lhs ^ value) & (lhs ^ result)) & 0x8000) != 0) flags |= FlagPV;
    if (u32(lhs) < sub) flags |= FlagC;
    regs_.hl = result;
    setF(flags);
}

void Z80::daa() {
    const u8 oldA = a();
    const u8 oldF = f();
    u8 correction = 0;
    bool carry = (oldF & FlagC) != 0;

    if ((oldF & FlagN) == 0) {
        if ((oldF & FlagH) || (oldA & 0x0F) > 9) correction |= 0x06;
        if (carry || oldA > 0x99) { correction |= 0x60; carry = true; }
        setA(static_cast<u8>(oldA + correction));
    } else {
        if (oldF & FlagH) correction |= 0x06;
        if (carry) correction |= 0x60;
        setA(static_cast<u8>(oldA - correction));
    }

    u8 flags = static_cast<u8>((oldF & FlagN) | (a() & (FlagS | FlagY | FlagX)));
    if (a() == 0) flags |= FlagZ;
    if (parity(a())) flags |= FlagPV;
    if (((oldA ^ a()) & 0x10) != 0) flags |= FlagH;
    if (carry) flags |= FlagC;
    setF(flags);
}

bool Z80::condition(int code) const {
    switch (code & 7) {
        case 0: return (f() & FlagZ) == 0;
        case 1: return (f() & FlagZ) != 0;
        case 2: return (f() & FlagC) == 0;
        case 3: return (f() & FlagC) != 0;
        case 4: return (f() & FlagPV) == 0;
        case 5: return (f() & FlagPV) != 0;
        case 6: return (f() & FlagS) == 0;
        default: return (f() & FlagS) != 0;
    }
}

void Z80::alu(int operation, u8 value) {
    switch (operation & 7) {
        case 0: setA(add8(a(), value, false)); break;
        case 1: setA(add8(a(), value, true)); break;
        case 2: setA(sub8(a(), value, false)); break;
        case 3: setA(sub8(a(), value, true)); break;
        case 4: logicAnd(value); break;
        case 5: logicXor(value); break;
        case 6: logicOr(value); break;
        case 7: cp8(value); break;
    }
}

u8 Z80::rotateShift(int operation, u8 value) {
    u8 result = value;
    bool carry = false;
    switch (operation & 7) {
        case 0: carry = (value & 0x80) != 0; result = static_cast<u8>((value << 1) | (carry ? 1 : 0)); break; // RLC
        case 1: carry = (value & 0x01) != 0; result = static_cast<u8>((value >> 1) | (carry ? 0x80 : 0)); break; // RRC
        case 2: { const bool oldC = (f() & FlagC) != 0; carry = (value & 0x80) != 0; result = static_cast<u8>((value << 1) | (oldC ? 1 : 0)); break; } // RL
        case 3: { const bool oldC = (f() & FlagC) != 0; carry = (value & 0x01) != 0; result = static_cast<u8>((value >> 1) | (oldC ? 0x80 : 0)); break; } // RR
        case 4: carry = (value & 0x80) != 0; result = static_cast<u8>(value << 1); break; // SLA
        case 5: carry = (value & 0x01) != 0; result = static_cast<u8>((value >> 1) | (value & 0x80)); break; // SRA
        case 6: carry = (value & 0x80) != 0; result = static_cast<u8>((value << 1) | 1); break; // SLL (undocumented)
        case 7: carry = (value & 0x01) != 0; result = static_cast<u8>(value >> 1); break; // SRL
    }
    u8 flags = szpFlags(result);
    if (carry) flags |= FlagC;
    setF(flags);
    return result;
}

void Z80::bitTest(int bit, u8 value, bool indexed, u16 indexedAddress) {
    const u8 mask = static_cast<u8>(1u << (bit & 7));
    u8 flags = static_cast<u8>((f() & FlagC) | FlagH);
    if ((value & mask) == 0) flags |= static_cast<u8>(FlagZ | FlagPV);
    if ((bit & 7) == 7 && (value & 0x80)) flags |= FlagS;
    if (indexed) flags |= static_cast<u8>(hi(indexedAddress) & (FlagY | FlagX));
    else flags |= static_cast<u8>(value & (FlagY | FlagX));
    setF(flags);
}

int Z80::executeCB(u8 opcode) {
    const int x = opcode >> 6;
    const int y = (opcode >> 3) & 7;
    const int z = opcode & 7;
    const u16 address = regs_.hl;
    const u8 value = reg8(z, NoIndex, address);

    if (x == 0) {
        const u8 result = rotateShift(y, value);
        setReg8(z, NoIndex, address, result);
        return z == 6 ? 15 : 8;
    }
    if (x == 1) {
        bitTest(y, value, false, 0);
        return z == 6 ? 12 : 8;
    }
    const u8 result = x == 2 ? static_cast<u8>(value & ~(1u << y))
                             : static_cast<u8>(value | (1u << y));
    setReg8(z, NoIndex, address, result);
    return z == 6 ? 15 : 8;
}

int Z80::executeIndexedCB(IndexMode mode, s8 displacement, u8 opcode) {
    const int x = opcode >> 6;
    const int y = (opcode >> 3) & 7;
    const int z = opcode & 7;
    const u16 address = static_cast<u16>(hlLike(mode) + displacement);
    const u8 value = read8(address);

    if (x == 1) {
        bitTest(y, value, true, address);
        return 16; // plus the DD/FD prefix T-states accounted by step()
    }

    u8 result;
    if (x == 0) result = rotateShift(y, value);
    else if (x == 2) result = static_cast<u8>(value & ~(1u << y));
    else result = static_cast<u8>(value | (1u << y));

    write8(address, result);
    if (z != 6) setReg8(z, NoIndex, 0, result);
    return 19; // plus DD/FD prefix T-states
}

int Z80::executeBlock(u8 opcode) {
    const bool decrement = (opcode & 0x08) != 0;
    const bool repeat = (opcode & 0x10) != 0;
    const int family = opcode & 0x03;
    const int delta = decrement ? -1 : 1;

    if (family == 0) { // LDI/LDD/LDIR/LDDR
        const u8 value = read8(regs_.hl);
        write8(regs_.de, value);
        regs_.hl = static_cast<u16>(regs_.hl + delta);
        regs_.de = static_cast<u16>(regs_.de + delta);
        regs_.bc = static_cast<u16>(regs_.bc - 1);
        const u8 sum = static_cast<u8>(a() + value);
        u8 flags = static_cast<u8>(f() & (FlagS | FlagZ | FlagC));
        if (regs_.bc != 0) flags |= FlagPV;
        if (sum & 0x08) flags |= FlagX;
        if (sum & 0x02) flags |= FlagY;
        setF(flags);
        if (repeat && regs_.bc != 0) { regs_.pc = static_cast<u16>(regs_.pc - 2); return 21; }
        return 16;
    }

    if (family == 1) { // CPI/CPD/CPIR/CPDR
        const u8 value = read8(regs_.hl);
        const u8 av = a();
        const u8 result = static_cast<u8>(av - value);
        const bool half = ((av ^ value ^ result) & 0x10) != 0;
        regs_.hl = static_cast<u16>(regs_.hl + delta);
        regs_.bc = static_cast<u16>(regs_.bc - 1);
        u8 flags = static_cast<u8>((f() & FlagC) | FlagN | (result & FlagS));
        if (result == 0) flags |= FlagZ;
        if (half) flags |= FlagH;
        if (regs_.bc != 0) flags |= FlagPV;
        const u8 adjusted = static_cast<u8>(result - (half ? 1 : 0));
        if (adjusted & 0x08) flags |= FlagX;
        if (adjusted & 0x02) flags |= FlagY;
        setF(flags);
        if (repeat && regs_.bc != 0 && result != 0) { regs_.pc = static_cast<u16>(regs_.pc - 2); return 21; }
        return 16;
    }

    if (family == 2) { // INI/IND/INIR/INDR
        const u16 port = regs_.bc;
        const u8 value = ioRead(port);
        write8(regs_.hl, value);
        regs_.hl = static_cast<u16>(regs_.hl + delta);
        setHi(regs_.bc, static_cast<u8>(hi(regs_.bc) - 1));
        const u8 b = hi(regs_.bc);
        const u16 k = u16(value) + u16(static_cast<u8>(lo(port) + delta));
        u8 flags = static_cast<u8>(b & (FlagS | FlagY | FlagX));
        if (b == 0) flags |= FlagZ;
        if (value & 0x80) flags |= FlagN;
        if (k & 0x100) flags |= static_cast<u8>(FlagH | FlagC);
        if (parity(static_cast<u8>((k & 7) ^ b))) flags |= FlagPV;
        setF(flags);
        if (repeat && b != 0) { regs_.pc = static_cast<u16>(regs_.pc - 2); return 21; }
        return 16;
    }

    // OUTI/OUTD/OTIR/OTDR
    const u8 value = read8(regs_.hl);
    regs_.hl = static_cast<u16>(regs_.hl + delta);
    setHi(regs_.bc, static_cast<u8>(hi(regs_.bc) - 1));
    ioWrite(regs_.bc, value);
    const u8 b = hi(regs_.bc);
    const u16 k = u16(value) + u16(lo(regs_.hl));
    u8 flags = static_cast<u8>(b & (FlagS | FlagY | FlagX));
    if (b == 0) flags |= FlagZ;
    if (value & 0x80) flags |= FlagN;
    if (k & 0x100) flags |= static_cast<u8>(FlagH | FlagC);
    if (parity(static_cast<u8>((k & 7) ^ b))) flags |= FlagPV;
    setF(flags);
    if (repeat && b != 0) { regs_.pc = static_cast<u16>(regs_.pc - 2); return 21; }
    return 16;
}

int Z80::executeED(u8 opcode) {
    const int x = opcode >> 6;
    const int y = (opcode >> 3) & 7;
    const int z = opcode & 7;
    const int p = y >> 1;
    const int q = y & 1;

    if (x == 1) {
        switch (z) {
            case 0: { // IN r,(C), IN (C)
                const u8 value = ioRead(regs_.bc);
                if (y != 6) setReg8(y, NoIndex, 0, value);
                u8 flags = static_cast<u8>((f() & FlagC) | szpFlags(value));
                setF(flags);
                return 12;
            }
            case 1: { // OUT (C),r, OUT (C),0
                const u8 value = y == 6 ? 0 : reg8(y, NoIndex, 0);
                ioWrite(regs_.bc, value);
                return 12;
            }
            case 2:
                if (q) adc16(rp(p, NoIndex)); else sbc16(rp(p, NoIndex));
                return 15;
            case 3: {
                const u16 address = fetch16();
                if (q) setRp(p, NoIndex, read16(address));
                else write16(address, rp(p, NoIndex));
                return 20;
            }
            case 4: // NEG and aliases
                setA(sub8(0, a(), false));
                return 8;
            case 5: // RETN/RETI and aliases
                regs_.pc = pop16();
                regs_.iff1 = regs_.iff2;
                return 14;
            case 6: // IM n
                switch (y) {
                    case 0: case 1: case 4: case 5: regs_.interrupt_mode = 0; break;
                    case 2: case 6: regs_.interrupt_mode = 1; break;
                    default: regs_.interrupt_mode = 2; break;
                }
                return 8;
            case 7:
                switch (y) {
                    case 0: regs_.i = a(); return 9;       // LD I,A
                    case 1: regs_.r = a(); return 9;       // LD R,A
                    case 2: {                              // LD A,I
                        setA(regs_.i);
                        u8 flags = static_cast<u8>((f() & FlagC) | (a() & (FlagS | FlagY | FlagX)));
                        if (a() == 0) flags |= FlagZ;
                        if (regs_.iff2) flags |= FlagPV;
                        setF(flags);
                        return 9;
                    }
                    case 3: {                              // LD A,R
                        setA(regs_.r);
                        u8 flags = static_cast<u8>((f() & FlagC) | (a() & (FlagS | FlagY | FlagX)));
                        if (a() == 0) flags |= FlagZ;
                        if (regs_.iff2) flags |= FlagPV;
                        setF(flags);
                        return 9;
                    }
                    case 4: {                              // RRD
                        const u8 m = read8(regs_.hl);
                        const u8 oldA = a();
                        write8(regs_.hl, static_cast<u8>((oldA << 4) | (m >> 4)));
                        setA(static_cast<u8>((oldA & 0xF0) | (m & 0x0F)));
                        setF(static_cast<u8>((f() & FlagC) | szpFlags(a())));
                        return 18;
                    }
                    case 5: {                              // RLD
                        const u8 m = read8(regs_.hl);
                        const u8 oldA = a();
                        write8(regs_.hl, static_cast<u8>((m << 4) | (oldA & 0x0F)));
                        setA(static_cast<u8>((oldA & 0xF0) | (m >> 4)));
                        setF(static_cast<u8>((f() & FlagC) | szpFlags(a())));
                        return 18;
                    }
                    default: return 8; // documented NOP slots
                }
        }
    }

    if (x == 2 && y >= 4 && z <= 3) return executeBlock(opcode);
    return 8; // undefined ED opcodes act as two-byte NOPs
}

int Z80::executeMain(u8 opcode, IndexMode mode) {
    const int x = opcode >> 6;
    const int y = (opcode >> 3) & 7;
    const int z = opcode & 7;
    const int p = y >> 1;
    const int q = y & 1;

    if (x == 0) {
        switch (z) {
            case 0:
                switch (y) {
                    case 0: return 4; // NOP
                    case 1: std::swap(regs_.af, regs_.af_alt); return 4;
                    case 2: { // DJNZ
                        const s8 d = static_cast<s8>(fetch8());
                        const u8 b = static_cast<u8>(hi(regs_.bc) - 1);
                        setHi(regs_.bc, b);
                        if (b != 0) { regs_.pc = static_cast<u16>(regs_.pc + d); return 13; }
                        return 8;
                    }
                    case 3: { const s8 d = static_cast<s8>(fetch8()); regs_.pc = static_cast<u16>(regs_.pc + d); return 12; }
                    default: {
                        const s8 d = static_cast<s8>(fetch8());
                        if (condition(y - 4)) { regs_.pc = static_cast<u16>(regs_.pc + d); return 12; }
                        return 7;
                    }
                }
            case 1:
                if (!q) { setRp(p, mode, fetch16()); return 10; }
                add16(rp(p, mode), mode);
                return 11;
            case 2:
                if (!q) {
                    switch (p) {
                        case 0: write8(regs_.bc, a()); return 7;
                        case 1: write8(regs_.de, a()); return 7;
                        case 2: { const u16 n = fetch16(); write16(n, hlLike(mode)); return 16; }
                        default: { const u16 n = fetch16(); write8(n, a()); return 13; }
                    }
                } else {
                    switch (p) {
                        case 0: setA(read8(regs_.bc)); return 7;
                        case 1: setA(read8(regs_.de)); return 7;
                        case 2: { const u16 n = fetch16(); setHlLike(mode, read16(n)); return 16; }
                        default: { const u16 n = fetch16(); setA(read8(n)); return 13; }
                    }
                }
            case 3:
                if (!q) setRp(p, mode, static_cast<u16>(rp(p, mode) + 1));
                else setRp(p, mode, static_cast<u16>(rp(p, mode) - 1));
                return 6;
            case 4: {
                u16 addr = hlLike(mode);
                int extra = 0;
                if (y == 6 && mode != NoIndex) { addr = static_cast<u16>(addr + static_cast<s8>(fetch8())); extra = 8; }
                const u8 v = reg8(y, mode, addr);
                setReg8(y, mode, addr, inc8(v));
                return (y == 6 ? 11 : 4) + extra;
            }
            case 5: {
                u16 addr = hlLike(mode);
                int extra = 0;
                if (y == 6 && mode != NoIndex) { addr = static_cast<u16>(addr + static_cast<s8>(fetch8())); extra = 8; }
                const u8 v = reg8(y, mode, addr);
                setReg8(y, mode, addr, dec8(v));
                return (y == 6 ? 11 : 4) + extra;
            }
            case 6: {
                u16 addr = hlLike(mode);
                int extra = 0;
                if (y == 6 && mode != NoIndex) { addr = static_cast<u16>(addr + static_cast<s8>(fetch8())); extra = 5; }
                const u8 n = fetch8();
                setReg8(y, mode, addr, n);
                return (y == 6 ? 10 : 7) + extra;
            }
            case 7:
                switch (y) {
                    case 0: { // RLCA
                        const u8 old = a(); const bool c = (old & 0x80) != 0;
                        setA(static_cast<u8>((old << 1) | (c ? 1 : 0)));
                        setF(static_cast<u8>((f() & (FlagS | FlagZ | FlagPV)) | (a() & (FlagY | FlagX)) | (c ? FlagC : 0)));
                        return 4;
                    }
                    case 1: { const u8 old = a(); const bool c = (old & 1) != 0; setA(static_cast<u8>((old >> 1) | (c ? 0x80 : 0))); setF(static_cast<u8>((f() & (FlagS | FlagZ | FlagPV)) | (a() & (FlagY | FlagX)) | (c ? FlagC : 0))); return 4; }
                    case 2: { const u8 old = a(); const bool c = (old & 0x80) != 0; const bool oldC = (f() & FlagC) != 0; setA(static_cast<u8>((old << 1) | (oldC ? 1 : 0))); setF(static_cast<u8>((f() & (FlagS | FlagZ | FlagPV)) | (a() & (FlagY | FlagX)) | (c ? FlagC : 0))); return 4; }
                    case 3: { const u8 old = a(); const bool c = (old & 1) != 0; const bool oldC = (f() & FlagC) != 0; setA(static_cast<u8>((old >> 1) | (oldC ? 0x80 : 0))); setF(static_cast<u8>((f() & (FlagS | FlagZ | FlagPV)) | (a() & (FlagY | FlagX)) | (c ? FlagC : 0))); return 4; }
                    case 4: daa(); return 4;
                    case 5: setA(static_cast<u8>(~a())); setF(static_cast<u8>((f() & (FlagS | FlagZ | FlagPV | FlagC)) | FlagH | FlagN | (a() & (FlagY | FlagX)))); return 4;
                    case 6: setF(static_cast<u8>((f() & (FlagS | FlagZ | FlagPV)) | (a() & (FlagY | FlagX)) | FlagC)); return 4;
                    default: {
                        const bool oldC = (f() & FlagC) != 0;
                        u8 nf = static_cast<u8>((f() & (FlagS | FlagZ | FlagPV)) | (a() & (FlagY | FlagX)));
                        if (oldC) nf |= FlagH; else nf |= FlagC;
                        setF(nf);
                        return 4;
                    }
                }
        }
    }

    if (x == 1) {
        if (opcode == 0x76) { halted_ = true; return 4; }
        u16 addr = hlLike(mode);
        int extra = 0;
        if ((y == 6 || z == 6) && mode != NoIndex) { addr = static_cast<u16>(addr + static_cast<s8>(fetch8())); extra = 8; }
        // With an indexed memory operand, DD/FD 66/6E/74/75 use the
        // ordinary H/L register for the non-memory side; IXH/IXL/IYH/IYL
        // substitutions apply only to the register-only encodings.
        const IndexMode registerMode = (mode != NoIndex && (y == 6 || z == 6)) ? NoIndex : mode;
        const u8 value = reg8(z, registerMode, addr);
        setReg8(y, registerMode, addr, value);
        return ((y == 6 || z == 6) ? 7 : 4) + extra;
    }

    if (x == 2) {
        u16 addr = hlLike(mode);
        int extra = 0;
        if (z == 6 && mode != NoIndex) { addr = static_cast<u16>(addr + static_cast<s8>(fetch8())); extra = 8; }
        alu(y, reg8(z, mode, addr));
        return (z == 6 ? 7 : 4) + extra;
    }

    switch (z) {
        case 0:
            if (condition(y)) { regs_.pc = pop16(); return 11; }
            return 5;
        case 1:
            if (!q) { setRp2(p, mode, pop16()); return 10; }
            switch (p) {
                case 0: regs_.pc = pop16(); return 10;
                case 1: std::swap(regs_.bc, regs_.bc_alt); std::swap(regs_.de, regs_.de_alt); std::swap(regs_.hl, regs_.hl_alt); return 4;
                case 2: regs_.pc = hlLike(mode); return 4;
                default: regs_.sp = hlLike(mode); return 6;
            }
        case 2: {
            const u16 n = fetch16();
            if (condition(y)) regs_.pc = n;
            return 10;
        }
        case 3:
            switch (y) {
                case 0: regs_.pc = fetch16(); return 10;
                case 1: return 4; // CB is consumed by step(), unreachable in normal flow
                case 2: { const u8 n = fetch8(); const u16 port = static_cast<u16>((u16(a()) << 8) | n); ioWrite(port, a()); return 11; }
                case 3: { const u8 n = fetch8(); const u16 port = static_cast<u16>((u16(a()) << 8) | n); setA(ioRead(port)); return 11; }
                case 4: { const u16 tmp = read16(regs_.sp); write16(regs_.sp, hlLike(mode)); setHlLike(mode, tmp); return 19; }
                case 5: std::swap(regs_.de, regs_.hl); return 4; // DD/FD prefix is ignored for EX DE,HL
                case 6: regs_.iff1 = regs_.iff2 = false; ei_delay_ = 0; return 4;
                default: regs_.iff1 = regs_.iff2 = true; ei_delay_ = 2; return 4;
            }
        case 4: {
            const u16 n = fetch16();
            if (condition(y)) { push16(regs_.pc); regs_.pc = n; return 17; }
            return 10;
        }
        case 5:
            if (!q) { push16(rp2(p, mode)); return 11; }
            if (p == 0) { const u16 n = fetch16(); push16(regs_.pc); regs_.pc = n; return 17; }
            return 4; // prefix opcodes are handled by step()
        case 6: alu(y, fetch8()); return 7;
        case 7: push16(regs_.pc); regs_.pc = static_cast<u16>(y * 8); return 11;
    }
    return 4;
}

int Z80::serviceInterrupt() {
    if (nmi_pending_) {
        nmi_pending_ = false;
        halted_ = false;
        regs_.iff2 = regs_.iff1;
        regs_.iff1 = false;
        incrementR();
        // NMI acknowledge is 5T followed by two 3T stack writes.
        advanceTStates(5);
        push16(regs_.pc);
        regs_.pc = 0x0066;
        return 11;
    }

    if (!irq_pending_ || !regs_.iff1 || ei_delay_ != 0) return 0;
    halted_ = false;
    regs_.iff1 = false;
    regs_.iff2 = false;
    incrementR();

    // Maskable interrupt acknowledge is a 7T M1-like cycle. Sample the bus
    // vector at acknowledge time rather than permanently capturing it when the
    // IRQ line was first asserted. This matters on Pac-Man because port 0 is a
    // separate vector latch behind the sync-bus controller.
    advanceTStates(7);
    const u8 acknowledgedVector = bus_ ? bus_->interruptAcknowledge(irq_vector_) : irq_vector_;
    if (regs_.interrupt_mode == 2) {
        const u16 table = static_cast<u16>((u16(regs_.i) << 8) | acknowledgedVector);
        const u16 target = read16(table);
        push16(regs_.pc);
        regs_.pc = target;
        return 19;
    }
    if (regs_.interrupt_mode == 1) {
        push16(regs_.pc);
        regs_.pc = 0x0038;
        return 13;
    }

    // IM 0 executes an externally supplied instruction. Pac-Man runs IM 2,
    // but supporting the common RST vectors makes this core useful to tests.
    if ((acknowledgedVector & 0xC7) == 0xC7) {
        push16(regs_.pc);
        regs_.pc = static_cast<u16>(acknowledgedVector & 0x38);
        return 13;
    }
    return 13; // non-RST IM0 bus opcodes are electrically possible but unused here
}

int Z80::step() {
    if (!bus_) return 0;
    step_tstates_ = 0;

    const int interruptCycles = serviceInterrupt();
    if (interruptCycles != 0) {
        finishTiming(interruptCycles);
        ++instructions_executed_;
        return interruptCycles;
    }

    if (halted_) {
        // During HALT the CPU continues M1/refresh timing and increments R.
        advanceTStates(4);
        incrementR();
        if (ei_delay_ > 0) --ei_delay_;
        return 4;
    }

    last_pc_ = regs_.pc;
    IndexMode mode = NoIndex;
    int prefixCycles = 0;
    u8 opcode = fetchOpcode();
    last_opcode_ = opcode;

    while (opcode == 0xDD || opcode == 0xFD) {
        mode = opcode == 0xDD ? UseIX : UseIY;
        prefixCycles += 4;
        opcode = fetchOpcode();
        last_opcode_ = opcode;
    }

    int cycles = 0;
    if (opcode == 0xCB) {
        if (mode == NoIndex) {
            cycles = executeCB(fetchOpcode());
        } else {
            const s8 displacement = static_cast<s8>(fetch8());
            // The final DDCB/FDCB operation byte is not an M1 fetch.
            const u8 cbop = fetch8();
            cycles = prefixCycles + executeIndexedCB(mode, displacement, cbop);
            prefixCycles = 0;
        }
    } else if (opcode == 0xED) {
        cycles = executeED(fetchOpcode()); // DD/FD before ED is ignored apart from timing
    } else {
        cycles = executeMain(opcode, mode);
    }

    cycles += prefixCycles;
    finishTiming(cycles);
    ++instructions_executed_;
    if (ei_delay_ > 0) --ei_delay_;
    return cycles;
}

void Z80::requestIrq(u8 vector) { irq_pending_ = true; irq_vector_ = vector; }
void Z80::clearIrq() { irq_pending_ = false; }
void Z80::requestNmi() { nmi_pending_ = true; }

} // namespace pacemu
