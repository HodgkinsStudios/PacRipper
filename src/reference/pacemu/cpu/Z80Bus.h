// PacRipper semantic-oracle analysis test-only independent Z80 oracle source.
// Adapted from an earlier Pac-Man emulator project created and owned by Jacob Hodgkins.
// Validation/corroboration only; never static disassembly proof.
#pragma once

#include "../core/Types.h"

namespace pacemu {

// Minimal electrical interface seen by the Z80 core.  Keeping this separate
// from Pac-Man's concrete board bus makes the CPU independently testable with
// flat 64 KiB exerciser memories while the arcade board retains its mirrors,
// latches and side effects.
class Z80Bus {
public:
    virtual ~Z80Bus() {}
    virtual u8 read8(u16 address) = 0;
    virtual void write8(u16 address, u8 value) = 0;
    virtual u8 ioRead(u16 port) = 0;
    virtual void ioWrite(u16 port, u8 value) = 0;

    // Called during the maskable interrupt acknowledge M1 cycle. Most generic
    // test buses can simply return the vector previously supplied to requestIrq(),
    // while Pac-Man overrides this so the CPU samples the *current* sync-bus
    // controller latch at acknowledge time, matching the physical board.
    virtual u8 interruptAcknowledge(u8 requestedVector) { return requestedVector; }
};

} // namespace pacemu
