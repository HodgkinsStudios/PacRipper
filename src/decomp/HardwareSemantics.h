#pragma once
// PacRipper hardware-semantics analysis hardware semantic layer
// Created by Jacob Hodgkins

#include "../disasm/Z80Disassembler.h"
#include "DefUseAnalysis.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace pacripper {

enum class MemoryAccessKind { Read, Write, ReadWrite, Unknown };
enum class AddressResolutionKind { ExactStatic, BoundedStatic, DynamicObserved, Unresolved };
enum class BoardDeviceKind {
    None,
    VideoRam,
    ColorRam,
    OpenBus,
    WorkRam,
    SpriteRam,
    OutputLatch,
    InputIN0,
    NamcoWSG,
    InputIN1,
    SpriteCoordinate,
    NopWriteRegion,
    InputDSW1,
    InputDSW2,
    Watchdog,
    MixedOrUnknown
};
enum class MemoryEffectClass {
    OrdinaryMemory,
    VolatileRead,
    VolatileWrite,
    SideEffectingWrite,
    ExternalInputRead,
    OpenBusRead,
    NopDeviceWrite,
    Unknown
};

struct HardwareAccessInput {
    std::uint16_t pc=0;
    std::size_t instructionLength=1;
    MemoryAccessKind access=MemoryAccessKind::Unknown;
    unsigned width=1;
    AddressResolutionKind addressResolution=AddressResolutionKind::Unresolved;
    std::uint16_t start=0;
    std::uint16_t end=0; // exclusive when resolved
    bool staticProof=false;
    bool dynamicObserved=false;
    std::string addressEntity;
    std::set<std::size_t> addressDefinitionIds;
    std::set<std::size_t> valueDefinitionIds;
    std::set<std::size_t> readResultDefinitionIds;
    std::set<std::uint16_t> provenancePCs;
    std::string rawInstruction;
    std::string note;
};

struct HardwareAccessRecord {
    std::size_t id=0;
    std::uint16_t pc=0;
    std::size_t instructionLength=1;
    MemoryAccessKind access=MemoryAccessKind::Unknown;
    unsigned width=1;
    AddressResolutionKind addressResolution=AddressResolutionKind::Unresolved;
    std::uint16_t start=0;
    std::uint16_t end=0;
    BoardDeviceKind device=BoardDeviceKind::None;
    std::string readIdentity;
    std::string writeIdentity;
    std::string intrinsic;
    bool volatileAccess=false;
    bool sideEffecting=false;
    MemoryEffectClass effect=MemoryEffectClass::Unknown;
    bool staticProof=false;
    bool dynamicObserved=false;
    std::string addressEntity;
    std::set<std::size_t> addressDefinitionIds;
    std::set<std::size_t> valueDefinitionIds;
    std::set<std::size_t> readResultDefinitionIds;
    std::set<std::uint16_t> provenancePCs;
    std::string rawInstruction;
    std::string note;
};

struct HardwareSemanticStats {
    std::size_t records=0;
    std::size_t exactStatic=0;
    std::size_t boundedStatic=0;
    std::size_t dynamicOnly=0;
    std::size_t corroboratedDynamic=0;
    std::size_t volatileReads=0;
    std::size_t sideEffectingWrites=0;
    std::map<BoardDeviceKind,std::size_t> byDevice;
};

struct ResolvedAddressFact {
    AddressResolutionKind resolution=AddressResolutionKind::Unresolved;
    std::uint16_t start=0;
    std::uint16_t end=0; // exclusive
    std::set<std::size_t> definitionIds;
    std::set<std::uint16_t> provenancePCs;
};

class HardwareSemantics {
public:
    static bool isBoardMapped(std::uint16_t address);
    static BoardDeviceKind deviceFor(std::uint16_t address,MemoryAccessKind access);
    static std::string deviceText(BoardDeviceKind kind);
    static std::string accessText(MemoryAccessKind kind);
    static std::string resolutionText(AddressResolutionKind kind);
    static std::string effectText(MemoryEffectClass kind);
    static HardwareAccessRecord classify(const HardwareAccessInput& input);
    static HardwareSemanticStats stats(const std::vector<HardwareAccessRecord>& records);

    // Resolve an address-bearing reaching-definition fact only when every accepted
    // alternative is an exact constant expression. Multiple exact alternatives are
    // retained as a bounded interval rather than guessed to one address.
    static ResolvedAddressFact resolveAddressFact(const ReachingDefinitionFact& fact,
                                                  const std::map<std::size_t,ExpressionRecord>& expressions,
                                                  int displacement=0);
};

} // namespace pacripper
