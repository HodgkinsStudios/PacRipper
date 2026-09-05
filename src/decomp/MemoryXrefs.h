#pragma once
// PacRipper hardware-semantics analysis semantic memory cross-reference index
// Created by Jacob Hodgkins

#include "HardwareSemantics.h"
#include "RamObjects.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace pacripper {

struct MemoryXrefRecord {
    std::size_t id=0;
    std::size_t hardwareAccessId=0;
    std::uint16_t pc=0;
    MemoryAccessKind access=MemoryAccessKind::Unknown;
    AddressResolutionKind addressResolution=AddressResolutionKind::Unresolved;
    std::uint16_t start=0;
    std::uint16_t end=0;
    BoardDeviceKind device=BoardDeviceKind::None;
    bool staticProof=false;
    bool dynamicObserved=false;
    std::set<std::uint16_t> functionOwners;
    std::set<std::size_t> addressDefinitionIds;
    std::set<std::size_t> valueDefinitionIds;
    std::set<std::size_t> readResultDefinitionIds;
    std::set<std::uint16_t> valueDefinitionPCs;
    std::set<std::uint16_t> downstreamUsePCs;
    std::set<std::size_t> ramObjectIds;
};

struct MemoryXrefStats {
    std::size_t records=0;
    std::size_t exactAddressRecords=0;
    std::size_t hardwareRecords=0;
    std::size_t ramRecords=0;
    std::size_t writeValueLinks=0;
    std::size_t readUseLinks=0;
};

class MemoryXrefs {
public:
    static std::vector<MemoryXrefRecord> build(const std::vector<HardwareAccessRecord>& accesses,
                                               const DefUseResult& defUse,
                                               const std::map<std::uint16_t,std::set<std::uint16_t>>& functionOwnersByPC,
                                               const std::vector<RamObjectRecord>& ramObjects);
    static MemoryXrefStats stats(const std::vector<MemoryXrefRecord>& records);
    static std::vector<std::size_t> exactAddressMatches(const std::vector<MemoryXrefRecord>& records,
                                                        std::uint16_t address,
                                                        MemoryAccessKind access=MemoryAccessKind::Unknown);
};

} // namespace pacripper
