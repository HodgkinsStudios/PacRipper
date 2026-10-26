#pragma once
// Created by Jacob Hodgkins

#include "RomClosure.h"

#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace pacripper {

enum class RomObjectKind {
    ExactAccessCluster,
    ByteLookupTable,
    WordPointerTable,
    SequentialStream,
    RecordTable,
    BoundedRegion,
    DynamicObservedRegion
};

struct RomObjectRecord {
    std::size_t id = 0;
    std::uint16_t start = 0;
    std::uint16_t end = 0; // exclusive
    RomObjectKind kind = RomObjectKind::ExactAccessCluster;
    bool exactBoundary = false;
    bool boundedBoundary = false;
    bool dynamicOnly = false;
    std::size_t entrySize = 0;
    std::size_t entryCount = 0;
    std::set<std::size_t> consumerIndices;
    std::set<std::uint16_t> consumerPCs;
    std::set<std::size_t> overlappingObjectIds;
    std::string note;
};

struct RomPointerLinkRecord {
    std::size_t tableObjectId = 0;
    std::size_t tableEntryIndex = 0;
    std::uint16_t entryAddress = 0;
    std::uint16_t target = 0;
    std::set<std::size_t> targetObjectIds;
    bool pointeeExtentProven = false;
    std::uint16_t pointeeStart = 0;
    std::uint16_t pointeeEnd = 0;
    std::string note;
};

struct FunctionRegisterSummary {
    std::uint16_t functionEntry = 0;
    std::set<std::string> localMayWrite;
    std::set<std::string> transitiveMayWrite;
    std::set<std::string> preserved;
    std::set<std::string> stackRestored;
    std::set<std::uint16_t> directCallees;
    std::set<std::uint16_t> directRamMayWrite;
    std::set<std::uint16_t> transitiveRamMayWrite;
    bool hasUnknownMemoryWrite = false;
    bool transitiveUnknownMemoryWrite = false;
    bool hasUnknownCallEffects = false;
    bool hasNonReturnExit = false;
    bool stackBalanced = false;
};

struct UnresolvedPrioritySpan {
    std::uint16_t start = 0;
    std::uint16_t end = 0; // exclusive
    std::size_t length = 0;
    std::size_t nearbyObjectCount = 0;
    std::size_t nearbyPointerTargetCount = 0;
    std::size_t nearbyConsumerCount = 0;
    std::string reason;
};

struct RomObjectStats {
    std::size_t objects = 0;
    std::size_t exactObjects = 0;
    std::size_t boundedObjects = 0;
    std::size_t dynamicObjects = 0;
    std::size_t byteLookupObjects = 0;
    std::size_t wordPointerObjects = 0;
    std::size_t streamObjects = 0;
    std::size_t recordObjects = 0;
    std::size_t pointerLinks = 0;
    std::size_t pointerLinksToObjects = 0;
    std::size_t pointeeExtentsProven = 0;
    std::size_t functionSummaries = 0;
    std::size_t provenPreservedRegisterFacts = 0;
    std::size_t stackRestoredRegisterFacts = 0;
    std::size_t objectPointerInterproceduralConsumers = 0;
    std::size_t objectPointerRamPointerReloadConsumers = 0;
    std::size_t objectPointerStackPointerConsumers = 0;
    std::size_t newlyExplainedBytes = 0;
};

class RomObjects {
public:
    static std::string objectKindText(RomObjectKind kind);
    static RomObjectKind objectKindForConsumer(RomConsumerKind kind,bool dynamic);
    static std::size_t entrySizeForConsumer(RomConsumerKind kind);
    static bool isStrongPointeeObject(const RomObjectRecord& object);

    static std::vector<RomObjectRecord> reconstruct(const std::vector<RomConsumerRecord>& consumers,
                                                    std::size_t romSize);
    static std::vector<RomPointerLinkRecord> decodePointerLinks(const std::vector<RomObjectRecord>& objects,
                                                                const std::vector<std::uint8_t>& program);
    static std::vector<UnresolvedPrioritySpan> prioritizeUnresolved(const std::vector<RomByteClosureRecord>& closure,
                                                                    const std::vector<RomObjectRecord>& objects,
                                                                    std::size_t maxSpans=64);
};

} // namespace pacripper
