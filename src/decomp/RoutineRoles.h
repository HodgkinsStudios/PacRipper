#pragma once
// PacRipper structured-expression analysis neutral routine role signatures, clustering and navigation
// Created by Jacob Hodgkins

#include "RoutineBehavior.h"
#include "StructuredControl.h"
#include "StructuredValues.h"

#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace pacripper {

enum class RoutineSimilarityKind { ExactSignature, CompatibleAdditionalEffects, MateriallyDifferent };

struct RoutineRoleInput {
    std::uint16_t functionEntry=0;
    std::set<std::string> definiteInputs;
    std::set<std::string> possibleInputs;
    std::set<std::string> definiteOutputs;
    std::set<std::uint16_t> definiteRamReads;
    std::set<std::uint16_t> possibleRamReads;
    std::set<std::uint16_t> definiteRamWrites;
    std::set<std::uint16_t> possibleRamWrites;
    std::set<std::size_t> readSchemaIds;
    std::set<std::size_t> writeSchemaIds;
    std::set<BoardDeviceKind> definiteHardwareReads;
    std::set<BoardDeviceKind> possibleHardwareReads;
    std::set<BoardDeviceKind> definiteHardwareWrites;
    std::set<BoardDeviceKind> possibleHardwareWrites;
    std::set<std::uint16_t> directCallees;
    std::size_t loopCount=0;
    std::size_t ifCount=0;
    std::size_t ifElseCount=0;
    std::size_t whileCount=0;
    std::size_t doWhileCount=0;
    std::size_t definiteCallInputs=0;
    std::size_t possibleCallInputs=0;
    std::size_t preservedCallValues=0;
    std::size_t returnedCallValues=0;
    bool dynamicCorroborated=false;
    std::set<BoardDeviceKind> dynamicOnlyHardwareReads;
    std::set<BoardDeviceKind> dynamicOnlyHardwareWrites;
};

struct RoutineRoleSignatureRecord : RoutineRoleInput {
    std::size_t id=0;
    std::set<std::string> staticFacts;
    std::set<std::string> dynamicOnlyFacts;
    std::string canonicalSignature;
    std::string neutralLabel;
};

struct RoutineSimilarityRecord {
    std::uint16_t first=0;
    std::uint16_t second=0;
    RoutineSimilarityKind kind=RoutineSimilarityKind::MateriallyDifferent;
    std::set<std::string> sharedFacts;
    std::set<std::string> firstOnlyFacts;
    std::set<std::string> secondOnlyFacts;
};

struct RoutineClusterRecord {
    std::size_t id=0;
    RoutineSimilarityKind kind=RoutineSimilarityKind::ExactSignature;
    std::vector<std::uint16_t> members;
    std::set<std::string> sharedFacts;
};

struct RoutineNavigationRecord {
    std::uint16_t functionEntry=0;
    std::set<std::uint16_t> callers;
    std::set<std::uint16_t> callees;
    std::set<std::size_t> schemas;
    std::set<BoardDeviceKind> hardwareDevices;
    std::set<std::uint16_t> ramAddresses;
    std::set<std::size_t> structuredRegionIds;
    std::set<std::size_t> liftedStatementIds;
    std::set<std::uint16_t> similarExact;
    std::set<std::uint16_t> similarCompatible;
};

struct RoutineRoleStats {
    std::size_t signatures=0;
    std::size_t dynamicallyCorroborated=0;
    std::size_t signaturesWithDynamicOnlyEffects=0;
    std::size_t exactClusters=0;
    std::size_t exactClusteredRoutines=0;
    std::size_t compatiblePairs=0;
    std::size_t materiallyDifferentPairs=0;
    std::size_t navigationRecords=0;
};

class RoutineRoles {
public:
    static RoutineRoleSignatureRecord makeSignature(std::size_t id,const RoutineRoleInput& input);
    static RoutineSimilarityRecord compare(const RoutineRoleSignatureRecord& a,const RoutineRoleSignatureRecord& b);
    static std::vector<RoutineClusterRecord> exactClusters(const std::vector<RoutineRoleSignatureRecord>& records);
    static std::string similarityText(RoutineSimilarityKind kind);
    static RoutineRoleStats stats(const std::vector<RoutineRoleSignatureRecord>& signatures,
                                  const std::vector<RoutineSimilarityRecord>& similarities,
                                  const std::vector<RoutineClusterRecord>& clusters,
                                  const std::vector<RoutineNavigationRecord>& navigation);
};

} // namespace pacripper
