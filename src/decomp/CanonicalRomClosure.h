#pragma once
// PacRipper canonical ROM closure RAM-descriptor mirror bound + corrected final ROM closure
// Created by Jacob Hodgkins

#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace pacripper {

struct CanonicalClosureHighSelectorBoundRecord {
    std::size_t id=0;
    std::uint16_t selector=0;
    std::uint16_t producerPC=0;
    std::uint16_t tableEntry=0;
    std::uint16_t target=0;
    std::uint16_t scanStart=0;
    std::uint16_t firstRomMirrorAddress=0x8000;
    std::uint16_t firstFixedDelimiterBus=0;
    std::uint16_t firstFixedDelimiterRom=0;
    std::uint16_t secondFixedDelimiterBus=0;
    std::uint16_t secondFixedDelimiterRom=0;
    std::set<std::size_t> relevantIntermissionWriterProofIds;
    std::set<std::uint16_t> potentialRomReadAddresses;
    bool selectorProducerExact=false;
    bool boardMirrorExact=false;
    bool fixedDelimiterFenceProven=false;
    bool cpirRomFenceProven=false;
    bool writerContentInvariantRequired=true;
    bool accepted=false;
    std::string note;
};

struct CanonicalClosureCanonicalDataObjectRecord {
    std::size_t id=0;
    std::string name;
    std::uint16_t start=0;
    std::uint16_t end=0;
    std::set<std::uint16_t> rootPCs;
    std::set<std::uint16_t> consumerPCs;
    std::set<std::uint16_t> coveredAddresses;
    bool sourceShapeProven=false;
    bool accepted=false;
    std::string note;
};

struct CanonicalClosureNegativeClosureRecord {
    std::size_t id=0;
    std::uint16_t start=0;
    std::uint16_t end=0;
    std::size_t length=0;
    std::size_t residualExtentNegativeProofId=static_cast<std::size_t>(-1);
    std::set<std::uint16_t> canonicalImmediateReferencePCs;
    bool residualExtentOrdinaryPremisesAccepted=false;
    bool highSelectorRomDomainDisjoint=false;
    bool canonicalImmediateReferenceAbsent=false;
    bool tailGuard=false;
    bool im2VectorTailExclusionAccepted=false;
    bool acceptedUnused=false;
    std::string note;
};

struct CanonicalClosureResidualRecord {
    std::size_t id=0;
    std::uint16_t start=0;
    std::uint16_t end=0;
    std::size_t length=0;
    std::string reason;
};

struct CanonicalClosureStats {
    std::size_t highSelectorProofs=0;
    std::size_t acceptedHighSelectorProofs=0;
    std::size_t boundedHighSelectorPotentialRomBytes=0;
    std::size_t canonicalDataObjects=0;
    std::size_t acceptedCanonicalDataObjects=0;
    std::size_t newlyPositiveRomBytes=0;
    std::size_t negativeClosureRecords=0;
    std::size_t acceptedNegativeClosureRecords=0;
    std::size_t newlyProvenUnusedRomBytes=0;
    std::size_t positivelyClassifiedRomBytes=0;
    std::size_t provenUnusedRomBytes=0;
    std::size_t unresolvedRomBytes=0;
    std::size_t residualSpans=0;
    std::size_t canonicalSystemOnlyHighRomRoots=0;
    bool canonicalSystemOnlyHighRomRootInventoryComplete=false;
    bool highSelectorRomDomainComplete=false;
    bool im2VectorTailExclusionAccepted=false;
    bool completeRomClassification=false;
};

} // namespace pacripper
