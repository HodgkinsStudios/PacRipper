#pragma once
// PacRipper canonical semantic lift corrected canonical semantic rebase
// Created by Jacob Hodgkins

#include "SemanticOracleEngine.h"
#include "ReconciliationEngine.h"

#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace pacripper {

enum class CanonicalSemanticExtensionKind {
    None,
    IndexedMemory,
    Neg
};

struct CanonicalSemanticLiftedOperation {
    std::size_t id=0;
    std::string stableId;
    std::string blockId;
    std::uint16_t blockStart=0;
    std::uint16_t sourcePC=0;
    std::uint16_t fallthroughPC=0;
    SemanticKind baseKind=SemanticKind::Unsupported;
    SemanticOracleExtensionKind semanticOracleExtension=SemanticOracleExtensionKind::None;
    CanonicalSemanticExtensionKind canonicalSemanticExtension=CanonicalSemanticExtensionKind::None;
    bool supported=false;
    std::vector<std::uint8_t> bytes;
    std::string mnemonic;
    std::string operands;
    std::string rawText;
    std::string note;
};

struct CanonicalSemanticLiftedBlock {
    std::string stableId;
    std::uint16_t start=0;
    std::uint16_t end=0;
    std::vector<std::size_t> operationIds;
    bool fullySupported=false;
};

struct CanonicalSemanticOracleRecord {
    std::size_t id=0;
    std::string blockId;
    std::uint16_t blockStart=0;
    std::size_t snapshots=0;
    std::size_t operationsCompared=0;
    bool supported=false;
    bool accepted=false;
    std::uint16_t firstDivergencePC=0xFFFF;
    std::string diagnostic;
};

struct CanonicalSemanticSelectorDomainRecord {
    std::size_t id=0;
    std::set<std::uint16_t> selectors;
    std::set<std::uint16_t> directSelectors;
    std::set<std::uint16_t> inlineTaskSelectors;
    std::set<std::uint16_t> wrapperSelectors;
    std::set<std::uint16_t> playerSelectors;
    std::set<std::uint16_t> levelSelectors;
    std::set<std::uint16_t> producerPCs;
    bool callInventoryComplete=false;
    bool inlineInventoryComplete=false;
    bool finiteDomainComplete=false;
    std::string note;
};

struct CanonicalSemanticSelectorReferenceRecord {
    std::size_t id=0;
    std::uint16_t selector=0;
    std::uint16_t tableEntry=0;
    std::uint16_t target=0;
    bool lowPath=false;
    bool targetInRom=false;
    bool streamExtentProven=false;
    bool ramDependentHighPath=false;
    std::set<std::uint16_t> romReadAddresses;
    std::string note;
};

struct CanonicalSemanticResidualRecord {
    std::size_t id=0;
    std::uint16_t start=0;
    std::uint16_t end=0;
    std::size_t length=0;
    std::string reason;
};

struct CanonicalSemanticStats {
    std::size_t canonicalInstructionStarts=0;
    std::size_t mechanicallyLiftedInstructions=0;
    std::size_t unsupportedInstructionSemantics=0;
    std::size_t canonicalBlocks=0;
    std::size_t fullySupportedBlocks=0;
    std::size_t independentlyVerifiedBlocks=0;
    std::size_t independentOracleMismatches=0;
    std::size_t independentOracleSnapshots=0;
    std::size_t independentOracleOperations=0;
    std::size_t semanticLiftPrimitiveOperations=0;
    std::size_t semanticOracleExtensionOperations=0;
    std::size_t canonicalSemanticExtensionOperations=0;
    std::size_t selectorDomainValues=0;
    std::size_t selectorReferences=0;
    std::size_t ramDependentHighSelectors=0;
    std::size_t newlyPositiveRomBytes=0;
    std::size_t positivelyClassifiedRomBytes=0;
    std::size_t unresolvedRomBytes=0;
    std::size_t residualSpans=0;
    bool selectorDomainComplete=false;
    bool completeCanonicalSemanticCoverage=false;
    bool independentOracleComplete=false;
};

class CanonicalSemanticLift {
public:
    static std::string extensionKindText(CanonicalSemanticExtensionKind kind);
    static std::string semanticKindText(const CanonicalSemanticLiftedOperation& operation);

    static void buildCanonicalLift(const std::vector<std::uint8_t>& program,
                                   const std::vector<ReconciliationCanonicalInstructionRecord>& canonical,
                                   std::vector<CanonicalSemanticLiftedOperation>& operations,
                                   std::vector<CanonicalSemanticLiftedBlock>& blocks,
                                   CanonicalSemanticStats& stats);

    static bool executeLifted(const CanonicalSemanticLiftedOperation& operation,
                              SemanticExecutionState& state,
                              std::string& error);

    static std::vector<CanonicalSemanticOracleRecord> verifyWithIndependentOracle(
        const std::vector<std::uint8_t>& program,
        const std::vector<CanonicalSemanticLiftedOperation>& operations,
        const std::vector<CanonicalSemanticLiftedBlock>& blocks,
        CanonicalSemanticStats& stats,
        unsigned snapshotsPerBlock=3);
};

} // namespace pacripper
