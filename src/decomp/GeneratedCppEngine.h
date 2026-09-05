#pragma once
// PacRipper generated-code execution model canonical generated-C++ rebase + differential execution
// Created by Jacob Hodgkins

#include "CanonicalSemanticLift.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pacripper {

class GeneratedExecutionBoundary {
public:
    virtual ~GeneratedExecutionBoundary()=default;
    // Reference-execution event seam. The ordinary generated-code execution model path does not use this
    // interface; platform abstraction+ may attach adapters without changing the verified generated
    // operation descriptors or generated corpus.
    virtual std::uint8_t memoryRead(std::uint16_t address,std::uint8_t fallback,std::uint16_t sourcePC)=0;
    virtual void memoryWrite(std::uint16_t address,std::uint8_t value,std::uint16_t sourcePC)=0;
    virtual std::uint8_t portRead(std::uint16_t port,std::uint8_t fallback,std::uint16_t sourcePC)=0;
    virtual void portWrite(std::uint16_t port,std::uint8_t value,std::uint16_t sourcePC)=0;
    virtual void interruptControl(SemanticKind kind,std::uint8_t value,std::uint16_t sourcePC)=0;
    virtual void halt(std::uint16_t sourcePC)=0;
};

struct GeneratedOperation {
    std::size_t id=0;
    std::string stableId;
    std::string blockId;
    std::uint16_t blockStart=0;
    std::uint16_t sourcePC=0;
    std::uint16_t fallthroughPC=0;
    SemanticKind baseKind=SemanticKind::Unsupported;
    SemanticOracleExtensionKind semanticOracleExtension=SemanticOracleExtensionKind::None;
    CanonicalSemanticExtensionKind canonicalSemanticExtension=CanonicalSemanticExtensionKind::None;
    std::vector<std::uint8_t> bytes;
    std::string mnemonic;
    std::string operands;
    std::string rawText;
    std::string provenance;
};

struct GeneratedBlock {
    std::string stableId;
    std::uint16_t start=0;
    std::uint16_t end=0;
    std::vector<std::size_t> operationIds;
};

struct GeneratedSourceRecord {
    std::size_t id=0;
    std::string blockId;
    std::string operationId;
    std::uint16_t blockStart=0;
    std::uint16_t sourcePC=0;
    std::uint16_t fallthroughPC=0;
    std::string semanticKind;
    std::vector<std::uint8_t> bytes;
    std::string generatedFunction;
    std::string provenance;
};

enum class GeneratedMismatchDomain {
    None,
    SemanticInterpreter,
    IndependentOracle,
    GeneratedModel
};

struct GeneratedCodeDifferentialRecord {
    std::size_t id=0;
    std::string blockId;
    std::uint16_t blockStart=0;
    std::size_t snapshots=0;
    std::size_t operationsCompared=0;
    bool accepted=false;
    GeneratedMismatchDomain mismatchDomain=GeneratedMismatchDomain::None;
    std::uint16_t firstDivergencePC=0xFFFF;
    std::string firstOperationId;
    std::string diagnostic;
};

struct GeneratedCodeStats {
    std::size_t canonicalOperations=0;
    std::size_t generatedOperations=0;
    std::size_t canonicalBlocks=0;
    std::size_t generatedBlocks=0;
    std::size_t sourceMapRecords=0;
    std::size_t provenanceCompleteOperations=0;
    std::size_t semanticallyAcceptedBlocks=0;
    std::size_t oracleAcceptedBlocks=0;
    std::size_t acceptedBlocks=0;
    std::size_t semanticMismatches=0;
    std::size_t oracleMismatches=0;
    std::size_t generatedModelMismatches=0;
    std::size_t differentialSnapshots=0;
    std::size_t differentialOperations=0;
    bool completeGeneratedCoverage=false;
    bool completeSourceProvenance=false;
    bool deterministicCorpus=false;
    bool differentialComplete=false;
};

class GeneratedCppEngine {
public:
    static std::string mismatchDomainText(GeneratedMismatchDomain domain);
    static std::string semanticKindText(const GeneratedOperation& operation);

    static void buildGeneratedModel(const std::vector<CanonicalSemanticLiftedOperation>& canonicalOperations,
                                    const std::vector<CanonicalSemanticLiftedBlock>& canonicalBlocks,
                                    std::vector<GeneratedOperation>& generatedOperations,
                                    std::vector<GeneratedBlock>& generatedBlocks,
                                    std::vector<GeneratedSourceRecord>& sourceMap,
                                    GeneratedCodeStats& stats);

    // Intentionally separate exact execution path from CanonicalSemanticLift::executeLifted.
    // It consumes the verified generated operation descriptor and implements the same machine
    // semantics independently so differential verification is not a self-comparison.
    static bool executeGeneratedOperation(const GeneratedOperation& operation,
                                          SemanticExecutionState& state,
                                          std::string& error);

    // Additive platform abstraction seam. With a transparent boundary this is bit-for-bit
    // equivalent to executeGeneratedOperation; the original entry point remains
    // the verified generated-code execution model regression path.
    static bool executeGeneratedOperationWithBoundary(const GeneratedOperation& operation,
                                                      SemanticExecutionState& state,
                                                      GeneratedExecutionBoundary& boundary,
                                                      std::string& error);

    static bool executeGeneratedBlock(const GeneratedBlock& block,
                                      const std::vector<GeneratedOperation>& operations,
                                      SemanticExecutionState& state,
                                      std::size_t& executedOperations,
                                      std::string& error);

    static std::vector<GeneratedCodeDifferentialRecord> verifyGeneratedExecution(
        const std::vector<std::uint8_t>& program,
        const std::vector<CanonicalSemanticLiftedOperation>& canonicalOperations,
        const std::vector<CanonicalSemanticLiftedBlock>& canonicalBlocks,
        const std::vector<GeneratedOperation>& generatedOperations,
        const std::vector<GeneratedBlock>& generatedBlocks,
        GeneratedCodeStats& stats,
        unsigned snapshotsPerBlock=3);

    static bool emitGeneratedCorpus(const std::string& directory,
                                    const std::vector<GeneratedOperation>& operations,
                                    const std::vector<GeneratedBlock>& blocks,
                                    const std::vector<GeneratedSourceRecord>& sourceMap,
                                    std::string& error);
};

} // namespace pacripper
