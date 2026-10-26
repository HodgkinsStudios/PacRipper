#pragma once
// PacRipper contract-aware value flow typed expression propagation and safe statement lifting
// Created by Jacob Hodgkins

#include "DefUseAnalysis.h"
#include "HardwareSemantics.h"
#include "TableSchemas.h"
#include "TypeEvidence.h"
#include "ValueFlow.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace pacripper {

struct PointerBoundEvidence {
    std::size_t definitionId=0;
    bool baseValueKnown=false;
    std::uint16_t baseValue=0;
    std::uint16_t start=0;
    std::uint16_t end=0;
};

struct TypedValueRecord {
    std::size_t id=0;
    std::size_t definitionId=0;
    std::uint16_t pc=0;
    std::string entity;
    unsigned bits=0;
    bool exact=false;
    bool staticProof=false;
    std::set<TypeRoleKind> roles;
    std::set<BoardDeviceKind> devices;
    bool pointerOffsetBounded=false;
    std::string expression;
    std::set<std::uint16_t> provenancePCs;
};

struct IndexedExpressionInput {
    std::uint16_t pc=0;
    std::size_t schemaId=0;
    std::uint16_t schemaStart=0;
    std::uint16_t schemaEnd=0;
    std::size_t stride=0;
    std::size_t elementCount=0;
    std::size_t fieldOffset=0;
    std::size_t fieldWidth=1;
    bool staticProof=false;
    bool finiteBounds=false;
    bool indexExact=false;
    bool indexMinKnown=false;
    std::size_t indexMin=0;
    bool indexMaxKnown=false;
    std::size_t indexMax=0;
    std::string indexExpression;
    std::set<std::size_t> indexDefinitionIds;
    std::set<std::uint16_t> provenancePCs;
};

struct IndexedExpressionRecord : IndexedExpressionInput {
    std::size_t id=0;
    std::string text;
};

struct StatementLiftInput {
    std::uint16_t functionEntry=0;
    std::uint16_t sinkPC=0;
    std::string destination;
    std::string expression;
    bool staticProof=false;
    bool expressionExact=false;
    bool singleConsumerChain=false;
    bool crossesVolatileOrSideEffect=false;
    bool crossesAmbiguousMerge=false;
    bool crossesUnknownCall=false;
    std::set<std::uint16_t> consumedPCs;
    std::set<std::size_t> consumedDefinitionIds;
    std::set<std::uint16_t> flagProducerPCs;
    std::vector<std::string> rawFallback;
};

struct LiftedStatementRecord : StatementLiftInput {
    std::size_t id=0;
    std::string text;
};

struct TypedLiftingStats {
    std::size_t typedValues=0;
    std::size_t pointerValues=0;
    std::size_t hardwareProvenanceValues=0;
    std::size_t boundedPointerArithmetic=0;
    std::size_t indexedExpressions=0;
    std::size_t liftedStatements=0;
    std::size_t liftedInstructions=0;
    std::size_t flagPreservingLifts=0;
};

class TypedLifting {
public:
    static std::vector<TypedValueRecord> propagateTypes(const DefUseResult& defUse,
                                                        const std::vector<TypeEvidenceRecord>& types,
                                                        const std::vector<HardwareAccessRecord>& hardware,
                                                        const std::vector<PointerBoundEvidence>& pointerBounds={});
    static bool buildIndexedExpression(const IndexedExpressionInput& input,IndexedExpressionRecord& out);
    static bool canLiftStatement(const StatementLiftInput& input);
    static LiftedStatementRecord makeLiftedStatement(std::size_t id,const StatementLiftInput& input);
    static TypedLiftingStats stats(const std::vector<TypedValueRecord>& typed,
                                   const std::vector<IndexedExpressionRecord>& indexed,
                                   const std::vector<LiftedStatementRecord>& lifted);
};

} // namespace pacripper
