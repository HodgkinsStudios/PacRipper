#pragma once
// PacRipper structured-expression analysis proof-guided structured expression regions
// Created by Jacob Hodgkins

#include "StructuredControl.h"
#include "TypeEvidence.h"
#include "HardwareSemantics.h"
#include "ValueFlow.h"

#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace pacripper {

struct StructuredExpressionRegionInput {
    std::uint16_t functionEntry=0;
    RegionKind kind=RegionKind::GotoFallback;
    std::uint16_t entry=0;
    std::uint16_t conditionPC=0;
    std::string rawCondition;
    std::string semanticExpression;
    bool staticRegionProof=false;
    bool dependenciesExact=false;
    bool ambiguousDependencies=false;
    std::set<std::uint16_t> sourceBlocks;
    std::set<std::uint16_t> provingPCs;
    std::set<TypeRoleKind> typedRoles;
    std::set<BoardDeviceKind> typedDevices;
};

struct StructuredExpressionRegionRecord : StructuredExpressionRegionInput {
    std::size_t id=0;
    bool semanticLifted=false;
    std::string renderedCondition;
};

struct TemporaryElisionInput {
    std::size_t regionId=0;
    std::uint16_t functionEntry=0;
    std::size_t definitionId=0;
    std::uint16_t definitionPC=0;
    std::string valueName;
    bool staticProof=false;
    bool exactSameOriginCopy=false;
    bool singleConsumerIntermediate=false;
    bool allUsesInsideRegion=false;
    bool escapesRegion=false;
    bool flagsPreserved=false;
    bool orderPreserved=false;
    bool volatileOrSideEffecting=false;
    std::set<std::uint16_t> usePCs;
    std::vector<std::string> rawFallback;
};

struct TemporaryElisionRecord : TemporaryElisionInput {
    std::size_t id=0;
    bool presentationOnly=true;
    std::string reason;
};

struct CallContinuityRecord {
    std::size_t id=0;
    std::size_t callBindingId=0;
    std::uint16_t callerFunction=0;
    std::uint16_t callPC=0;
    std::uint16_t calleeFunction=0;
    std::string reg;
    CallPostValueKind kind=CallPostValueKind::None;
    std::string postValueName;
    bool exact=false;
    bool preserved=false;
    bool returnedOutput=false;
    std::set<std::uint16_t> provingPCs;
};

struct StructuredValuesStats {
    std::size_t regions=0;
    std::size_t exactSemanticConditions=0;
    std::size_t rawFallbackConditions=0;
    std::size_t temporaryElisions=0;
    std::size_t callContinuities=0;
    std::size_t preservedContinuities=0;
    std::size_t returnedOutputContinuities=0;
};

class StructuredValues {
public:
    static StructuredExpressionRegionRecord makeRegion(std::size_t id,const StructuredExpressionRegionInput& input);
    static bool canElideTemporary(const TemporaryElisionInput& input);
    static TemporaryElisionRecord makeTemporaryElision(std::size_t id,const TemporaryElisionInput& input);
    static std::vector<CallContinuityRecord> buildCallContinuity(const std::vector<CallBindingRecord>& bindings);
    static StructuredValuesStats stats(const std::vector<StructuredExpressionRegionRecord>& regions,
                                       const std::vector<TemporaryElisionRecord>& elisions,
                                       const std::vector<CallContinuityRecord>& continuity);
};

} // namespace pacripper
