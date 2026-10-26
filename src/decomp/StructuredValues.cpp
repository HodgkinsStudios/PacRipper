// PacRipper structured-expression analysis proof-guided structured expression regions
// Created by Jacob Hodgkins

#include "StructuredValues.h"

namespace pacripper {

StructuredExpressionRegionRecord StructuredValues::makeRegion(std::size_t id,const StructuredExpressionRegionInput& input){
    StructuredExpressionRegionRecord r;static_cast<StructuredExpressionRegionInput&>(r)=input;r.id=id;
    r.semanticLifted=input.staticRegionProof&&input.dependenciesExact&&!input.ambiguousDependencies&&!input.semanticExpression.empty();
    r.renderedCondition=r.semanticLifted?input.semanticExpression:input.rawCondition;
    if(r.renderedCondition.empty())r.renderedCondition="/* unresolved Z80 flag condition */";
    return r;
}

bool StructuredValues::canElideTemporary(const TemporaryElisionInput& i){
    if(!i.staticProof||i.valueName.empty())return false;
    if(!(i.exactSameOriginCopy||i.singleConsumerIntermediate))return false;
    if(!i.allUsesInsideRegion||i.escapesRegion)return false;
    if(!i.flagsPreserved||!i.orderPreserved)return false;
    if(i.volatileOrSideEffecting)return false;
    return true;
}

TemporaryElisionRecord StructuredValues::makeTemporaryElision(std::size_t id,const TemporaryElisionInput& input){
    TemporaryElisionRecord r;static_cast<TemporaryElisionInput&>(r)=input;r.id=id;
    r.reason=input.exactSameOriginCopy?"exact same-origin synthetic copy":"exact single-consumer synthetic intermediate";
    return r;
}

std::vector<CallContinuityRecord> StructuredValues::buildCallContinuity(const std::vector<CallBindingRecord>& bindings){
    std::vector<CallContinuityRecord> out;
    for(const auto& b:bindings){
        const bool preserved=b.postValueKind==CallPostValueKind::PreservedInput&&b.provenPreserved&&b.hasInputBinding;
        const bool returned=b.postValueKind==CallPostValueKind::ProducedOutput&&b.provenReturningOutput&&b.hasOutputBinding;
        if(!preserved&&!returned)continue;
        if(b.postValueName.empty())continue;
        CallContinuityRecord r;r.id=out.size();r.callBindingId=b.id;r.callerFunction=b.callerFunction;r.callPC=b.callPC;r.calleeFunction=b.calleeFunction;r.reg=b.reg;r.kind=b.postValueKind;r.postValueName=b.postValueName;r.exact=true;r.preserved=preserved;r.returnedOutput=returned;r.provingPCs=b.outputSourcePCs;r.provingPCs.insert(b.callPC);out.push_back(r);
    }
    return out;
}

StructuredValuesStats StructuredValues::stats(const std::vector<StructuredExpressionRegionRecord>& regions,const std::vector<TemporaryElisionRecord>& elisions,const std::vector<CallContinuityRecord>& continuity){
    StructuredValuesStats s;s.regions=regions.size();s.temporaryElisions=elisions.size();s.callContinuities=continuity.size();
    for(const auto&r:regions)(r.semanticLifted?++s.exactSemanticConditions:++s.rawFallbackConditions);
    for(const auto&c:continuity){if(c.preserved)++s.preservedContinuities;if(c.returnedOutput)++s.returnedOutputContinuities;}
    return s;
}

} // namespace pacripper
