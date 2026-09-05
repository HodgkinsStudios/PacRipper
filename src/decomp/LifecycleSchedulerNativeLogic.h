#pragma once
// PacRipper lifecycle/scheduler logic native game-logic implementation: lifecycle + scheduler ownership
// Created by Jacob Hodgkins

#include "CoreNativeLogic.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace pacripper {

enum class LifecycleSchedulerLogicFamily {
    TaskQueueRestartFront,
    TaskQueueAppendCore,
    DelayedCommandPrepare,
    DelayedCommandCore,
    AttractInitializePrefix,
    AttractInitializeCopy,
    GlobalStateAdvance,
    AttractStateOne,
    RackAdvanceInputGate,
    StartStatePreparePrefix,
    StartStateContinuation,
    SessionResetLifecycle,
    AttractTaskBatch,
    SetGlobalStateThree,
    DelayedAdvanceAndClear,
    IntermissionSetupTaskBatch,
    IntermissionSetupPrefix,
    NoIntermissionExit,
    IntermissionCleanupPrefix,
    StateFieldClearRoutine,
    IntermissionCleanupAdvance,
    AttractTaskBatchRedirect,
    SetGlobalStateThreeRedirect
};

struct LifecycleSchedulerCoverageRecord {
    std::size_t id=0;
    std::string stableId;
    LifecycleSchedulerLogicFamily family=LifecycleSchedulerLogicFamily::TaskQueueRestartFront;
    std::uint16_t entryPC=0;
    std::vector<std::uint16_t> sourcePCs;
    std::size_t units=0;
    bool directNative=false;
    bool sourcePresent=false;
    std::string evidence;
};

struct LifecycleSchedulerValidationRecord {
    std::string stableId;
    bool passed=false;
    std::string evidenceKind;
    std::string diagnostic;
};

struct LifecycleSchedulerStats {
    std::size_t recoveredLogicUnits=0;
    std::size_t baselineDirectNativeLogicUnits=0;
    std::size_t additionalDirectNativeLogicUnits=0;
    std::size_t directNativeLogicUnits=0;
    std::size_t transitionalLogicUnits=0;
    std::size_t baselineCoverageFamilies=0;
    std::size_t additionalCoverageFamilies=0;
    std::size_t coverageFamilies=0;
    bool noOverlap=false;
    bool noGap=false;
    bool coverageReady=false;
    std::size_t differentialChecks=0;
    std::size_t differentialPassed=0;
    std::size_t differentialFailed=0;
    std::size_t differentialReferenceOperations=0;
    std::size_t canonicalChecks=0;
    std::size_t canonicalPassed=0;
    std::size_t canonicalFailed=0;
    std::size_t canonicalInheritedFamiliesObserved=0;
    std::size_t canonicalNewFamiliesObserved=0;
    std::uint64_t canonicalInheritedFamilyInvocations=0;
    std::uint64_t canonicalNewFamilyInvocations=0;
    std::uint64_t canonicalTransitionalOperations=0;
    std::uint64_t canonicalReferenceOperations=0;
    std::uint64_t canonicalHybridOperations=0;
    std::uint64_t canonicalReferenceSessionHash=0;
    std::uint64_t canonicalHybridSessionHash=0;
    bool canonicalHybridPass=false;
    std::size_t lifecycleChecks=0;
    std::size_t lifecyclePassed=0;
    std::size_t lifecycleFailed=0;
    std::uint64_t lifecycleReferenceSessionHash=0;
    std::uint64_t lifecycleHybridSessionHash=0;
    bool lifecycleInputScenarioPass=false;
    bool endToEndNative=false;
};

class LifecycleSchedulerHybridRecoveredLogic final: public TransitionalRecoveredLogic {
public:
    LifecycleSchedulerHybridRecoveredLogic(const std::vector<std::uint8_t>& program,
                               const std::vector<GeneratedOperation>& operations);
    std::size_t inheritedFamiliesObserved() const;
    std::size_t newFamiliesObserved() const;
    std::uint64_t inheritedFamilyInvocations() const { return inheritedFamilyInvocations_; }
    std::uint64_t newFamilyInvocations() const { return newFamilyInvocations_; }
    std::uint64_t transitionalOperationsExecuted() const { return transitionalOperationsExecuted_; }
    const std::map<CoreLogicFamily,std::uint64_t>& inheritedInvocations() const { return inheritedInvocations_; }
    const std::map<LifecycleSchedulerLogicFamily,std::uint64_t>& newInvocations() const { return newInvocations_; }
protected:
    bool executeUntilYield(std::string& error) override;
private:
    std::map<CoreLogicFamily,std::uint64_t> inheritedInvocations_;
    std::map<LifecycleSchedulerLogicFamily,std::uint64_t> newInvocations_;
    std::uint64_t inheritedFamilyInvocations_=0;
    std::uint64_t newFamilyInvocations_=0;
    std::uint64_t transitionalOperationsExecuted_=0;
};

class LifecycleSchedulerNativeLogicCoverage {
public:
    static constexpr std::size_t FixedRecoveredLogicUnits=CoreNativeLogicCoverage::FixedRecoveredLogicUnits;
    static constexpr std::size_t BaselineDirectNativeLogicUnits=CoreNativeLogicCoverage::DirectNativeLogicUnits;
    static constexpr std::size_t AdditionalDirectNativeLogicUnits=195;
    static constexpr std::size_t DirectNativeLogicUnits=BaselineDirectNativeLogicUnits+AdditionalDirectNativeLogicUnits;
    static constexpr std::size_t TransitionalOperationQuantum=CoreNativeLogicCoverage::TransitionalOperationQuantum;

    static std::string familyText(LifecycleSchedulerLogicFamily family);
    static const std::vector<LifecycleSchedulerCoverageRecord>& coverageManifest();
    static bool familyForEntry(std::uint16_t pc,LifecycleSchedulerLogicFamily& family);
    static bool isCoveredSourcePC(std::uint16_t pc);

    static void buildCoverageLedger(const std::vector<GeneratedOperation>& operations,
                                     std::vector<LifecycleSchedulerCoverageRecord>& ledger,
                                     LifecycleSchedulerStats& stats);
    static bool executeNativeFamily(LifecycleSchedulerLogicFamily family,SemanticExecutionState& state,
                                    std::size_t& equivalentOperations,std::string& error,GeneratedExecutionBoundary* boundary=nullptr);
    static std::vector<LifecycleSchedulerValidationRecord> runDifferentialValidation(
        const std::vector<std::uint8_t>& program,
        const std::vector<GeneratedOperation>& operations,
        LifecycleSchedulerStats& stats);
    static std::vector<LifecycleSchedulerValidationRecord> runCanonicalValidation(
        const std::vector<std::uint8_t>& program,
        const std::vector<GeneratedOperation>& operations,
        const RuntimeResourceStore& resources,
        LifecycleSchedulerStats& stats);
};

} // namespace pacripper
