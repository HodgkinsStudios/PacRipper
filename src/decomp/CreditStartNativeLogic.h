#pragma once
// PacRipper credit/start logic native game-logic implementation: real credit/start lifecycle
// Created by Jacob Hodgkins

#include "LifecycleSchedulerNativeLogic.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace pacripper {

enum class CreditStartLogicFamily {
    MainModeDispatch,
    CreditPresenceTransition,
    CreditStateDispatch,
    StartSubstateDispatch,
    CreditStartPrompt,
    TwoPlayerStartGate,
    OnePlayerStartGate,
    CreditDeductionRefresh,
    StartSessionFinalization
};

struct CreditStartCoverageRecord {
    std::size_t id=0;
    std::string stableId;
    CreditStartLogicFamily family=CreditStartLogicFamily::MainModeDispatch;
    std::uint16_t entryPC=0;
    std::vector<std::uint16_t> sourcePCs;
    std::size_t units=0;
    bool directNative=false;
    bool sourcePresent=false;
    std::string evidence;
};

struct CreditStartValidationRecord {
    std::string stableId;
    bool passed=false;
    std::string evidenceKind;
    std::string diagnostic;
};

struct CreditStartStats {
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
    std::uint64_t lifecycleReferenceOperations=0;
    std::uint64_t lifecycleHybridOperations=0;
    std::uint64_t lifecycleTransitionalOperations=0;
    std::uint64_t lifecycleReferenceSessionHash=0;
    std::uint64_t lifecycleHybridSessionHash=0;
    std::size_t lifecycleNewFamiliesObserved=0;
    std::uint64_t lifecycleNewFamilyInvocations=0;
    std::uint64_t lifecycleCoinFirstCreditFrame=0;
    std::uint64_t lifecycleStartGateFirstFrame=0;
    std::uint64_t lifecycleSessionFinalizeFirstFrame=0;
    bool lifecycleInputScenarioPass=false;
    bool endToEndNative=false;
};

class CreditStartHybridRecoveredLogic final: public TransitionalRecoveredLogic {
public:
    CreditStartHybridRecoveredLogic(const std::vector<std::uint8_t>& program,
                               const std::vector<GeneratedOperation>& operations);
    std::size_t inheritedFamiliesObserved() const;
    std::size_t newFamiliesObserved() const;
    std::uint64_t inheritedFamilyInvocations() const { return inheritedFamilyInvocations_; }
    std::uint64_t newFamilyInvocations() const { return newFamilyInvocations_; }
    std::uint64_t transitionalOperationsExecuted() const { return transitionalOperationsExecuted_; }
    const std::map<CoreLogicFamily,std::uint64_t>& coreInvocations() const { return coreInvocations_; }
    const std::map<LifecycleSchedulerLogicFamily,std::uint64_t>& lifecycleSchedulerInvocations() const { return lifecycleSchedulerInvocations_; }
    const std::map<CreditStartLogicFamily,std::uint64_t>& newInvocations() const { return newInvocations_; }
protected:
    bool executeUntilYield(std::string& error) override;
private:
    std::map<CoreLogicFamily,std::uint64_t> coreInvocations_;
    std::map<LifecycleSchedulerLogicFamily,std::uint64_t> lifecycleSchedulerInvocations_;
    std::map<CreditStartLogicFamily,std::uint64_t> newInvocations_;
    std::uint64_t inheritedFamilyInvocations_=0;
    std::uint64_t newFamilyInvocations_=0;
    std::uint64_t transitionalOperationsExecuted_=0;
};

class CreditStartNativeLogicCoverage {
public:
    static constexpr std::size_t FixedRecoveredLogicUnits=LifecycleSchedulerNativeLogicCoverage::FixedRecoveredLogicUnits;
    static constexpr std::size_t BaselineDirectNativeLogicUnits=LifecycleSchedulerNativeLogicCoverage::DirectNativeLogicUnits;
    static constexpr std::size_t AdditionalDirectNativeLogicUnits=55;
    static constexpr std::size_t DirectNativeLogicUnits=BaselineDirectNativeLogicUnits+AdditionalDirectNativeLogicUnits;
    static constexpr std::size_t TransitionalOperationQuantum=LifecycleSchedulerNativeLogicCoverage::TransitionalOperationQuantum;

    static std::string familyText(CreditStartLogicFamily family);
    static const std::vector<CreditStartCoverageRecord>& coverageManifest();
    static bool familyForEntry(std::uint16_t pc,CreditStartLogicFamily& family);
    static bool isCoveredSourcePC(std::uint16_t pc);

    static void buildCoverageLedger(const std::vector<GeneratedOperation>& operations,
                                     std::vector<CreditStartCoverageRecord>& ledger,
                                     CreditStartStats& stats);
    static bool executeNativeFamily(CreditStartLogicFamily family,SemanticExecutionState& state,
                                    std::size_t& equivalentOperations,std::string& error,GeneratedExecutionBoundary* boundary=nullptr);
    static std::vector<CreditStartValidationRecord> runDifferentialValidation(
        const std::vector<std::uint8_t>& program,
        const std::vector<GeneratedOperation>& operations,
        CreditStartStats& stats);
    static std::vector<CreditStartValidationRecord> runCanonicalValidation(
        const std::vector<std::uint8_t>& program,
        const std::vector<GeneratedOperation>& operations,
        const RuntimeResourceStore& resources,
        CreditStartStats& stats);
};

} // namespace pacripper
