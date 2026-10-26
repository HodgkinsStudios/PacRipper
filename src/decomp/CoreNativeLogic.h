#pragma once
// PacRipper core native logic direct native game-logic implementation:
// Created by Jacob Hodgkins

#include "NativeIntegration.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace pacripper {

enum class CoreLogicFamily {
    ResetEntry,
    GlobalGameStateDispatch,
    IntermissionSelectDispatch,
    FirstIntermissionDispatch,
    SecondIntermissionDispatch,
    ThirdIntermissionDispatch,
    IntermissionActorInitialization,
    IntermissionActorClear,
    FirstIntermissionStateAdvance,
    SecondIntermissionStateAdvance,
    ThirdIntermissionStateAdvance
};

struct CoreCoverageRecord {
    std::size_t id=0;
    std::string stableId;
    CoreLogicFamily family=CoreLogicFamily::ResetEntry;
    std::uint16_t entryPC=0;
    std::vector<std::uint16_t> sourcePCs;
    std::size_t units=0;
    bool directNative=false;
    bool sourcePresent=false;
    std::string evidence;
};

struct CoreValidationRecord {
    std::string stableId;
    bool passed=false;
    std::string evidenceKind;
    std::string diagnostic;
};

struct CoreStats {
    std::size_t recoveredLogicUnits=0;
    std::size_t coverageFamilies=0;
    std::size_t directNativeLogicUnits=0;
    std::size_t transitionalLogicUnits=0;
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
    std::size_t canonicalNativeFamiliesObserved=0;
    std::uint64_t canonicalNativeFamilyInvocations=0;
    std::uint64_t canonicalTransitionalOperations=0;
    std::uint64_t canonicalReferenceOperations=0;
    std::uint64_t canonicalHybridOperations=0;
    std::uint64_t canonicalReferenceSessionHash=0;
    std::uint64_t canonicalHybridSessionHash=0;
    bool canonicalHybridPass=false;
    bool endToEndNative=false;
};

// Hybrid coverage driver: explicit core native logic families execute directly in state-oriented
// C++; only the complement of the fixed 5,414-operation corpus may reach the verified
// generated-code execution model generated-semantic seam inherited from native integration.
class CoreHybridRecoveredLogic final: public TransitionalRecoveredLogic {
public:
    CoreHybridRecoveredLogic(const std::vector<std::uint8_t>& program,
                               const std::vector<GeneratedOperation>& operations);
    std::uint64_t nativeFamilyInvocations() const { return nativeFamilyInvocations_; }
    std::size_t nativeFamiliesObserved() const;
    std::uint64_t transitionalOperationsExecuted() const { return transitionalOperationsExecuted_; }
    const std::map<CoreLogicFamily,std::uint64_t>& familyInvocations() const { return familyInvocations_; }
protected:
    bool executeUntilYield(std::string& error) override;
private:
    std::map<CoreLogicFamily,std::uint64_t> familyInvocations_;
    std::uint64_t nativeFamilyInvocations_=0;
    std::uint64_t transitionalOperationsExecuted_=0;
};

class CoreNativeLogicCoverage {
public:
    static constexpr std::size_t FixedRecoveredLogicUnits=5414;
    static constexpr std::size_t DirectNativeLogicUnits=71;
    static constexpr std::size_t TransitionalOperationQuantum=8192;

    static std::string familyText(CoreLogicFamily family);
    static const std::vector<CoreCoverageRecord>& coverageManifest();
    static bool familyForEntry(std::uint16_t pc,CoreLogicFamily& family);
    static bool isCoveredSourcePC(std::uint16_t pc);

    static void buildCoverageLedger(const std::vector<GeneratedOperation>& operations,
                                     std::vector<CoreCoverageRecord>& ledger,
                                     CoreStats& stats);

    // Direct state-oriented implementation used by both the product hybrid driver and
    // the differential harness. equivalentOperations is the number of generated
    // operations the verified reference path would execute for the same family boundary.
    static bool executeNativeFamily(CoreLogicFamily family,SemanticExecutionState& state,
                                    std::size_t& equivalentOperations,std::string& error);

    static std::vector<CoreValidationRecord> runDifferentialValidation(
        const std::vector<std::uint8_t>& program,
        const std::vector<GeneratedOperation>& operations,
        CoreStats& stats);

    static std::vector<CoreValidationRecord> runCanonicalValidation(
        const std::vector<std::uint8_t>& program,
        const std::vector<GeneratedOperation>& operations,
        const RuntimeResourceStore& resources,
        CoreStats& stats);
};

} // namespace pacripper
