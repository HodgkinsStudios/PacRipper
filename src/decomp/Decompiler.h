#pragma once
// Created by Jacob Hodgkins

#include "../analysis/Analyzer.h"
#include "StackModel.h"
#include "StructuredControl.h"
#include "ConditionSemantics.h"
#include "RomClosure.h"
#include "RomObjects.h"
#include "DefUseAnalysis.h"
#include "RamObjects.h"
#include "HardwareSemantics.h"
#include "MemoryXrefs.h"
#include "RamShapes.h"
#include "TypeEvidence.h"
#include "TableSchemas.h"
#include "RoutineContracts.h"
#include "ValueFlow.h"
#include "TypedLifting.h"
#include "RoutineBehavior.h"
#include "StructuredValues.h"
#include "RoutineRoles.h"
#include "ResidualResearch.h"
#include "ObjectStateRoles.h"
#include "IndirectAddressAnalysis.h"
#include "HighRomSemantics.h"
#include "ResidualReferenceAnalysis.h"
#include "SystemRootAnalysis.h"
#include "RootContextAnalysis.h"
#include "MemoryAliasAnalysis.h"
#include "CommandStreamAnalysis.h"
#include "MazeTopologyAnalysis.h"
#include "IntermissionAnalysis.h"
#include "ResidualExtentAnalysis.h"
#include "Im2VectorAnalysis.h"
#include "SemanticLiftEngine.h"
#include "SemanticOracleEngine.h"
#include "ReconciliationEngine.h"
#include "CanonicalSemanticLift.h"
#include "CanonicalRomClosure.h"
#include "ExactRomReconstruction.h"
#include "RomRebuilder.h"
#include "GeneratedCppEngine.h"
#include "PlatformAbstraction.h"
#include "NativeRuntime.h"
#include "NativeRenderer.h"
#include "NativeAudio.h"
#include "NativeIntegration.h"
#include "CoreNativeLogic.h"
#include "LifecycleSchedulerNativeLogic.h"
#include "CreditStartNativeLogic.h"
#include "SessionInitializationNativeLogic.h"
#include "../recoder/DisplayMapNativeLogic.h"
#include "../recoder/HudBoardNativeLogic.h"
#include "../recoder/BoardInterpreterNativeLogic.h"
#include "../recoder/CommandInterpreterNativeLogic.h"
#include "../recoder/RstUtilityNativeLogic.h"
#include "../recoder/SchedulerUtilityNativeLogic.h"
#include "../recoder/GraphicCreditNativeLogic.h"
#include "../recoder/FrameUpdateNativeLogic.h"
#include "../recoder/ObjectInputNativeLogic.h"
#include "../recoder/FrameHelperNativeLogic.h"
#include "../recoder/CoordinateRenderNativeLogic.h"
#include "../recoder/StartupUtilityNativeLogic.h"
#include "../recoder/StartupRuntimeNativeLogic.h"
#include "../recoder/InterruptSchedulerNativeLogic.h"
#include "../recoder/SystemUtilityNativeLogic.h"
#include "../recoder/StartupSelfTestNativeLogic.h"
#include "../recoder/ColdStateNativeLogic.h"
#include "../recoder/ColdHelperNativeLogic.h"
#include "../recoder/CoordinateDispatchNativeLogic.h"
#include "../recoder/IntermissionStateNativeLogic.h"
#include "../recoder/SystemRootPrimaryNativeLogic.h"
#include "../recoder/SystemRootSecondaryNativeLogic.h"
#include "../recoder/InterruptLatchNativeLogic.h"

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace pacripper {

enum class CfgEdgeKind { Fallthrough, BranchTaken, BranchNotTaken, Call, Restart, Dispatch, Return, Indirect, DynamicIndirect, DynamicReturn };

struct CfgEdge {
    std::uint16_t from = 0;
    int to = -1; // block start; -1 means no concrete destination
    CfgEdgeKind kind = CfgEdgeKind::Fallthrough;
    std::string condition;
    std::size_t observedCount = 0;
};

struct AbstractValue {
    bool known = false;
    std::uint16_t value = 0;
    unsigned bits = 16;
};

struct RegisterState {
    std::map<std::string,AbstractValue> regs;
};

struct BasicBlock {
    std::uint16_t start = 0;
    std::uint16_t end = 0; // exclusive source span, not necessarily contiguous across inline RST payloads
    std::vector<std::uint16_t> instructions;
    std::vector<CfgEdge> outgoing;
    std::set<std::uint16_t> incoming;
    RegisterState entryState;
    RegisterState exitState;
    std::set<std::uint16_t> functionOwners;
};

struct FunctionModel {
    std::uint16_t entry = 0;
    std::string name;
    std::set<std::uint16_t> blocks;
    std::set<std::uint16_t> callees;
    std::set<std::uint16_t> callers;
};

struct StackBlockInfo {
    bool entryInitialized = false;
    bool exitInitialized = false;
    StackState entryState;
    StackState exitState;
};

struct FunctionCallReturnEvidence {
    std::uint16_t functionEntry = 0;
    std::set<std::uint16_t> staticCallers;
    std::set<std::uint16_t> staticContinuations;
    std::map<std::uint16_t,std::size_t> observedReturnDestinations;
    std::size_t matchedObservedReturnTransitions = 0;
    std::size_t unmatchedObservedReturnTransitions = 0;
};


struct ConditionEvidenceRecord {
    std::uint16_t branchAddress = 0;
    std::string rawCondition;
    int producerAddress = -1;
    std::string producerInstruction;
    std::string expression;
    bool crossBlock = false;
    bool dependenciesStable = true;
    std::set<std::string> clobberedRegisters;
    bool memoryClobbered = false;
    std::string semanticNote;
};

struct DefUsePipelineStats {
    DefUseStats defUse;
    RamObjectStats ramObjects;
    std::size_t baselineUnresolvedBytes = 0;
    std::size_t expressionRomConsumers = 0;
    std::size_t newlyExplainedBytes = 0;
    std::size_t unresolvedAfterDefUse = 0;
};

struct HardwarePipelineStats {
    HardwareSemanticStats hardware;
    MemoryXrefStats memoryXrefs;
    RamShapeStats ramShapes;
    std::size_t newlyExplainedBytes = 0;
    std::size_t unresolvedAfterHardwareSemantic = 0;
};

struct TypeContractStats {
    TypeEvidenceStats types;
    TableSchemaStats schemas;
    RoutineContractStats contracts;
    std::size_t newlyExplainedBytes = 0;
    std::size_t unresolvedAfterTypeContract = 0;
};

struct ContractValueStats {
    ValueFlowStats valueFlow;
    TypedLiftingStats lifting;
    RoutineBehaviorStats behavior;
    std::size_t newlyExplainedBytes = 0;
    std::size_t unresolvedAfterContractValue = 0;
};

struct StructuredExpressionStats {
    StructuredValuesStats structuredValues;
    RoutineRoleStats roles;
    std::size_t newlyExplainedBytes = 0;
    std::size_t unresolvedAfterStructuredExpression = 0;
};

struct ResidualClosureStats {
    ResidualResearchStats residual;
    ObjectStateRoleStats objectState;
    std::size_t newlyExplainedBytes = 0;
    std::size_t newlyExactExplainedBytes = 0;
    std::size_t newlyBoundedExplainedBytes = 0;
    std::size_t unresolvedAfterResidualClosure = 0;
};


struct IndirectAddressPipelineStats {
    IndirectAddressStats address;
    std::size_t closureProvenanceRecords = 0;
    std::size_t residualAuditSpans = 0;
    std::size_t auditedResidualBytes = 0;
    std::size_t newlyExplainedBytes = 0;
    std::size_t newlyExactExplainedBytes = 0;
    std::size_t newlyBoundedExplainedBytes = 0;
    std::size_t unresolvedAfterIndirectAddress = 0;
};


struct HighRomStats {
    std::size_t decoders=0;
    std::size_t pointerTableDomains=0;
    std::size_t sparsePointerTableDomains=0;
    std::size_t streamFamilies=0;
    std::size_t acceptedStreams=0;
    std::size_t fixedRecordProofs=0;
    std::size_t boundedBlockProofs=0;
    std::size_t closureProvenanceRecords=0;
    std::size_t residualAuditSpans=0;
    std::size_t auditedResidualBytes=0;
    std::size_t newlyExplainedBytes=0;
    std::size_t newlyExactExplainedBytes=0;
    std::size_t newlyBoundedExplainedBytes=0;
    std::size_t unresolvedAfterHighRom=0;
    SemanticCoverageStats semanticCoverage;
};

struct ResidualReferenceStats {
    std::size_t negativeReferenceRecords=0;
    std::size_t exhaustiveNegativeReferenceRecords=0;
    std::size_t unusedRomRegions=0;
    std::size_t systemSemanticRecords=0;
    std::size_t overlapRecords=0;
    std::size_t closureProvenanceRecords=0;
    std::size_t newlyExplainedBytes=0;
    std::size_t newlyExactExplainedBytes=0;
    std::size_t newlyBoundedExplainedBytes=0;
    std::size_t newlyNegativeExplainedBytes=0;
    std::size_t unresolvedAfterResidualReference=0;
    std::size_t residualSpansAfterResidualReference=0;
    std::size_t unknownIndirectBlockerPCs=0;
    std::size_t dynamicResidualReadEvents=0;
    ResidualReferenceSemanticCoverageStats semanticCoverage;
};

struct DecompilerStats {
    std::size_t basicBlocks = 0;
    std::size_t cfgEdges = 0;
    std::size_t functions = 0;
    std::size_t propagatedBlockEntries = 0;
    std::size_t constantRegisterFacts = 0;
    std::size_t sharedBlocks = 0;
    std::size_t unownedBlocks = 0;
    std::size_t observedCfgEdges = 0;
    std::size_t dynamicOnlyEdges = 0;
    std::size_t functionsWithDominatorTrees = 0;
    std::size_t blocksWithImmediateDominator = 0;
    std::size_t blocksWithImmediatePostDominator = 0;
    std::size_t naturalLoops = 0;
    std::size_t structuredIfRegions = 0;
    std::size_t structuredIfElseRegions = 0;
    std::size_t structuredWhileRegions = 0;
    std::size_t structuredDoWhileRegions = 0;
    std::size_t fallbackBlocks = 0;
    std::size_t stackModeledFunctions = 0;
    std::size_t stackModeledBlocks = 0;
    std::size_t staticCallSites = 0;
    std::size_t observedReturnRecords = 0;
    std::size_t observedReturnsMatchingKnownContinuations = 0;
    std::size_t conditionalFlagBranches = 0;
    std::size_t flagProducerResolvedBranches = 0;
    std::size_t semanticConditionBranches = 0;
    std::size_t crossBlockSemanticConditions = 0;
    std::size_t semanticConditionsSuppressedByClobber = 0;
    RomClosureStats romClosure;
    RomObjectStats romObjects;
    DefUsePipelineStats defUse;
    HardwarePipelineStats hardwareSemantic;
    TypeContractStats typeContract;
    ContractValueStats contractValue;
    StructuredExpressionStats structuredExpression;
    ResidualClosureStats residualClosure;
    IndirectAddressPipelineStats indirectAddress;
    HighRomStats highRom;
    ResidualReferenceStats residualReference;
    SystemRootStats systemRoot;
    RootContextStats rootContext;
    MemoryAliasStats memoryAlias;
    CommandStreamStats commandStream;
    MazeTopologyStats mazeTopology;
    IntermissionStats intermission;
    ResidualExtentStats residualExtent;
    Im2VectorStats im2Vector;
    SemanticLiftStats semanticLift;
    SemanticOracleStats semanticOracle;
    ReconciliationStats reconciliation;
    CanonicalSemanticStats canonicalSemantic;
    CanonicalClosureStats canonicalClosure;
    RomReconstructionStats romReconstruction;
    RomRebuilderStats romRebuilder;
    GeneratedCodeStats generatedCode;
    PlatformAbstractionStats platformContract;
    NativeRuntimeStats nativeRuntime;
    NativeVideoStats nativeVideo;
    NativeAudioStats nativeAudio;
    NativeIntegrationStats nativeIntegration;
    CoreStats core;
    LifecycleSchedulerStats lifecycleScheduler;
    CreditStartStats creditStart;
    SessionInitializationStats sessionInitialization;
    MazePreparationStats mazePreparation;
    DisplayMapStats displayMap;
    HudBoardStats hudBoard;
    BoardInterpreterStats boardInterpreter;
    CommandInterpreterStats commandInterpreter;
    RstUtilityStats rstUtility;
    SchedulerUtilityStats schedulerUtility;
    GraphicCreditStats graphicCredit;
    FrameUpdateStats frameUpdate;
    ObjectInputStats objectInput;
    FrameHelperStats frameHelper;
    CoordinateRenderStats coordinateRender;
    StartupUtilityStats startupUtility;
    StartupRuntimeStats startupRuntime;
    InterruptSchedulerStats interruptScheduler;
    SystemUtilityStats systemUtility;
    StartupSelfTestStats startupSelfTest;
    ColdStateStats coldState;
    ColdHelperStats coldHelper;
    CoordinateDispatchStats coordinateDispatch;
    IntermissionStateStats intermissionState;
    SystemRootPrimaryStats systemRootPrimary;
    SystemRootSecondaryStats systemRootSecondary;
    InterruptLatchStats interruptLatch;
};

class Decompiler {
public:
    bool build(const Analyzer& analyzer,std::string& error);
    void clear();
    bool ready() const { return ready_; }
    const DecompilerStats& stats() const { return stats_; }
    const std::map<std::uint16_t,BasicBlock>& blocks() const { return blocks_; }
    const std::map<std::uint16_t,FunctionModel>& functions() const { return functions_; }
    const std::map<std::uint16_t,StructureAnalysis>& structures() const { return structures_; }
    const std::map<std::uint16_t,StackBlockInfo>& stackBlocks() const { return stackBlocks_; }
    const std::vector<CallSiteRecord>& callSites() const { return callSites_; }
    const std::vector<ObservedReturnRecord>& observedReturns() const { return observedReturns_; }
    const std::map<std::uint16_t,ConditionEvidenceRecord>& conditionEvidence() const { return conditionEvidence_; }
    const std::vector<RomConsumerRecord>& romConsumers() const { return romConsumers_; }
    const std::vector<RomByteClosureRecord>& romClosureBytes() const { return romClosureBytes_; }
    const std::vector<RamPairEvidenceRecord>& ramPairEvidence() const { return ramPairEvidence_; }
    const std::vector<RomObjectRecord>& romObjects() const { return romObjects_; }
    const std::vector<RomPointerLinkRecord>& romPointerLinks() const { return romPointerLinks_; }
    const std::map<std::uint16_t,FunctionRegisterSummary>& functionRegisterSummaries() const { return functionRegisterSummaries_; }
    const std::vector<UnresolvedPrioritySpan>& unresolvedPriority() const { return unresolvedPriority_; }
    const DefUseResult& defUseResult() const { return defUseResult_; }
    const std::vector<RamObjectRecord>& ramObjects() const { return ramObjects_; }
    const std::vector<RomConsumerRecord>& defUseRomConsumers() const { return defUseRomConsumers_; }
    const std::vector<RomByteClosureRecord>& defUseClosureBytes() const { return defUseClosureBytes_; }
    const std::vector<UnresolvedPrioritySpan>& defUseUnresolvedPriority() const { return defUseUnresolvedPriority_; }
    const std::vector<HardwareAccessRecord>& hardwareAccesses() const { return hardwareAccesses_; }
    const std::vector<MemoryXrefRecord>& memoryXrefs() const { return memoryXrefs_; }
    const std::vector<RamShapeRecord>& ramShapes() const { return ramShapes_; }
    const std::vector<TypeEvidenceRecord>& typeEvidence() const { return typeEvidence_; }
    const std::vector<TableSchemaRecord>& tableSchemas() const { return tableSchemas_; }
    const std::vector<RoutineContractRecord>& routineContracts() const { return routineContracts_; }
    const std::vector<MachineValueRecord>& machineValues() const { return machineValues_; }
    const std::vector<MergeValueRecord>& mergeValues() const { return mergeValues_; }
    const std::vector<CallBindingRecord>& callBindings() const { return callBindings_; }
    const std::vector<TypedValueRecord>& typedValues() const { return typedValues_; }
    const std::vector<IndexedExpressionRecord>& indexedExpressions() const { return indexedExpressions_; }
    const std::vector<LiftedStatementRecord>& liftedStatements() const { return liftedStatements_; }
    const std::vector<RoutineBehaviorRecord>& routineBehaviors() const { return routineBehaviors_; }
    const std::vector<StructuredExpressionRegionRecord>& structuredValueRegions() const { return structuredValueRegions_; }
    const std::vector<TemporaryElisionRecord>& temporaryElisions() const { return temporaryElisions_; }
    const std::vector<CallContinuityRecord>& callContinuities() const { return callContinuities_; }
    const std::vector<RoutineRoleSignatureRecord>& routineRoles() const { return routineRoles_; }
    const std::vector<RoutineSimilarityRecord>& routineSimilarities() const { return routineSimilarities_; }
    const std::vector<RoutineClusterRecord>& routineClusters() const { return routineClusters_; }
    const std::vector<RoutineNavigationRecord>& routineNavigation() const { return routineNavigation_; }
    const std::vector<DormantCodeSeedRecord>& dormantCodeSeeds() const { return dormantCodeSeeds_; }
    const std::vector<DormantCodeDiscoveryRecord>& dormantCodeDiscoveries() const { return dormantCodeDiscoveries_; }
    const std::vector<RomExtentRefinementRecord>& romExtentRefinements() const { return romExtentRefinements_; }
    const std::vector<ResidualAuditRecord>& residualAudit() const { return residualAudit_; }
    const std::vector<ObjectRoleRecord>& objectRoles() const { return objectRoles_; }
    const std::vector<StateXrefRecord>& stateXrefs() const { return stateXrefs_; }
    const std::vector<ResidualPriorityV2Record>& residualPriorityV2() const { return residualPriorityV2_; }
    const std::vector<RomByteClosureRecord>& residualClosureClosureBytes() const { return residualClosureClosureBytes_; }
    const std::vector<IndirectMemoryAccessRecord>& indirectMemoryAccesses() const { return indirectMemoryAccesses_; }
    const std::vector<IndirectRomConsumerProofRecord>& indirectRomConsumerProofs() const { return indirectRomConsumerProofs_; }
    const std::vector<IndirectAddressClosureProvenanceRecord>& indirectAddressClosureProvenance() const { return indirectAddressClosureProvenance_; }
    const std::vector<RomByteClosureRecord>& indirectAddressClosureBytes() const { return indirectAddressClosureBytes_; }
    const std::vector<ResidualAuditRecord>& indirectAddressResidualAudit() const { return indirectAddressResidualAudit_; }
    const std::vector<ResidualPriorityV2Record>& indirectAddressResidualPriorityV2() const { return indirectAddressResidualPriorityV2_; }
    const std::vector<RomDecoderRecord>& romDecoders() const { return romDecoders_; }
    const std::vector<PointerTableDomainRecord>& pointerTableDomains() const { return pointerTableDomains_; }
    const std::vector<StreamSemanticRecord>& streamSemantics() const { return streamSemantics_; }
    const std::vector<StreamFamilyRecord>& streamFamilies() const { return streamFamilies_; }
    const std::vector<FixedRecordSemanticRecord>& fixedRecordSemantics() const { return fixedRecordSemantics_; }
    const std::vector<BoundedBlockSemanticRecord>& boundedBlockSemantics() const { return boundedBlockSemantics_; }
    const std::vector<HighRomClosureProvenanceRecord>& highRomClosureProvenance() const { return highRomClosureProvenance_; }
    const std::vector<RomByteClosureRecord>& highRomClosureBytes() const { return highRomClosureBytes_; }
    const std::vector<HighRomResidualAuditRecord>& highRomResidualAudit() const { return highRomResidualAudit_; }
    const std::vector<ResidualPriorityV2Record>& highRomResidualPriorityV2() const { return highRomResidualPriorityV2_; }
    const std::vector<SystemRomSemanticRecord>& systemRomSemantics() const { return systemRomSemantics_; }
    const std::vector<NegativeReferenceRecord>& negativeReferenceEvidence() const { return negativeReferenceEvidence_; }
    const std::vector<UnusedRomRegionRecord>& unusedRomRegions() const { return unusedRomRegions_; }
    const std::vector<SemanticOverlapRecord>& residualReferenceSemanticOverlaps() const { return residualReferenceSemanticOverlaps_; }
    const std::vector<ResidualReferenceClosureProvenanceRecord>& residualReferenceClosureProvenance() const { return residualReferenceClosureProvenance_; }
    const std::vector<RomByteClosureRecord>& residualReferenceClosureBytes() const { return residualReferenceClosureBytes_; }
    const std::vector<SystemRootRecord>& systemRoots() const { return systemRoots_; }
    const std::vector<SystemRootReachabilityRecord>& systemRootReachability() const { return systemRootReachability_; }
    const std::vector<SystemRootInlineDataRecord>& systemRootInlineData() const { return systemRootInlineData_; }
    const std::vector<IndirectAddressRefinementRecord>& indirectAddressRefinements() const { return indirectAddressRefinements_; }
    const std::vector<SystemRootNegativeReferenceRecord>& systemRootNegativeReferenceEvidence() const { return systemRootNegativeReferenceEvidence_; }
    const std::vector<UnusedRomRegionRecord>& systemRootUnusedRomRegions() const { return systemRootUnusedRomRegions_; }
    const std::vector<SystemRootClosureProvenanceRecord>& systemRootClosureProvenance() const { return systemRootClosureProvenance_; }
    const std::vector<RomByteClosureRecord>& systemRootClosureBytes() const { return systemRootClosureBytes_; }
    const std::vector<RootContextAddressContextRecord>& rootContextAddressContexts() const { return rootContextAddressContexts_; }
    const std::vector<RootContextAddressProofRecord>& rootContextAddressProofs() const { return rootContextAddressProofs_; }
    const std::vector<RootContextNegativeReferenceRecord>& rootContextNegativeReferenceEvidence() const { return rootContextNegativeReferenceEvidence_; }
    const std::vector<UnusedRomRegionRecord>& rootContextUnusedRomRegions() const { return rootContextUnusedRomRegions_; }
    const std::vector<RootContextClosureProvenanceRecord>& rootContextClosureProvenance() const { return rootContextClosureProvenance_; }
    const std::vector<RootContextAddressContextRecord>& memoryAliasWriterContexts() const { return memoryAliasWriterContexts_; }
    const std::vector<RootContextAddressProofRecord>& memoryAliasWriterProofs() const { return memoryAliasWriterProofs_; }
    const std::vector<MemoryAliasWriterAliasRecord>& memoryAliasWriterAliases() const { return memoryAliasWriterAliases_; }
    const std::vector<MemoryAliasAddressProofRecord>& memoryAliasAddressProofs() const { return memoryAliasAddressProofs_; }
    const std::vector<MemoryAliasClosureProvenanceRecord>& memoryAliasClosureProvenance() const { return memoryAliasClosureProvenance_; }
    const std::vector<RomByteClosureRecord>& memoryAliasClosureBytes() const { return memoryAliasClosureBytes_; }
    const std::vector<CommandStreamWriterAliasRecord>& commandStreamWriterAliases() const { return commandStreamWriterAliases_; }
    const std::vector<CommandStreamValueProofRecord>& commandStreamValueProofs() const { return commandStreamValueProofs_; }
    const std::vector<CommandStreamCommandStreamRecord>& commandStreamCommandStreams() const { return commandStreamCommandStreams_; }
    const std::vector<CommandStreamAddressProofRecord>& commandStreamAddressProofs() const { return commandStreamAddressProofs_; }
    const std::vector<CommandStreamClosureProvenanceRecord>& commandStreamClosureProvenance() const { return commandStreamClosureProvenance_; }
    const std::vector<RomByteClosureRecord>& commandStreamClosureBytes() const { return commandStreamClosureBytes_; }
    const std::vector<MazeTopologyTopologyInputRecord>& mazeTopologyTopologyInputs() const { return mazeTopologyTopologyInputs_; }
    const std::vector<MazeTopologyDirectionCandidateRecord>& mazeTopologyDirectionCandidates() const { return mazeTopologyDirectionCandidates_; }
    const std::vector<MazeTopologyRetryLoopProofRecord>& mazeTopologyRetryLoopProofs() const { return mazeTopologyRetryLoopProofs_; }
    const std::vector<MazeTopologyAddressProofRecord>& mazeTopologyAddressProofs() const { return mazeTopologyAddressProofs_; }
    const std::vector<MazeTopologyResidualClassificationRecord>& mazeTopologyResidualClassification() const { return mazeTopologyResidualClassification_; }
    const std::vector<MazeTopologyClosureProvenanceRecord>& mazeTopologyClosureProvenance() const { return mazeTopologyClosureProvenance_; }
    const std::vector<RomByteClosureRecord>& mazeTopologyClosureBytes() const { return mazeTopologyClosureBytes_; }
    const std::vector<IntermissionDispatchProofRecord>& intermissionDispatchProofs() const { return intermissionDispatchProofs_; }
    const std::vector<IntermissionVideoWriterProofRecord>& intermissionWriterProofs() const { return intermissionWriterProofs_; }
    const std::vector<IntermissionLifecycleProofRecord>& intermissionLifecycleProofs() const { return intermissionLifecycleProofs_; }
    const std::vector<IntermissionAddressProofRecord>& intermissionAddressProofs() const { return intermissionAddressProofs_; }
    const std::vector<IntermissionClosureProvenanceRecord>& intermissionClosureProvenance() const { return intermissionClosureProvenance_; }
    const std::vector<RomByteClosureRecord>& intermissionClosureBytes() const { return intermissionClosureBytes_; }
    const std::vector<ResidualExtentResidualAuditRecord>& residualExtentResidualAudit() const { return residualExtentResidualAudit_; }
    const std::vector<ResidualExtentExtentProofRecord>& residualExtentExtentProofs() const { return residualExtentExtentProofs_; }
    const std::vector<ResidualExtentNegativeReferenceRecord>& residualExtentNegativeReferenceProofs() const { return residualExtentNegativeReferenceProofs_; }
    const std::vector<ResidualExtentUnusedRegionRecord>& residualExtentUnusedRegions() const { return residualExtentUnusedRegions_; }
    const std::vector<ResidualExtentClosureProvenanceRecord>& residualExtentClosureProvenance() const { return residualExtentClosureProvenance_; }
    const std::vector<ResidualExtentFinalResidualRecord>& residualExtentFinalResidual() const { return residualExtentFinalResidual_; }
    const std::vector<RomByteClosureRecord>& residualExtentClosureBytes() const { return residualExtentClosureBytes_; }
    const std::vector<Im2VectorOutputInventoryRecord>& im2VectorOutputInventory() const { return im2VectorOutputInventory_; }
    const std::vector<Im2VectorCpuModeProofRecord>& im2VectorCpuModeProofs() const { return im2VectorCpuModeProofs_; }
    const std::vector<Im2VectorVectorDomainProofRecord>& im2VectorVectorDomainProofs() const { return im2VectorVectorDomainProofs_; }
    const std::vector<Im2VectorSystemNegativeRecord>& im2VectorSystemNegativeProofs() const { return im2VectorSystemNegativeProofs_; }
    const std::vector<Im2VectorClosureProvenanceRecord>& im2VectorClosureProvenance() const { return im2VectorClosureProvenance_; }
    const std::vector<Im2VectorFinalResidualRecord>& im2VectorFinalResidual() const { return im2VectorFinalResidual_; }
    const std::vector<RomByteClosureRecord>& im2VectorClosureBytes() const { return im2VectorClosureBytes_; }
    const std::vector<SemanticRomProvenanceRecord>& semanticLiftProvenanceLedger() const { return semanticLiftProvenanceLedger_; }
    const std::vector<SemanticLiftedOperation>& semanticLiftLiftedOperations() const { return semanticLiftLiftedOperations_; }
    const std::vector<SemanticLiftedBlock>& semanticLiftLiftedBlocks() const { return semanticLiftLiftedBlocks_; }
    const std::vector<SemanticDifferentialRecord>& semanticLiftDifferentialRecords() const { return semanticLiftDifferentialRecords_; }
    const std::vector<SemanticOracleLiftedOperation>& semanticOracleLiftedOperations() const { return semanticOracleLiftedOperations_; }
    const std::vector<SemanticOracleLiftedBlock>& semanticOracleLiftedBlocks() const { return semanticOracleLiftedBlocks_; }
    const std::vector<SemanticOracleOracleRecord>& semanticOracleOracleRecords() const { return semanticOracleOracleRecords_; }
    const std::vector<SemanticOracleGeneratedSourceRecord>& semanticOracleGeneratedSourceMap() const { return semanticOracleGeneratedSourceMap_; }
    const std::vector<ReconciliationCanonicalInstructionRecord>& reconciliationCanonicalInstructions() const { return reconciliationCanonicalInstructions_; }
    const std::vector<RomByteClosureRecord>& reconciliationClosureBytes() const { return reconciliationClosureBytes_; }
    const std::vector<ReconciliationResidualRecord>& reconciliationFinalResidual() const { return reconciliationFinalResidual_; }
    const std::vector<CanonicalSemanticLiftedOperation>& canonicalSemanticLiftedOperations() const { return canonicalSemanticLiftedOperations_; }
    const std::vector<CanonicalSemanticLiftedBlock>& canonicalSemanticLiftedBlocks() const { return canonicalSemanticLiftedBlocks_; }
    const std::vector<CanonicalSemanticOracleRecord>& canonicalSemanticOracleRecords() const { return canonicalSemanticOracleRecords_; }
    const std::vector<CanonicalSemanticSelectorDomainRecord>& canonicalSemanticSelectorDomains() const { return canonicalSemanticSelectorDomains_; }
    const std::vector<CanonicalSemanticSelectorReferenceRecord>& canonicalSemanticSelectorReferences() const { return canonicalSemanticSelectorReferences_; }
    const std::vector<RomByteClosureRecord>& canonicalSemanticClosureBytes() const { return canonicalSemanticClosureBytes_; }
    const std::vector<CanonicalSemanticResidualRecord>& canonicalSemanticFinalResidual() const { return canonicalSemanticFinalResidual_; }
    std::vector<std::string> canonicalSemanticRebaseLines() const;
    const std::vector<CanonicalClosureHighSelectorBoundRecord>& canonicalClosureHighSelectorBounds() const { return canonicalClosureHighSelectorBounds_; }
    const std::vector<CanonicalClosureCanonicalDataObjectRecord>& canonicalClosureCanonicalDataObjects() const { return canonicalClosureCanonicalDataObjects_; }
    const std::vector<CanonicalClosureNegativeClosureRecord>& canonicalClosureNegativeClosure() const { return canonicalClosureNegativeClosure_; }
    const std::vector<RomByteClosureRecord>& canonicalClosureClosureBytes() const { return canonicalClosureClosureBytes_; }
    const std::vector<CanonicalClosureResidualRecord>& canonicalClosureFinalResidual() const { return canonicalClosureFinalResidual_; }
    std::vector<std::string> canonicalClosureClosureLines() const;
    const std::vector<RomReconstructionReconstructionByteRecord>& romReconstructionReconstructionLedger() const { return romReconstructionReconstructionLedger_; }
    const std::vector<RomReconstructionReconstructionMapRecord>& romReconstructionReconstructionMap() const { return romReconstructionReconstructionMap_; }
    const std::vector<RomReconstructionBinaryDiffRecord>& romReconstructionBinaryDiff() const { return romReconstructionBinaryDiff_; }
    const std::vector<std::uint8_t>& romReconstructionRebuiltBytes() const { return romReconstructionRebuiltBytes_; }
    std::vector<std::string> romReconstructionReconstructionLines() const;
    const RomRebuildResult& romRebuilderRebuildResult() const { return romRebuilderRebuildResult_; }
    std::vector<std::string> romRebuilderRebuilderLines() const;
    const std::vector<GeneratedOperation>& generatedCodeGeneratedOperations() const { return generatedCodeGeneratedOperations_; }
    const std::vector<GeneratedBlock>& generatedCodeGeneratedBlocks() const { return generatedCodeGeneratedBlocks_; }
    const std::vector<GeneratedSourceRecord>& generatedCodeGeneratedSourceMap() const { return generatedCodeGeneratedSourceMap_; }
    const std::vector<GeneratedCodeDifferentialRecord>& generatedCodeDifferentialRecords() const { return generatedCodeDifferentialRecords_; }
    std::vector<std::string> generatedCodeGeneratedCppLines() const;
    const std::vector<PlatformDependencyRecord>& platformContractDependencies() const { return platformContractDependencies_; }
    const std::vector<PlatformServiceContract>& platformContractServiceContracts() const { return platformContractServiceContracts_; }
    const std::vector<PlatformBoundaryValidationRecord>& platformContractBoundaryValidation() const { return platformContractBoundaryValidation_; }
    std::vector<std::string> platformContractAbstractionLines() const;
    const std::vector<RuntimeNativeClassRecord>& nativeRuntimeNativeClasses() const { return nativeRuntimeNativeClasses_; }
    const std::vector<RuntimeValidationRecord>& nativeRuntimeValidation() const { return nativeRuntimeValidation_; }
    std::vector<std::string> nativeRuntimeNativeFoundationLines() const;
    const std::vector<VideoNativeClassRecord>& nativeVideoNativeClasses() const { return nativeVideoNativeClasses_; }
    const std::vector<VideoValidationRecord>& nativeVideoValidation() const { return nativeVideoValidation_; }
    const std::vector<VideoValidationRecord>& nativeVideoCanonicalValidation() const { return nativeVideoCanonicalValidation_; }
    std::vector<std::string> nativeVideoNativeVideoLines() const;
    void runNativeVideoCanonicalAssetValidation(const RomSet& set);
    const std::vector<AudioNativeClassRecord>& nativeAudioNativeClasses() const { return nativeAudioNativeClasses_; }
    const std::vector<AudioValidationRecord>& nativeAudioValidation() const { return nativeAudioValidation_; }
    const std::vector<AudioValidationRecord>& nativeAudioCanonicalValidation() const { return nativeAudioCanonicalValidation_; }
    std::vector<std::string> nativeAudioNativeAudioLines() const;
    void runNativeAudioCanonicalAssetValidation(const RomSet& set);
    const std::vector<IntegrationStateMapRecord>& nativeIntegrationStateMap() const { return nativeIntegrationStateMap_; }
    const std::vector<IntegrationExecutionLedgerRecord>& nativeIntegrationExecutionLedger() const { return nativeIntegrationExecutionLedger_; }
    const std::vector<IntegrationValidationRecord>& nativeIntegrationValidation() const { return nativeIntegrationValidation_; }
    const std::vector<IntegrationValidationRecord>& nativeIntegrationCanonicalValidation() const { return nativeIntegrationCanonicalValidation_; }
    std::vector<std::string> nativeIntegrationNativeIntegrationLines() const;
    void runNativeIntegrationCanonicalIntegrationValidation(const RomSet& set);
    const std::vector<CoreCoverageRecord>& coreCoverageLedger() const { return coreCoverageLedger_; }
    const std::vector<CoreValidationRecord>& coreDifferentialValidation() const { return coreDifferentialValidation_; }
    const std::vector<CoreValidationRecord>& coreCanonicalValidation() const { return coreCanonicalValidation_; }
    std::vector<std::string> coreNativeLogicLines() const;
    void runCoreCanonicalIntegrationValidation(const RomSet& set);
    const std::vector<LifecycleSchedulerCoverageRecord>& lifecycleSchedulerCoverageLedger() const { return lifecycleSchedulerCoverageLedger_; }
    const std::vector<LifecycleSchedulerValidationRecord>& lifecycleSchedulerDifferentialValidation() const { return lifecycleSchedulerDifferentialValidation_; }
    const std::vector<LifecycleSchedulerValidationRecord>& lifecycleSchedulerCanonicalValidation() const { return lifecycleSchedulerCanonicalValidation_; }
    std::vector<std::string> lifecycleSchedulerNativeLogicLines() const;
    void runLifecycleSchedulerCanonicalIntegrationValidation(const RomSet& set);
    const std::vector<CreditStartCoverageRecord>& creditStartCoverageLedger() const { return creditStartCoverageLedger_; }
    const std::vector<CreditStartValidationRecord>& creditStartDifferentialValidation() const { return creditStartDifferentialValidation_; }
    const std::vector<CreditStartValidationRecord>& creditStartCanonicalValidation() const { return creditStartCanonicalValidation_; }
    std::vector<std::string> creditStartNativeLogicLines() const;
    void runCreditStartCanonicalIntegrationValidation(const RomSet& set);
    const std::vector<SessionInitializationCoverageRecord>& sessionInitializationCoverageLedger() const { return sessionInitializationCoverageLedger_; }
    const std::vector<SessionInitializationValidationRecord>& sessionInitializationDifferentialValidation() const { return sessionInitializationDifferentialValidation_; }
    const std::vector<SessionInitializationValidationRecord>& sessionInitializationCanonicalValidation() const { return sessionInitializationCanonicalValidation_; }
    std::vector<std::string> sessionInitializationNativeLogicLines() const;
    void runSessionInitializationCanonicalIntegrationValidation(const RomSet& set);
    const std::vector<MazePreparationCoverageRecord>& mazePreparationCoverageLedger() const { return mazePreparationCoverageLedger_; }
    const std::vector<MazePreparationValidationRecord>& mazePreparationDifferentialValidation() const { return mazePreparationDifferentialValidation_; }
    const std::vector<MazePreparationValidationRecord>& mazePreparationCanonicalValidation() const { return mazePreparationCanonicalValidation_; }
    std::vector<std::string> mazePreparationNativeLogicLines() const;
    void runMazePreparationCanonicalIntegrationValidation(const RomSet& set);
    const std::vector<DisplayMapCoverageRecord>& displayMapCoverageLedger() const { return displayMapCoverageLedger_; }
    const std::vector<DisplayMapValidationRecord>& displayMapDifferentialValidation() const { return displayMapDifferentialValidation_; }
    const std::vector<DisplayMapValidationRecord>& displayMapCanonicalValidation() const { return displayMapCanonicalValidation_; }
    std::vector<std::string> displayMapNativeLogicLines() const;
    void runDisplayMapCanonicalIntegrationValidation(const RomSet& set);
    const std::vector<HudBoardCoverageRecord>& hudBoardCoverageLedger() const { return hudBoardCoverageLedger_; }
    const std::vector<HudBoardValidationRecord>& hudBoardDifferentialValidation() const { return hudBoardDifferentialValidation_; }
    const std::vector<HudBoardValidationRecord>& hudBoardCanonicalValidation() const { return hudBoardCanonicalValidation_; }
    std::vector<std::string> hudBoardNativeLogicLines() const;
    void runHudBoardCanonicalIntegrationValidation(const RomSet& set);
    const std::vector<BoardInterpreterCoverageRecord>& boardInterpreterCoverageLedger() const { return boardInterpreterCoverageLedger_; }
    const std::vector<BoardInterpreterValidationRecord>& boardInterpreterDifferentialValidation() const { return boardInterpreterDifferentialValidation_; }
    std::vector<std::string> boardInterpreterNativeLogicLines() const;
    const std::vector<CommandInterpreterCoverageRecord>& commandInterpreterCoverageLedger() const { return commandInterpreterCoverageLedger_; }
    const std::vector<CommandInterpreterValidationRecord>& commandInterpreterDifferentialValidation() const { return commandInterpreterDifferentialValidation_; }
    std::vector<std::string> commandInterpreterNativeLogicLines() const;
    const std::vector<RstUtilityCoverageRecord>& rstUtilityCoverageLedger() const { return rstUtilityCoverageLedger_; }
    const std::vector<RstUtilityValidationRecord>& rstUtilityDifferentialValidation() const { return rstUtilityDifferentialValidation_; }
    std::vector<std::string> rstUtilityNativeLogicLines() const;
    const std::vector<SchedulerUtilityCoverageRecord>& schedulerUtilityCoverageLedger() const { return schedulerUtilityCoverageLedger_; }
    const std::vector<SchedulerUtilityValidationRecord>& schedulerUtilityDifferentialValidation() const { return schedulerUtilityDifferentialValidation_; }
    std::vector<std::string> schedulerUtilityNativeLogicLines() const;
    const std::vector<GraphicCreditCoverageRecord>& graphicCreditCoverageLedger() const { return graphicCreditCoverageLedger_; }
    const std::vector<GraphicCreditValidationRecord>& graphicCreditDifferentialValidation() const { return graphicCreditDifferentialValidation_; }
    std::vector<std::string> graphicCreditNativeLogicLines() const;
    const std::vector<FrameUpdateCoverageRecord>& frameUpdateCoverageLedger() const { return frameUpdateCoverageLedger_; }
    const std::vector<FrameUpdateValidationRecord>& frameUpdateDifferentialValidation() const { return frameUpdateDifferentialValidation_; }
    std::vector<std::string> frameUpdateNativeLogicLines() const;
    const std::vector<ObjectInputCoverageRecord>& objectInputCoverageLedger() const { return objectInputCoverageLedger_; }
    const std::vector<ObjectInputValidationRecord>& objectInputDifferentialValidation() const { return objectInputDifferentialValidation_; }
    std::vector<std::string> objectInputNativeLogicLines() const;
    const std::vector<FrameHelperCoverageRecord>& frameHelperCoverageLedger() const { return frameHelperCoverageLedger_; }
    const std::vector<FrameHelperValidationRecord>& frameHelperDifferentialValidation() const { return frameHelperDifferentialValidation_; }
    std::vector<std::string> frameHelperNativeLogicLines() const;
    const std::vector<CoordinateRenderCoverageRecord>& coordinateRenderCoverageLedger() const { return coordinateRenderCoverageLedger_; }
    const std::vector<CoordinateRenderValidationRecord>& coordinateRenderDifferentialValidation() const { return coordinateRenderDifferentialValidation_; }
    std::vector<std::string> coordinateRenderNativeLogicLines() const;
    const std::vector<StartupUtilityCoverageRecord>& startupUtilityCoverageLedger() const { return startupUtilityCoverageLedger_; }
    const std::vector<StartupUtilityValidationRecord>& startupUtilityDifferentialValidation() const { return startupUtilityDifferentialValidation_; }
    std::vector<std::string> startupUtilityNativeLogicLines() const;
    const std::vector<StartupRuntimeCoverageRecord>& startupRuntimeCoverageLedger() const { return startupRuntimeCoverageLedger_; }
    const std::vector<StartupRuntimeValidationRecord>& startupRuntimeDifferentialValidation() const { return startupRuntimeDifferentialValidation_; }
    std::vector<std::string> startupRuntimeNativeLogicLines() const;
    const std::vector<InterruptSchedulerCoverageRecord>& interruptSchedulerCoverageLedger() const { return interruptSchedulerCoverageLedger_; }
    const std::vector<InterruptSchedulerValidationRecord>& interruptSchedulerDifferentialValidation() const { return interruptSchedulerDifferentialValidation_; }
    std::vector<std::string> interruptSchedulerNativeLogicLines() const;
    const std::vector<SystemUtilityCoverageRecord>& systemUtilityCoverageLedger() const { return systemUtilityCoverageLedger_; }
    const std::vector<SystemUtilityValidationRecord>& systemUtilityDifferentialValidation() const { return systemUtilityDifferentialValidation_; }
    std::vector<std::string> systemUtilityNativeLogicLines() const;
    const std::vector<StartupSelfTestCoverageRecord>& startupSelfTestCoverageLedger() const { return startupSelfTestCoverageLedger_; }
    const std::vector<StartupSelfTestValidationRecord>& startupSelfTestDifferentialValidation() const { return startupSelfTestDifferentialValidation_; }
    std::vector<std::string> startupSelfTestNativeLogicLines() const;
    const std::vector<ColdStateCoverageRecord>& coldStateCoverageLedger() const { return coldStateCoverageLedger_; }
    const std::vector<ColdStateValidationRecord>& coldStateDifferentialValidation() const { return coldStateDifferentialValidation_; }
    std::vector<std::string> coldStateNativeLogicLines() const;
    const std::vector<ColdHelperCoverageRecord>& coldHelperCoverageLedger() const { return coldHelperCoverageLedger_; }
    const std::vector<ColdHelperValidationRecord>& coldHelperDifferentialValidation() const { return coldHelperDifferentialValidation_; }
    std::vector<std::string> coldHelperNativeLogicLines() const;
    const std::vector<CoordinateDispatchCoverageRecord>& coordinateDispatchCoverageLedger() const { return coordinateDispatchCoverageLedger_; }
    const std::vector<CoordinateDispatchValidationRecord>& coordinateDispatchDifferentialValidation() const { return coordinateDispatchDifferentialValidation_; }
    std::vector<std::string> coordinateDispatchNativeLogicLines() const;
    const std::vector<IntermissionStateCoverageRecord>& intermissionStateCoverageLedger() const { return intermissionStateCoverageLedger_; }
    const std::vector<IntermissionStateValidationRecord>& intermissionStateDifferentialValidation() const { return intermissionStateDifferentialValidation_; }
    std::vector<std::string> intermissionStateNativeLogicLines() const;
    const std::vector<SystemRootPrimaryCoverageRecord>& systemRootPrimaryCoverageLedger() const { return systemRootPrimaryCoverageLedger_; }
    const std::vector<SystemRootPrimaryValidationRecord>& systemRootPrimaryDifferentialValidation() const { return systemRootPrimaryDifferentialValidation_; }
    std::vector<std::string> systemRootPrimaryNativeLogicLines() const;
    const std::vector<SystemRootSecondaryCoverageRecord>& systemRootSecondaryCoverageLedger() const { return systemRootSecondaryCoverageLedger_; }
    const std::vector<SystemRootSecondaryValidationRecord>& systemRootSecondaryDifferentialValidation() const { return systemRootSecondaryDifferentialValidation_; }
    std::vector<std::string> systemRootSecondaryNativeLogicLines() const;
    const std::vector<InterruptLatchCoverageRecord>& interruptLatchCoverageLedger() const { return interruptLatchCoverageLedger_; }
    const std::vector<InterruptLatchValidationRecord>& interruptLatchDifferentialValidation() const { return interruptLatchDifferentialValidation_; }
    std::vector<std::string> interruptLatchNativeLogicLines() const;
    const std::vector<RomByteClosureRecord>& rootContextClosureBytes() const { return rootContextClosureBytes_; }

    std::vector<std::string> cfgLines() const;
    std::vector<std::string> irLines() const;
    std::vector<std::string> pseudocodeLines() const;
    std::vector<std::string> structuredPseudocodeLines() const;
    std::vector<std::string> valuePropagationLines() const;
    std::vector<std::string> structureLines() const;
    std::vector<std::string> dominatorLines() const;
    std::vector<std::string> postDominatorLines() const;
    std::vector<std::string> loopLines() const;
    std::vector<std::string> stackModelLines() const;
    std::vector<std::string> callReturnLines() const;
    std::vector<std::string> conditionSemanticsLines() const;
    std::vector<std::string> romClosureLines() const;
    std::vector<std::string> romConsumerLines() const;
    std::vector<std::string> ramPairLines() const;
    std::vector<std::string> romObjectLines() const;
    std::vector<std::string> pointerChainLines() const;
    std::vector<std::string> calleeSummaryLines() const;
    std::vector<std::string> unresolvedPriorityLines() const;
    std::vector<std::string> defUseLines() const;
    std::vector<std::string> expressionLines() const;
    std::vector<std::string> ramObjectLines() const;
    std::vector<std::string> xrefLines() const;
    std::vector<std::string> hardwareLines() const;
    std::vector<std::string> memoryXrefLines() const;
    std::vector<std::string> ramShapeLines() const;
    std::vector<std::string> typeEvidenceLines() const;
    std::vector<std::string> tableSchemaLines() const;
    std::vector<std::string> routineContractLines() const;
    std::vector<std::string> valueFlowLines() const;
    std::vector<std::string> callBindingLines() const;
    std::vector<std::string> typedPseudocodeLines() const;
    std::vector<std::string> routineBehaviorLines() const;
    std::vector<std::string> structuredValueLines() const;
    std::vector<std::string> routineRoleLines() const;
    std::vector<std::string> routineClusterLines() const;
    std::vector<std::string> routineNavigationLines() const;
    std::vector<std::string> residualAuditLines() const;
    std::vector<std::string> objectRoleLines() const;
    std::vector<std::string> stateXrefLines() const;
    std::vector<std::string> residualPriorityV2Lines() const;
    std::vector<std::string> indirectMemoryLines() const;
    std::vector<std::string> addressRangeLines() const;
    std::vector<std::string> indirectRomConsumerLines() const;
    std::vector<std::string> indirectAddressClosureLines() const;
    std::vector<std::string> romDecoderLines() const;
    std::vector<std::string> streamFamilyLines() const;
    std::vector<std::string> highRomObjectLines() const;
    std::vector<std::string> semanticCoverageLines() const;
    std::vector<std::string> highRomClosureLines() const;
    std::vector<std::string> highRomResidualPriorityV2Lines() const;
    std::vector<std::string> negativeRomEvidenceLines() const;
    std::vector<std::string> unusedRomRegionLines() const;
    std::vector<std::string> residualReferenceClosureLines() const;
    std::vector<std::string> systemRootLines() const;
    std::vector<std::string> systemRootReachabilityLines() const;
    std::vector<std::string> indirectRefinementLines() const;
    std::vector<std::string> systemRootNegativeRomEvidenceLines() const;
    std::vector<std::string> systemRootClosureLines() const;
    std::vector<std::string> rootContextAddressContextLines() const;
    std::vector<std::string> rootContextAddressProofLines() const;
    std::vector<std::string> rootContextNegativeRomEvidenceLines() const;
    std::vector<std::string> rootContextClosureLines() const;
    std::vector<std::string> memoryAliasWriterProofLines() const;
    std::vector<std::string> memoryAliasWriterAliasLines() const;
    std::vector<std::string> memoryAliasAddressProofLines() const;
    std::vector<std::string> memoryAliasClosureLines() const;
    std::vector<std::string> commandStreamWriterAliasLines() const;
    std::vector<std::string> commandStreamValueProofLines() const;
    std::vector<std::string> commandStreamCommandStreamLines() const;
    std::vector<std::string> commandStreamAddressProofLines() const;
    std::vector<std::string> commandStreamClosureLines() const;
    std::vector<std::string> mazeTopologyTopologyInputLines() const;
    std::vector<std::string> mazeTopologyDirectionCandidateLines() const;
    std::vector<std::string> mazeTopologyRetryLoopProofLines() const;
    std::vector<std::string> mazeTopologyAddressProofLines() const;
    std::vector<std::string> mazeTopologyResidualClassificationLines() const;
    std::vector<std::string> mazeTopologyClosureLines() const;
    std::vector<std::string> intermissionDispatchProofLines() const;
    std::vector<std::string> intermissionWriterProofLines() const;
    std::vector<std::string> intermissionLifecycleProofLines() const;
    std::vector<std::string> intermissionAddressProofLines() const;
    std::vector<std::string> intermissionClosureLines() const;
    std::vector<std::string> residualExtentResidualAuditLines() const;
    std::vector<std::string> residualExtentExtentProofLines() const;
    std::vector<std::string> residualExtentNegativeReferenceLines() const;
    std::vector<std::string> residualExtentClosureLines() const;
    std::vector<std::string> im2VectorOutputInventoryLines() const;
    std::vector<std::string> im2VectorCpuModeProofLines() const;
    std::vector<std::string> im2VectorVectorDomainLines() const;
    std::vector<std::string> im2VectorClosureLines() const;
    std::vector<std::string> semanticLiftProvenanceLines() const;
    std::vector<std::string> semanticLiftLiftLines() const;
    std::vector<std::string> semanticLiftDifferentialLines() const;
    std::vector<std::string> semanticOracleSemanticCoverageLines() const;
    std::vector<std::string> semanticOracleOracleLines() const;
    std::vector<std::string> semanticOracleGeneratedSourceMapLines() const;
    std::vector<std::string> reconciliationReconciliationLines() const;
    bool exportAll(const std::string& outputDir,std::string& error) const;

private:
    std::uint16_t continuationAfter(const Instruction& in) const;
    void discoverLeaders(std::set<std::uint16_t>& leaders);
    void buildBlocks(const std::set<std::uint16_t>& leaders);
    void buildEdges();
    void buildFunctions();
    void propagateValues();
    void buildConditionSemantics();
    void buildRomClosure();
    void buildObjectPointerObjects();
    void buildDefUse();
    void buildHardwareSemantic();
    void buildTypeContract();
    void buildContractValue();
    void buildStructuredExpression();
    void buildResidualClosure();
    void buildIndirectAddress();
    void buildHighRom();
    void buildResidualReference();
    void buildSystemRoot();
    void buildRootContext();
    void buildMemoryAlias();
    void buildCommandStream();
    void buildMazeTopology();
    void buildIntermission();
    void buildResidualExtent();
    void buildIm2Vector();
    void buildSemanticLift();
    void buildSemanticOracle();
    void buildReconciliation();
    void buildCanonicalSemantic();
    void buildCanonicalClosure();
    void buildRomReconstruction();
    void buildRomRebuilder();
    void buildGeneratedCode();
    void buildPlatformContract();
    void buildNativeRuntime();
    void buildNativeVideo();
    void buildNativeAudio();
    void buildNativeIntegration();
    void buildCore();
    void buildLifecycleScheduler();
    void buildCreditStart();
    void buildSessionInitialization();
    void buildMazePreparation();
    void buildDisplayMap();
    void buildHudBoard();
    void buildBoardInterpreter();
    void buildCommandInterpreter();
    void buildRstUtility();
    void buildSchedulerUtility();
    void buildGraphicCredit();
    void buildFrameUpdate();
    void buildObjectInput();
    void buildFrameHelper();
    void buildCoordinateRender();
    void buildStartupUtility();
    void buildStartupRuntime();
    void buildInterruptScheduler();
    void buildSystemUtility();
    void buildStartupSelfTest();
    void buildColdState();
    void buildColdHelper();
    void buildCoordinateDispatch();
    void buildIntermissionState();
    void buildSystemRootPrimary();
    void buildSystemRootSecondary();
    void buildInterruptLatch();
    void appendDefUseExpressionComments(std::vector<std::string>& out,std::uint16_t address,const std::string& indent) const;
    void appendHardwareSemanticHardwareComments(std::vector<std::string>& out,std::uint16_t address,const std::string& indent) const;
    void appendTypeContractTypeComments(std::vector<std::string>& out,std::uint16_t address,const std::string& indent) const;
    void buildFunctionRegisterSummaries();
    void buildInterproceduralPointerClosure();
    void recomputeRomClosureStats();
    void buildStructure();
    void buildStackModel();
    void buildCallReturnEvidence();
    StructuralGraph structuralGraphFor(std::uint16_t functionEntry) const;
    std::map<std::uint16_t,BranchDescriptor> branchDescriptorsFor(const StructuralGraph& graph) const;
    bool isStructuralEdge(CfgEdgeKind kind) const;
    RegisterState transferBlock(const BasicBlock& block,const RegisterState& entry) const;
    void transferInstruction(const Instruction& in,RegisterState& state) const;
    bool mergeState(RegisterState& dst,const RegisterState& src,bool initialized) const;
    std::string edgeKindText(CfgEdgeKind kind) const;
    std::string conditionFor(const Instruction& in) const;
    std::string renderedConditionFor(const Instruction& in) const;
    std::string blockName(std::uint16_t start) const;
    std::string functionName(std::uint16_t entry) const;
    std::string valueText(const AbstractValue& v) const;
    std::string stateText(const RegisterState& s) const;
    std::vector<std::string> instructionIR(const Instruction& in) const;
    std::string operandWithSymbols(const std::string& operand) const;
    bool isFunctionEntry(std::uint16_t address) const;
    void appendStructuredRegionLines(std::vector<std::string>& out,const StructuredRegion& region,
                                     const std::string& indent) const;
    void appendStructuredBlockLines(std::vector<std::string>& out,std::uint16_t block,
                                    const std::string& indent,bool skipProvingBranch=false,
                                    std::uint16_t provingAddress=0) const;
    std::string addressSetText(const std::set<std::uint16_t>& values) const;

    bool ready_=false;
    const Analyzer* analyzer_=nullptr;
    std::map<std::uint16_t,BasicBlock> blocks_;
    std::map<std::uint16_t,FunctionModel> functions_;
    std::map<std::uint16_t,std::uint16_t> instructionToBlock_;
    std::set<std::uint16_t> functionEntries_;
    std::map<std::uint16_t,StructureAnalysis> structures_;
    std::map<std::uint16_t,StackBlockInfo> stackBlocks_;
    std::vector<CallSiteRecord> callSites_;
    std::vector<ObservedReturnRecord> observedReturns_;
    std::vector<ReturnEvidenceMatch> returnMatches_;
    std::map<std::uint16_t,FunctionCallReturnEvidence> callReturnEvidence_;
    std::map<std::uint16_t,ConditionEvidenceRecord> conditionEvidence_;
    std::vector<RomConsumerRecord> romConsumers_;
    std::vector<RomByteClosureRecord> romClosureBytes_;
    std::vector<RamPairEvidenceRecord> ramPairEvidence_;
    std::vector<RomObjectRecord> romObjects_;
    std::vector<RomPointerLinkRecord> romPointerLinks_;
    std::map<std::uint16_t,FunctionRegisterSummary> functionRegisterSummaries_;
    std::vector<UnresolvedPrioritySpan> unresolvedPriority_;
    DefUseResult defUseResult_;
    std::vector<RamObjectRecord> ramObjects_;
    std::vector<RomConsumerRecord> defUseRomConsumers_;
    std::vector<RomByteClosureRecord> defUseClosureBytes_;
    std::vector<UnresolvedPrioritySpan> defUseUnresolvedPriority_;
    std::vector<HardwareAccessRecord> hardwareAccesses_;
    std::vector<MemoryXrefRecord> memoryXrefs_;
    std::vector<RamShapeRecord> ramShapes_;
    std::vector<TypeEvidenceRecord> typeEvidence_;
    std::vector<TableSchemaRecord> tableSchemas_;
    std::vector<RoutineContractRecord> routineContracts_;
    std::vector<MachineValueRecord> machineValues_;
    std::vector<MergeValueRecord> mergeValues_;
    std::vector<CallBindingRecord> callBindings_;
    std::vector<TypedValueRecord> typedValues_;
    std::vector<IndexedExpressionRecord> indexedExpressions_;
    std::vector<LiftedStatementRecord> liftedStatements_;
    std::vector<RoutineBehaviorRecord> routineBehaviors_;
    std::vector<StructuredExpressionRegionRecord> structuredValueRegions_;
    std::vector<TemporaryElisionRecord> temporaryElisions_;
    std::vector<CallContinuityRecord> callContinuities_;
    std::vector<RoutineRoleSignatureRecord> routineRoles_;
    std::vector<RoutineSimilarityRecord> routineSimilarities_;
    std::vector<RoutineClusterRecord> routineClusters_;
    std::vector<RoutineNavigationRecord> routineNavigation_;
    std::vector<DormantCodeSeedRecord> dormantCodeSeeds_;
    std::vector<DormantCodeDiscoveryRecord> dormantCodeDiscoveries_;
    std::vector<RomExtentRefinementRecord> romExtentRefinements_;
    std::vector<ResidualAuditRecord> residualAudit_;
    std::vector<ObjectRoleRecord> objectRoles_;
    std::vector<StateXrefRecord> stateXrefs_;
    std::vector<ResidualPriorityV2Record> residualPriorityV2_;
    std::vector<RomByteClosureRecord> residualClosureClosureBytes_;
    std::vector<RomObjectRecord> residualClosureRomObjects_;
    std::vector<IndirectMemoryAccessRecord> indirectMemoryAccesses_;
    std::vector<IndirectRomConsumerProofRecord> indirectRomConsumerProofs_;
    std::vector<IndirectAddressClosureProvenanceRecord> indirectAddressClosureProvenance_;
    std::vector<RomByteClosureRecord> indirectAddressClosureBytes_;
    std::vector<ResidualAuditRecord> indirectAddressResidualAudit_;
    std::vector<ResidualPriorityV2Record> indirectAddressResidualPriorityV2_;
    std::vector<RomDecoderRecord> romDecoders_;
    std::vector<PointerTableDomainRecord> pointerTableDomains_;
    std::vector<StreamSemanticRecord> streamSemantics_;
    std::vector<StreamFamilyRecord> streamFamilies_;
    std::vector<FixedRecordSemanticRecord> fixedRecordSemantics_;
    std::vector<BoundedBlockSemanticRecord> boundedBlockSemantics_;
    std::vector<HighRomClosureProvenanceRecord> highRomClosureProvenance_;
    std::vector<RomByteClosureRecord> highRomClosureBytes_;
    std::vector<HighRomResidualAuditRecord> highRomResidualAudit_;
    std::vector<ResidualPriorityV2Record> highRomResidualPriorityV2_;
    DecompilerStats stats_;
    // residual-reference analysis fields are intentionally appended after the verified the established analysis pipeline
    // object layout. This keeps earlier field offsets stable and makes the
    // additive-overlay boundary explicit in both source and validation builds.
    std::vector<SystemRomSemanticRecord> systemRomSemantics_;
    std::vector<NegativeReferenceRecord> negativeReferenceEvidence_;
    std::vector<UnusedRomRegionRecord> unusedRomRegions_;
    std::vector<SemanticOverlapRecord> residualReferenceSemanticOverlaps_;
    std::vector<ResidualReferenceClosureProvenanceRecord> residualReferenceClosureProvenance_;
    std::vector<RomByteClosureRecord> residualReferenceClosureBytes_;
    // system-root reachability analysis is another additive overlay. the established analysis pipeline containers above remain
    // verified and are never rewritten by system-root reachability/refinement.
    std::vector<SystemRootRecord> systemRoots_;
    std::vector<SystemRootReachabilityRecord> systemRootReachability_;
    std::vector<SystemRootInlineDataRecord> systemRootInlineData_;
    std::vector<IndirectAddressRefinementRecord> indirectAddressRefinements_;
    std::vector<SystemRootNegativeReferenceRecord> systemRootNegativeReferenceEvidence_;
    std::vector<UnusedRomRegionRecord> systemRootUnusedRomRegions_;
    std::vector<SystemRootClosureProvenanceRecord> systemRootClosureProvenance_;
    std::vector<RomByteClosureRecord> systemRootClosureBytes_;
    // context-sensitive root analysis remains additive: all the established analysis pipeline containers above are verified.
    std::vector<RootContextAddressContextRecord> rootContextAddressContexts_;
    std::vector<RootContextAddressProofRecord> rootContextAddressProofs_;
    std::vector<RootContextNegativeReferenceRecord> rootContextNegativeReferenceEvidence_;
    std::vector<UnusedRomRegionRecord> rootContextUnusedRomRegions_;
    std::vector<RootContextClosureProvenanceRecord> rootContextClosureProvenance_;
    std::vector<RomByteClosureRecord> rootContextClosureBytes_;
    // memory-alias analysis remains additive: the established analysis pipeline evidence above is verified.
    std::vector<RootContextAddressContextRecord> memoryAliasWriterContexts_;
    std::vector<RootContextAddressProofRecord> memoryAliasWriterProofs_;
    std::vector<MemoryAliasWriterAliasRecord> memoryAliasWriterAliases_;
    std::vector<MemoryAliasAddressProofRecord> memoryAliasAddressProofs_;
    std::vector<MemoryAliasClosureProvenanceRecord> memoryAliasClosureProvenance_;
    std::vector<RomByteClosureRecord> memoryAliasClosureBytes_;
    // command-stream memory analysis remains additive: the established analysis pipeline evidence above is verified.
    std::vector<CommandStreamWriterAliasRecord> commandStreamWriterAliases_;
    std::vector<CommandStreamValueProofRecord> commandStreamValueProofs_;
    std::vector<CommandStreamCommandStreamRecord> commandStreamCommandStreams_;
    std::vector<CommandStreamAddressProofRecord> commandStreamAddressProofs_;
    std::vector<CommandStreamClosureProvenanceRecord> commandStreamClosureProvenance_;
    std::vector<RomByteClosureRecord> commandStreamClosureBytes_;
    std::vector<MazeTopologyTopologyInputRecord> mazeTopologyTopologyInputs_;
    std::vector<MazeTopologyDirectionCandidateRecord> mazeTopologyDirectionCandidates_;
    std::vector<MazeTopologyRetryLoopProofRecord> mazeTopologyRetryLoopProofs_;
    std::vector<MazeTopologyAddressProofRecord> mazeTopologyAddressProofs_;
    std::vector<MazeTopologyResidualClassificationRecord> mazeTopologyResidualClassification_;
    std::vector<MazeTopologyClosureProvenanceRecord> mazeTopologyClosureProvenance_;
    std::vector<RomByteClosureRecord> mazeTopologyClosureBytes_;
    // intermission analysis closes the intermission lifecycle proof and remains additive to maze-topology analysis.
    std::vector<IntermissionDispatchProofRecord> intermissionDispatchProofs_;
    std::vector<IntermissionVideoWriterProofRecord> intermissionWriterProofs_;
    std::vector<IntermissionLifecycleProofRecord> intermissionLifecycleProofs_;
    std::vector<IntermissionAddressProofRecord> intermissionAddressProofs_;
    std::vector<IntermissionClosureProvenanceRecord> intermissionClosureProvenance_;
    std::vector<RomByteClosureRecord> intermissionClosureBytes_;
    // residual-extent analysis performs residual object-extent audit and exhaustive static negative-reference closure.
    std::vector<ResidualExtentResidualAuditRecord> residualExtentResidualAudit_;
    std::vector<ResidualExtentExtentProofRecord> residualExtentExtentProofs_;
    std::vector<ResidualExtentNegativeReferenceRecord> residualExtentNegativeReferenceProofs_;
    std::vector<ResidualExtentUnusedRegionRecord> residualExtentUnusedRegions_;
    std::vector<ResidualExtentClosureProvenanceRecord> residualExtentClosureProvenance_;
    std::vector<ResidualExtentFinalResidualRecord> residualExtentFinalResidual_;
    std::vector<RomByteClosureRecord> residualExtentClosureBytes_;
    // IM2/vector-domain analysis proves the complete rooted IM2 vector-latch domain and may close the final ROM tail.
    std::vector<Im2VectorOutputInventoryRecord> im2VectorOutputInventory_;
    std::vector<Im2VectorCpuModeProofRecord> im2VectorCpuModeProofs_;
    std::vector<Im2VectorVectorDomainProofRecord> im2VectorVectorDomainProofs_;
    std::vector<Im2VectorSystemNegativeRecord> im2VectorSystemNegativeProofs_;
    std::vector<Im2VectorClosureProvenanceRecord> im2VectorClosureProvenance_;
    std::vector<Im2VectorFinalResidualRecord> im2VectorFinalResidual_;
    std::vector<RomByteClosureRecord> im2VectorClosureBytes_;
    // semantic-lift engine adds a source-PC-preserving semantic lift and whole-ROM provenance audit.
    std::vector<SemanticRomProvenanceRecord> semanticLiftProvenanceLedger_;
    std::vector<SemanticLiftedOperation> semanticLiftLiftedOperations_;
    std::vector<SemanticLiftedBlock> semanticLiftLiftedBlocks_;
    std::vector<SemanticDifferentialRecord> semanticLiftDifferentialRecords_;
    // semantic-oracle analysis is additive: semantic-lift engine records above stay verified byte-for-byte.
    std::vector<SemanticOracleLiftedOperation> semanticOracleLiftedOperations_;
    std::vector<SemanticOracleLiftedBlock> semanticOracleLiftedBlocks_;
    std::vector<SemanticOracleOracleRecord> semanticOracleOracleRecords_;
    std::vector<SemanticOracleGeneratedSourceRecord> semanticOracleGeneratedSourceMap_;
    std::vector<ReconciliationCanonicalInstructionRecord> reconciliationCanonicalInstructions_;
    std::vector<RomByteClosureRecord> reconciliationClosureBytes_;
    std::vector<ReconciliationResidualRecord> reconciliationFinalResidual_;
    std::vector<CanonicalSemanticLiftedOperation> canonicalSemanticLiftedOperations_;
    std::vector<CanonicalSemanticLiftedBlock> canonicalSemanticLiftedBlocks_;
    std::vector<CanonicalSemanticOracleRecord> canonicalSemanticOracleRecords_;
    std::vector<CanonicalSemanticSelectorDomainRecord> canonicalSemanticSelectorDomains_;
    std::vector<CanonicalSemanticSelectorReferenceRecord> canonicalSemanticSelectorReferences_;
    std::vector<RomByteClosureRecord> canonicalSemanticClosureBytes_;
    std::vector<CanonicalSemanticResidualRecord> canonicalSemanticFinalResidual_;
    std::vector<CanonicalClosureHighSelectorBoundRecord> canonicalClosureHighSelectorBounds_;
    std::vector<CanonicalClosureCanonicalDataObjectRecord> canonicalClosureCanonicalDataObjects_;
    std::vector<CanonicalClosureNegativeClosureRecord> canonicalClosureNegativeClosure_;
    std::vector<RomByteClosureRecord> canonicalClosureClosureBytes_;
    std::vector<CanonicalClosureResidualRecord> canonicalClosureFinalResidual_;
    std::vector<RomReconstructionReconstructionByteRecord> romReconstructionReconstructionLedger_;
    std::vector<RomReconstructionReconstructionMapRecord> romReconstructionReconstructionMap_;
    std::vector<RomReconstructionBinaryDiffRecord> romReconstructionBinaryDiff_;
    std::vector<std::uint8_t> romReconstructionRebuiltBytes_;
    RomRebuildResult romRebuilderRebuildResult_;
    std::vector<GeneratedOperation> generatedCodeGeneratedOperations_;
    std::vector<GeneratedBlock> generatedCodeGeneratedBlocks_;
    std::vector<GeneratedSourceRecord> generatedCodeGeneratedSourceMap_;
    std::vector<GeneratedCodeDifferentialRecord> generatedCodeDifferentialRecords_;
    std::vector<PlatformDependencyRecord> platformContractDependencies_;
    std::vector<PlatformServiceContract> platformContractServiceContracts_;
    std::vector<PlatformBoundaryValidationRecord> platformContractBoundaryValidation_;
    std::vector<RuntimeNativeClassRecord> nativeRuntimeNativeClasses_;
    std::vector<RuntimeValidationRecord> nativeRuntimeValidation_;
    std::vector<VideoNativeClassRecord> nativeVideoNativeClasses_;
    std::vector<VideoValidationRecord> nativeVideoValidation_;
    std::vector<VideoValidationRecord> nativeVideoCanonicalValidation_;
    std::vector<AudioNativeClassRecord> nativeAudioNativeClasses_;
    std::vector<AudioValidationRecord> nativeAudioValidation_;
    std::vector<AudioValidationRecord> nativeAudioCanonicalValidation_;
    std::vector<IntegrationStateMapRecord> nativeIntegrationStateMap_;
    std::vector<IntegrationExecutionLedgerRecord> nativeIntegrationExecutionLedger_;
    std::vector<IntegrationValidationRecord> nativeIntegrationValidation_;
    std::vector<IntegrationValidationRecord> nativeIntegrationCanonicalValidation_;
    std::vector<CoreCoverageRecord> coreCoverageLedger_;
    std::vector<CoreValidationRecord> coreDifferentialValidation_;
    std::vector<CoreValidationRecord> coreCanonicalValidation_;
    std::vector<LifecycleSchedulerCoverageRecord> lifecycleSchedulerCoverageLedger_;
    std::vector<LifecycleSchedulerValidationRecord> lifecycleSchedulerDifferentialValidation_;
    std::vector<LifecycleSchedulerValidationRecord> lifecycleSchedulerCanonicalValidation_;
    std::vector<CreditStartCoverageRecord> creditStartCoverageLedger_;
    std::vector<CreditStartValidationRecord> creditStartDifferentialValidation_;
    std::vector<CreditStartValidationRecord> creditStartCanonicalValidation_;
    std::vector<SessionInitializationCoverageRecord> sessionInitializationCoverageLedger_;
    std::vector<SessionInitializationValidationRecord> sessionInitializationDifferentialValidation_;
    std::vector<SessionInitializationValidationRecord> sessionInitializationCanonicalValidation_;
    std::vector<MazePreparationCoverageRecord> mazePreparationCoverageLedger_;
    std::vector<MazePreparationValidationRecord> mazePreparationDifferentialValidation_;
    std::vector<MazePreparationValidationRecord> mazePreparationCanonicalValidation_;
    std::vector<DisplayMapCoverageRecord> displayMapCoverageLedger_;
    std::vector<DisplayMapValidationRecord> displayMapDifferentialValidation_;
    std::vector<DisplayMapValidationRecord> displayMapCanonicalValidation_;
    std::vector<HudBoardCoverageRecord> hudBoardCoverageLedger_;
    std::vector<HudBoardValidationRecord> hudBoardDifferentialValidation_;
    std::vector<HudBoardValidationRecord> hudBoardCanonicalValidation_;
    std::vector<BoardInterpreterCoverageRecord> boardInterpreterCoverageLedger_;
    std::vector<BoardInterpreterValidationRecord> boardInterpreterDifferentialValidation_;
    std::vector<CommandInterpreterCoverageRecord> commandInterpreterCoverageLedger_;
    std::vector<CommandInterpreterValidationRecord> commandInterpreterDifferentialValidation_;
    std::vector<RstUtilityCoverageRecord> rstUtilityCoverageLedger_;
    std::vector<RstUtilityValidationRecord> rstUtilityDifferentialValidation_;
    std::vector<SchedulerUtilityCoverageRecord> schedulerUtilityCoverageLedger_;
    std::vector<SchedulerUtilityValidationRecord> schedulerUtilityDifferentialValidation_;
    std::vector<GraphicCreditCoverageRecord> graphicCreditCoverageLedger_;
    std::vector<GraphicCreditValidationRecord> graphicCreditDifferentialValidation_;
    std::vector<FrameUpdateCoverageRecord> frameUpdateCoverageLedger_;
    std::vector<FrameUpdateValidationRecord> frameUpdateDifferentialValidation_;
    std::vector<ObjectInputCoverageRecord> objectInputCoverageLedger_;
    std::vector<ObjectInputValidationRecord> objectInputDifferentialValidation_;
    std::vector<FrameHelperCoverageRecord> frameHelperCoverageLedger_;
    std::vector<FrameHelperValidationRecord> frameHelperDifferentialValidation_;
    std::vector<CoordinateRenderCoverageRecord> coordinateRenderCoverageLedger_;
    std::vector<CoordinateRenderValidationRecord> coordinateRenderDifferentialValidation_;
    std::vector<StartupUtilityCoverageRecord> startupUtilityCoverageLedger_;
    std::vector<StartupUtilityValidationRecord> startupUtilityDifferentialValidation_;
    std::vector<StartupRuntimeCoverageRecord> startupRuntimeCoverageLedger_;
    std::vector<StartupRuntimeValidationRecord> startupRuntimeDifferentialValidation_;
    std::vector<InterruptSchedulerCoverageRecord> interruptSchedulerCoverageLedger_;
    std::vector<InterruptSchedulerValidationRecord> interruptSchedulerDifferentialValidation_;
    std::vector<SystemUtilityCoverageRecord> systemUtilityCoverageLedger_;
    std::vector<SystemUtilityValidationRecord> systemUtilityDifferentialValidation_;
    std::vector<StartupSelfTestCoverageRecord> startupSelfTestCoverageLedger_;
    std::vector<StartupSelfTestValidationRecord> startupSelfTestDifferentialValidation_;
    std::vector<ColdStateCoverageRecord> coldStateCoverageLedger_;
    std::vector<ColdStateValidationRecord> coldStateDifferentialValidation_;
    std::vector<ColdHelperCoverageRecord> coldHelperCoverageLedger_;
    std::vector<ColdHelperValidationRecord> coldHelperDifferentialValidation_;
    std::vector<CoordinateDispatchCoverageRecord> coordinateDispatchCoverageLedger_;
    std::vector<CoordinateDispatchValidationRecord> coordinateDispatchDifferentialValidation_;
    std::vector<IntermissionStateCoverageRecord> intermissionStateCoverageLedger_;
    std::vector<IntermissionStateValidationRecord> intermissionStateDifferentialValidation_;
    std::vector<SystemRootPrimaryCoverageRecord> systemRootPrimaryCoverageLedger_;
    std::vector<SystemRootPrimaryValidationRecord> systemRootPrimaryDifferentialValidation_;
    std::vector<SystemRootSecondaryCoverageRecord> systemRootSecondaryCoverageLedger_;
    std::vector<SystemRootSecondaryValidationRecord> systemRootSecondaryDifferentialValidation_;
    std::vector<InterruptLatchCoverageRecord> interruptLatchCoverageLedger_;
    std::vector<InterruptLatchValidationRecord> interruptLatchDifferentialValidation_;
};

} // namespace pacripper
