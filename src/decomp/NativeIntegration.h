#pragma once
// PacRipper native integration native game-state / execution integration
// Created by Jacob Hodgkins

#include "ObjectStateRoles.h"
#include "NativeAudio.h"
#include "GeneratedCppEngine.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace pacripper {

enum class IntegrationExecutionStage {
    InputCapture,
    LifecycleTiming,
    GameLogic,
    StateProjection,
    VideoOutput,
    AudioOutput,
    FrameCommit
};

struct IntegrationStateMapRecord {
    std::size_t id=0;
    std::string stableId;
    ObjectStateRoleKind role=ObjectStateRoleKind::StateStorage;
    std::uint16_t sourceStart=0;
    std::uint16_t sourceEnd=0;
    std::size_t byteCount=0;
    bool exact=false;
    bool productOwned=true;
    std::string evidence;
};

struct IntegrationExecutionLedgerRecord {
    std::string stableId;
    IntegrationExecutionStage stage=IntegrationExecutionStage::GameLogic;
    bool directNative=false;
    bool transitional=false;
    std::size_t units=0;
    std::string evidence;
};

struct IntegrationValidationRecord {
    std::string stableId;
    bool passed=false;
    std::string evidenceKind;
    std::string diagnostic;
};

struct NativeIntegrationStats {
    std::size_t stateRoleRecords=0;
    std::size_t stateMapUnits=0;
    std::size_t nativeOwnedStateUnits=0;
    std::size_t executionStages=0;
    std::size_t directNativeStages=0;
    std::size_t transitionalStages=0;
    std::size_t recoveredLogicUnits=0;
    std::size_t directNativeLogicUnits=0;
    std::size_t transitionalLogicUnits=0;
    std::size_t validationChecks=0;
    std::size_t validationPassed=0;
    std::size_t validationFailed=0;
    std::size_t canonicalChecks=0;
    std::size_t canonicalPassed=0;
    std::size_t canonicalFailed=0;
    std::uint64_t syntheticSessionHash=0;
    std::uint64_t canonicalResetStateHash=0;
    std::uint64_t canonicalBootStateHash=0;
    std::uint64_t canonicalBootFramebufferHash=0;
    std::uint64_t canonicalBootPcmHash=0;
    bool deterministicNativeSession=false;
    bool canonicalIntegrationPass=false;
    bool integratedSessionReady=false;
    bool endToEndNative=false;
};

struct IntegrationInputSnapshot {
    std::array<bool,16> actions{};
};

// Product-side recovered state owner. The byte-preserving backing is intentionally
// transitional; board addresses are not part of this public API.
class RecoveredGameState {
public:
    static constexpr std::size_t TransitionalStateBytes=0x400;

    void clear();
    std::uint8_t transitionalByte(std::size_t offset) const;
    bool setTransitionalByte(std::size_t offset,std::uint8_t value);
    const std::array<std::uint8_t,TransitionalStateBytes>& transitionalBytes() const { return transitionalBytes_; }
    std::uint64_t stableHash() const;
private:
    std::array<std::uint8_t,TransitionalStateBytes> transitionalBytes_{};
};

class RecoveredLogicDriver {
public:
    virtual ~RecoveredLogicDriver()=default;
    virtual void reset(RecoveredGameState& state,AudioNativeRuntime& runtime)=0;
    virtual bool updateFrame(RecoveredGameState& state,const IntegrationInputSnapshot& input,
                             AudioNativeRuntime& runtime,std::string& error)=0;
    virtual bool transitional() const=0;
    virtual std::size_t recoveredLogicUnits() const=0;
};

// The product session depends only on a logic-driver contract and the native services.
// A high-level native logic driver can replace the transitional driver without changing
// the session/front-end API.
class NativeSession {
public:
    static constexpr std::uint64_t FrameNanoseconds=16500000ULL;
    static constexpr std::size_t AudioSamplesPerFrame=3168;

    explicit NativeSession(RecoveredLogicDriver& driver);

    AudioNativeRuntime& runtime() { return runtime_; }
    const AudioNativeRuntime& runtime() const { return runtime_; }
    RecoveredGameState& gameState() { return gameState_; }
    const RecoveredGameState& gameState() const { return gameState_; }

    void powerOnReset();
    void start();
    void stop();
    void setPaused(bool paused);
    bool runFrame(std::string& error);
    std::uint64_t productFrameCounter() const { return productFrameCounter_; }
    const std::vector<std::int16_t>& lastPcm() const { return lastPcm_; }
    std::uint64_t stableSessionHash() const;

private:
    IntegrationInputSnapshot captureInput() const;

    RecoveredLogicDriver& driver_;
    AudioNativeRuntime runtime_;
    RecoveredGameState gameState_;
    std::uint64_t productFrameCounter_=0;
    std::vector<std::int16_t> lastPcm_;
};

// Coverage-only adapter. It keeps the remaining recovered machine-state semantics
// behind the logic-driver contract while core native logic+ elevates them into direct native C++.
// It performs no opcode fetch/decode loop; it dispatches only the verified generated
// semantic descriptors. This class is explicitly counted as transitional, never native.
class TransitionalRecoveredLogic: public RecoveredLogicDriver, protected GeneratedExecutionBoundary {
public:
    TransitionalRecoveredLogic(const std::vector<std::uint8_t>& program,
                                     const std::vector<GeneratedOperation>& operations);
    void reset(RecoveredGameState& state,AudioNativeRuntime& runtime) override;
    bool updateFrame(RecoveredGameState& state,const IntegrationInputSnapshot& input,
                     AudioNativeRuntime& runtime,std::string& error) override;
    bool transitional() const override { return true; }
    std::size_t recoveredLogicUnits() const override { return operations_.size(); }
    const SemanticExecutionState& machineState() const { return machineState_; }
    std::uint64_t operationsExecuted() const { return operationsExecuted_; }
protected:
    // core native logic+ may replace explicitly covered recovered families while delegating
    // the audited remainder to this one-operation verified-semantic seam.
    virtual bool executeUntilYield(std::string& error);
    bool executeTransitionalCurrentOperation(std::string& error);
    SemanticExecutionState& mutableMachineState() { return machineState_; }
    const SemanticExecutionState& mutableMachineState() const { return machineState_; }
    void accountEquivalentOperations(std::size_t count) { operationsExecuted_+=count; }
    GeneratedExecutionBoundary* mappedExecutionBoundary() { return this; }
private:
    std::uint8_t memoryRead(std::uint16_t address,std::uint8_t fallback,std::uint16_t sourcePC) override;
    void memoryWrite(std::uint16_t address,std::uint8_t value,std::uint16_t sourcePC) override;
    std::uint8_t portRead(std::uint16_t port,std::uint8_t fallback,std::uint16_t sourcePC) override;
    void portWrite(std::uint16_t port,std::uint8_t value,std::uint16_t sourcePC) override;
    void interruptControl(SemanticKind kind,std::uint8_t value,std::uint16_t sourcePC) override;
    void halt(std::uint16_t sourcePC) override;
    bool deliverFrameInterrupt(std::string& error);
    void projectInputsAndConfig(const IntegrationInputSnapshot& input,const AudioNativeRuntime& runtime);
    void projectStateToProduct(RecoveredGameState& state,AudioNativeRuntime& runtime);
    void projectAudio(AudioNativeRuntime& runtime);

    const std::vector<std::uint8_t>& program_;
    const std::vector<GeneratedOperation>& operations_;
    std::map<std::uint16_t,const GeneratedOperation*> byPc_;
    SemanticExecutionState machineState_{};
    std::uint64_t operationsExecuted_=0;
    std::uint8_t vectorLatch_=0;
    std::uint8_t mappedInput0_=0xFF;
    std::uint8_t mappedInput1_=0xFF;
    std::uint8_t mappedDip1_=0xFF;
    std::uint8_t mappedDip2_=0xFF;
};

class NativeIntegration {
public:
    static std::string executionStageText(IntegrationExecutionStage stage);
    static void buildStateMap(const std::vector<ObjectRoleRecord>& roles,
                              std::vector<IntegrationStateMapRecord>& stateMap,
                              NativeIntegrationStats& stats);
    static void buildExecutionLedger(std::size_t recoveredLogicUnits,
                                     std::vector<IntegrationExecutionLedgerRecord>& ledger,
                                     NativeIntegrationStats& stats);
    static std::vector<IntegrationValidationRecord> runSyntheticValidation(NativeIntegrationStats& stats);
    static std::vector<IntegrationValidationRecord> runCanonicalValidation(
        const std::vector<std::uint8_t>& program,
        const std::vector<GeneratedOperation>& operations,
        const RuntimeResourceStore& resources,
        NativeIntegrationStats& stats);
};

} // namespace pacripper
