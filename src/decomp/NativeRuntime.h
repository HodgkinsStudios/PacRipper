#pragma once
// PacRipper native runtime native PC runtime/platform foundation
// Created by Jacob Hodgkins

#include "PlatformAbstraction.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace pacripper {

enum class LogicalInput {
    P1Up, P1Left, P1Right, P1Down,
    P2Up, P2Left, P2Right, P2Down,
    Coin1, Coin2, Start1, Start2,
    Service, ServiceTest, RackAdvance, CocktailCabinet
};

enum class RuntimeLifecycleState { Stopped, Running, Paused };

struct RuntimeConfig {
    // Canonical defaults. These bytes are only the reference-compatibility encoding;
    // native/product code owns configuration through this typed host state.
    std::uint8_t canonicalDip1=0xC9;
    std::uint8_t canonicalDip2=0xFF;
};

struct RuntimeResourceRecord {
    std::string logicalName;
    std::string sourcePath;
    std::size_t size=0;
    bool userSupplied=false;
};

struct RuntimeNativeClassRecord {
    PlatformDependencyClass dependencyClass=PlatformDependencyClass::CoreMemory;
    PlatformServiceKind service=PlatformServiceKind::CoreState;
    bool required=false;
    bool implemented=false;
    bool stubOnly=false;
    std::size_t dependencySites=0;
    std::string evidence;
};

struct RuntimeValidationRecord {
    std::string stableId;
    bool passed=false;
    std::string diagnostic;
};

struct NativeRuntimeStats {
    std::size_t dependencySites=0;
    std::size_t dependencyClasses=0;
    std::size_t pcNativeRequiredClasses=0;
    std::size_t pcNativeImplementedClasses=0;
    std::size_t pcNativeRemainingClasses=0;
    std::size_t rendererAudioStubClasses=0;
    std::size_t validationChecks=0;
    std::size_t validationPassed=0;
    std::size_t validationFailed=0;
    bool deterministicHostValidation=false;
    bool foundationReady=false;
};

class RuntimeResourceStore {
public:
    bool addUserSupplied(const std::string& logicalName,const std::vector<std::uint8_t>& bytes,
                         const std::string& sourcePath,std::string& error);
    bool loadUserSuppliedFile(const std::string& logicalName,const std::string& path,
                              std::size_t expectedSize,std::string& error);
    const std::vector<std::uint8_t>* find(const std::string& logicalName) const;
    std::vector<RuntimeResourceRecord> records() const;
    void clear();
private:
    struct Entry { std::vector<std::uint8_t> bytes; RuntimeResourceRecord record; };
    std::map<std::string,Entry> entries_;
};

class NativeRuntime: public PlatformServices {
public:
    NativeRuntime();

    void powerOnReset();
    void softReset();
    void startSession();
    void stopSession();
    void setPaused(bool paused);
    RuntimeLifecycleState phase() const { return phase_; }
    std::uint64_t sessionId() const { return sessionId_; }
    std::uint64_t resetCount() const { return resetCount_; }

    void setInput(LogicalInput input,bool pressed);
    bool input(LogicalInput input) const;
    void releaseMomentaryInputs();
    std::uint8_t canonicalInputByte(unsigned bank) const;

    void setConfiguration(const RuntimeConfig& config) { config_=config; }
    const RuntimeConfig& configuration() const { return config_; }

    // PC host scheduler. Time is supplied by the frontend/test harness; no wall clock
    // is read internally, so runs are deterministic and headless-friendly.
    std::uint64_t advanceNanoseconds(std::uint64_t nanoseconds);
    std::uint64_t frameCounter() const { return frameCounter_; }
    std::uint64_t elapsedNanoseconds() const { return elapsedNanoseconds_; }
    std::uint64_t schedulerYieldCount() const { return schedulerYieldCount_; }
    bool logicTicksEnabled() const { return logicTicksEnabled_; }

    std::uint64_t watchdogKickCount() const { return watchdogKickCount_; }
    std::uint64_t watchdogAgeFrames() const { return watchdogAgeFrames_; }
    std::uint64_t watchdogResetRequests() const { return watchdogResetRequests_; }
    bool consumeResetRequest();
    std::uint64_t coinCounterPulses() const { return coinCounterPulses_; }

    RuntimeResourceStore& resources() { return resources_; }
    const RuntimeResourceStore& resources() const { return resources_; }

    // PlatformServices implementation. Renderer/audio methods intentionally
    // retain integration backing state but are not counted as native-complete.
    std::uint8_t coreStateRead(std::uint16_t logicalAddress,std::uint8_t fallback) override;
    void coreStateWrite(std::uint16_t logicalAddress,std::uint8_t value) override;
    std::uint8_t videoStateRead(PlatformDependencyClass region,std::uint16_t offset,std::uint8_t fallback) override;
    void videoStateWrite(PlatformDependencyClass region,std::uint16_t offset,std::uint8_t value) override;
    void setFlipScreen(bool enabled) override;
    void soundRegisterWrite(std::uint16_t index,std::uint8_t value) override;
    void setSoundEnabled(bool enabled) override;
    std::uint8_t readLogicalInput(unsigned bank,unsigned offset,std::uint8_t fallback) override;
    std::uint8_t readConfiguration(unsigned bank,unsigned offset,std::uint8_t fallback) override;
    void setInterruptEnabled(bool enabled) override;
    void setInterruptMode(std::uint8_t mode) override;
    void setInterruptVector(std::uint8_t vector) override;
    void onSchedulerHalt() override;
    void watchdogKick() override;
    void cabinetOutput(unsigned output,bool enabled) override;
    void coinCounterPulse() override;
    void referenceOnlyEffect(PlatformDependencyClass dependency,std::uint16_t address,std::uint8_t value) override;

private:
    static constexpr std::uint64_t kPixelClockHz=6144000ULL;
    static constexpr std::uint64_t kPixelsPerFrame=384ULL*264ULL;
    static constexpr std::uint64_t kNanosecondsPerSecond=1000000000ULL;
    static constexpr std::uint64_t kWatchdogFrames=16ULL;

    static std::size_t inputIndex(LogicalInput input);
    std::vector<std::uint8_t>* videoRegion(PlatformDependencyClass region);
    const std::vector<std::uint8_t>* videoRegion(PlatformDependencyClass region) const;

    std::array<bool,16> inputs_{};
    RuntimeConfig config_{};
    RuntimeLifecycleState phase_=RuntimeLifecycleState::Stopped;
    std::uint64_t sessionId_=0;
    std::uint64_t resetCount_=0;
    std::uint64_t elapsedNanoseconds_=0;
    std::uint64_t schedulerNumerator_=0;
    std::uint64_t frameCounter_=0;
    std::uint64_t schedulerYieldCount_=0;
    bool logicTicksEnabled_=false;
    std::uint8_t compatibilityInterruptMode_=0;
    std::uint8_t compatibilityInterruptVector_=0;
    std::uint64_t watchdogKickCount_=0;
    std::uint64_t watchdogKickBaseline_=0;
    std::uint64_t watchdogAgeFrames_=0;
    std::uint64_t watchdogResetRequests_=0;
    bool resetRequested_=false;
    std::uint64_t coinCounterPulses_=0;
    std::array<bool,8> cabinetOutputs_{};
    std::map<std::uint16_t,std::uint8_t> coreState_;
    std::vector<std::uint8_t> videoTiles_;
    std::vector<std::uint8_t> colors_;
    std::vector<std::uint8_t> spriteAttributes_;
    std::vector<std::uint8_t> spriteCoordinates_;
    bool flipScreenStub_=false;
    std::array<std::uint8_t,32> soundRegistersStub_{};
    bool soundEnabledStub_=false;
    std::uint64_t referenceOnlyEvents_=0;
    RuntimeResourceStore resources_;
};

class NativeRuntimeFoundation {
public:
    static std::string logicalInputText(LogicalInput input);
    static std::string lifecyclePhaseText(RuntimeLifecycleState phase);
    static void buildProgress(const std::vector<PlatformDependencyRecord>& dependencies,
                              std::vector<RuntimeNativeClassRecord>& classes,
                              NativeRuntimeStats& stats);
    static std::vector<RuntimeValidationRecord> runDeterministicValidation(NativeRuntimeStats& stats);
};

} // namespace pacripper
