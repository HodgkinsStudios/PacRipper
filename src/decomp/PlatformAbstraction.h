#pragma once
// PacRipper platform abstraction hardware-dependency abstraction + reference-core stabilization
// Created by Jacob Hodgkins

#include "HardwareSemantics.h"
#include "GeneratedCppEngine.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace pacripper {

enum class PlatformDisposition { RecoveredGameState, PcNativeService, ReferenceOnly };
enum class PlatformServiceKind { CoreState, Renderer, Audio, Input, Timing, Configuration, Lifecycle, ReferenceCompatibility };
enum class PlatformDependencyClass {
    CoreMemory,
    VideoTileMemory,
    ColorMemory,
    WorkMemory,
    SpriteAttributeMemory,
    OpenBus,
    BoardOutputLatch,
    InterruptEnableLatch,
    SoundEnableLatch,
    FlipScreenLatch,
    CoinCounterLatch,
    CabinetOutputLatch,
    PrimaryInputPort,
    SecondaryInputPort,
    SoundRegisters,
    SpriteCoordinates,
    NopDeviceWrite,
    DipSwitch1,
    DipSwitch2,
    Watchdog,
    InterruptVectorPort,
    PortInput,
    InterruptControl,
    HaltWakeup,
    RawBoardCompatibility
};

struct PlatformDependencyRecord {
    std::size_t id=0;
    std::string stableId;
    std::string operationId;
    std::string blockId;
    std::uint16_t sourcePC=0;
    std::vector<std::uint8_t> sourceBytes;
    PlatformDependencyClass dependencyClass=PlatformDependencyClass::CoreMemory;
    PlatformServiceKind service=PlatformServiceKind::CoreState;
    PlatformDisposition disposition=PlatformDisposition::RecoveredGameState;
    MemoryAccessKind access=MemoryAccessKind::Unknown;
    AddressResolutionKind addressResolution=AddressResolutionKind::Unresolved;
    std::uint16_t start=0;
    std::uint16_t end=0;
    bool inheritedHardwareEvidence=false;
    std::size_t inheritedHardwareAccessId=0;
    bool sourceProvenanceComplete=false;
    bool referenceAdapterRequired=false;
    bool pcNativeImplementationRequired=false;
    std::string evidence;
};

struct PlatformServiceContract {
    PlatformServiceKind service=PlatformServiceKind::CoreState;
    std::string stableId;
    std::string purpose;
    std::string nativeContract;
    std::string referenceContract;
    bool productService=false;
};

struct PlatformBoundaryValidationRecord {
    std::size_t operationId=0;
    std::uint16_t sourcePC=0;
    bool accepted=false;
    std::size_t boundaryEvents=0;
    std::string diagnostic;
};

struct PlatformAbstractionStats {
    std::size_t canonicalOperations=0;
    std::size_t canonicalBlocks=0;
    std::size_t inheritedHardwareRecords=0;
    std::size_t canonicalHardwareRecords=0;
    std::size_t dependencySites=0;
    std::size_t operationsWithDependencies=0;
    std::size_t dependencyClasses=0;
    std::size_t serviceContracts=0;
    std::size_t productServiceContracts=0;
    std::size_t sourceProvenanceComplete=0;
    std::size_t abstractedSites=0;
    std::size_t referenceRequiredClasses=0;
    std::size_t referenceCoveredClasses=0;
    std::size_t pcNativeRequiredClasses=0;
    std::size_t pcNativeImplementedClasses=0;
    std::size_t unclassifiedClasses=0;
    std::size_t boundaryOperationsChecked=0;
    std::size_t boundaryMismatches=0;
    std::size_t boundaryEvents=0;
    bool completeInventory=false;
    bool completeContractCoverage=false;
    bool completeReferenceCoverage=false;
    bool boundaryRegressionPass=false;
};

// Product-facing contracts. These deliberately speak in native game/service terms.
// Raw board addresses are confined to the reference adapter below.
class PlatformServices {
public:
    virtual ~PlatformServices()=default;
    virtual std::uint8_t coreStateRead(std::uint16_t logicalAddress,std::uint8_t fallback)=0;
    virtual void coreStateWrite(std::uint16_t logicalAddress,std::uint8_t value)=0;
    virtual std::uint8_t videoStateRead(PlatformDependencyClass region,std::uint16_t offset,std::uint8_t fallback)=0;
    virtual void videoStateWrite(PlatformDependencyClass region,std::uint16_t offset,std::uint8_t value)=0;
    virtual void setFlipScreen(bool enabled)=0;
    virtual void soundRegisterWrite(std::uint16_t index,std::uint8_t value)=0;
    virtual void setSoundEnabled(bool enabled)=0;
    virtual std::uint8_t readLogicalInput(unsigned bank,unsigned offset,std::uint8_t fallback)=0;
    virtual std::uint8_t readConfiguration(unsigned bank,unsigned offset,std::uint8_t fallback)=0;
    virtual void setInterruptEnabled(bool enabled)=0;
    virtual void setInterruptMode(std::uint8_t mode)=0;
    virtual void setInterruptVector(std::uint8_t vector)=0;
    virtual void onSchedulerHalt()=0;
    virtual void watchdogKick()=0;
    virtual void cabinetOutput(unsigned output,bool enabled)=0;
    virtual void coinCounterPulse()=0;
    virtual void referenceOnlyEffect(PlatformDependencyClass dependency,std::uint16_t address,std::uint8_t value)=0;
};

// Translates the verified generated-code execution model raw execution-event seam to platform abstraction service
// contracts while preserving fallback values for anything still internal to the
// recovered core. This is a bridge, not the final PC implementation.
class PlatformContractBoundary final: public GeneratedExecutionBoundary {
public:
    explicit PlatformContractBoundary(PlatformServices& services):services_(services){}
    std::uint8_t memoryRead(std::uint16_t address,std::uint8_t fallback,std::uint16_t sourcePC) override;
    void memoryWrite(std::uint16_t address,std::uint8_t value,std::uint16_t sourcePC) override;
    std::uint8_t portRead(std::uint16_t port,std::uint8_t fallback,std::uint16_t sourcePC) override;
    void portWrite(std::uint16_t port,std::uint8_t value,std::uint16_t sourcePC) override;
    void interruptControl(SemanticKind kind,std::uint8_t value,std::uint16_t sourcePC) override;
    void halt(std::uint16_t sourcePC) override;
private:
    PlatformServices& services_;
};

class PlatformAbstraction {
public:
    static std::string dependencyClassText(PlatformDependencyClass value);
    static std::string serviceText(PlatformServiceKind value);
    static std::string dispositionText(PlatformDisposition value);
    static std::vector<PlatformServiceContract> serviceContracts();
    static void buildInventory(const std::vector<GeneratedOperation>& operations,
                               const std::vector<GeneratedBlock>& blocks,
                               const std::vector<HardwareAccessRecord>& hardwareAccesses,
                               std::vector<PlatformDependencyRecord>& dependencies,
                               std::vector<PlatformServiceContract>& contracts,
                               PlatformAbstractionStats& stats);
    static std::vector<PlatformBoundaryValidationRecord> verifyBoundaryRegression(
        const std::vector<std::uint8_t>& program,
        const std::vector<GeneratedOperation>& operations,
        PlatformAbstractionStats& stats);
};

} // namespace pacripper
