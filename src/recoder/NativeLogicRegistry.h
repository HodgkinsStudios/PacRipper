#pragma once
// PacRipper canonical current native-logic coverage registry
// Created by Jacob Hodgkins

#include "InterruptLatchNativeLogic.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pacripper {

enum class NativeLogicModule : std::uint8_t { Core=0, LifecycleScheduler=1, CreditStart=2, SessionInitialization=3, MazePreparation=4, DisplayMap=5, HudBoard=6, BoardInterpreter=7, CommandInterpreter=8, RstUtility=9, SchedulerUtility=10, GraphicCredit=11, FrameUpdate=12, ObjectInput=13, FrameHelper=14, CoordinateRender=15, StartupUtility=16, StartupRuntime=17, InterruptScheduler=18, SystemUtility=19, StartupSelfTest=20, ColdState=21, ColdHelper=22, CoordinateDispatch=23, IntermissionState=24, SystemRootPrimary=25, SystemRootSecondary=26, InterruptLatch=27 };

struct NativeLogicFamilyRecord {
    std::size_t id=0;
    std::string stableId;
    std::string provenanceStableId;
    NativeLogicModule module=NativeLogicModule::Core;
    std::size_t localFamilyIndex=0;
    std::string familyName;
    std::uint16_t entryPC=0;
    std::vector<std::uint16_t> sourcePCs;
    std::size_t units=0;
    bool directNative=true;
    bool sourcePresent=false;
    bool mayReturnToTransitionalExecution=true;
    std::string validationStatus;
    std::string implementationOwner;
    std::string evidence;
};

struct NativeLogicLedgerStats {
    std::size_t recoveredOperations=0;
    std::size_t directNativeOperations=0;
    std::size_t transitionalOperations=0;
    std::size_t nativeFamilies=0;
    std::size_t overlapCount=0;
    std::size_t missingNativeSourcePCs=0;
    bool noOverlap=false;
    bool noGap=false;
    bool allNativeSourcesPresent=false;
    bool exactCurrentCoverage=false;
    bool exactLegacyCompatibilityCoverage=false; // compatibility alias: true only for the verified 340-op the earlier 340-operation native subset
};

struct NativeLogicDispatch {
    std::size_t recordIndex=0;
    NativeLogicModule module=NativeLogicModule::Core;
    std::size_t localFamilyIndex=0;
};

class NativeLogicRegistry {
public:
    static constexpr std::size_t FixedRecoveredOperations=5414;
    static constexpr std::size_t DirectNativeOperations=5414;
    static constexpr std::size_t DirectNativeLogicUnits=DirectNativeOperations;
    static constexpr std::size_t TransitionalOperations=0;
    static constexpr std::size_t TransitionalLogicUnits=TransitionalOperations;
    static constexpr std::size_t NativeFamilies=381;
    static constexpr std::size_t TransitionalOperationQuantum=SessionInitializationNativeLogicCoverage::TransitionalOperationQuantum;

    static const std::vector<NativeLogicFamilyRecord>& records();
    static bool entryForPC(std::uint16_t pc,NativeLogicDispatch& dispatch);
    static bool isCoveredSourcePC(std::uint16_t pc);
    static const NativeLogicFamilyRecord* recordForSourcePC(std::uint16_t pc);

    static void buildLedger(const std::vector<GeneratedOperation>& operations,
                            std::vector<NativeLogicFamilyRecord>& ledger,
                            NativeLogicLedgerStats& stats);

};

} // namespace pacripper
