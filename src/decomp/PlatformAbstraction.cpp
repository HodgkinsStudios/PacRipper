// PacRipper platform abstraction hardware-dependency abstraction + reference-core stabilization
// Created by Jacob Hodgkins

#include "PlatformAbstraction.h"

#include <algorithm>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>

namespace pacripper {
namespace {

struct Mapping {PlatformDependencyClass dependency;PlatformServiceKind service;PlatformDisposition disposition;bool referenceRequired;bool pcRequired;};

Mapping mappingForHardware(const HardwareAccessRecord& r){
    switch(r.device){
        case BoardDeviceKind::VideoRam:return {PlatformDependencyClass::VideoTileMemory,PlatformServiceKind::Renderer,PlatformDisposition::PcNativeService,true,true};
        case BoardDeviceKind::ColorRam:return {PlatformDependencyClass::ColorMemory,PlatformServiceKind::Renderer,PlatformDisposition::PcNativeService,true,true};
        case BoardDeviceKind::OpenBus:return {PlatformDependencyClass::OpenBus,PlatformServiceKind::ReferenceCompatibility,PlatformDisposition::ReferenceOnly,true,false};
        case BoardDeviceKind::WorkRam:return {PlatformDependencyClass::WorkMemory,PlatformServiceKind::CoreState,PlatformDisposition::RecoveredGameState,false,false};
        case BoardDeviceKind::SpriteRam:return {PlatformDependencyClass::SpriteAttributeMemory,PlatformServiceKind::Renderer,PlatformDisposition::PcNativeService,true,true};
        case BoardDeviceKind::InputIN0:return {PlatformDependencyClass::PrimaryInputPort,PlatformServiceKind::Input,PlatformDisposition::PcNativeService,true,true};
        case BoardDeviceKind::InputIN1:return {PlatformDependencyClass::SecondaryInputPort,PlatformServiceKind::Input,PlatformDisposition::PcNativeService,true,true};
        case BoardDeviceKind::NamcoWSG:return {PlatformDependencyClass::SoundRegisters,PlatformServiceKind::Audio,PlatformDisposition::PcNativeService,true,true};
        case BoardDeviceKind::SpriteCoordinate:return {PlatformDependencyClass::SpriteCoordinates,PlatformServiceKind::Renderer,PlatformDisposition::PcNativeService,true,true};
        case BoardDeviceKind::NopWriteRegion:return {PlatformDependencyClass::NopDeviceWrite,PlatformServiceKind::ReferenceCompatibility,PlatformDisposition::ReferenceOnly,true,false};
        case BoardDeviceKind::InputDSW1:return {PlatformDependencyClass::DipSwitch1,PlatformServiceKind::Configuration,PlatformDisposition::PcNativeService,true,true};
        case BoardDeviceKind::InputDSW2:return {PlatformDependencyClass::DipSwitch2,PlatformServiceKind::Configuration,PlatformDisposition::PcNativeService,true,true};
        case BoardDeviceKind::Watchdog:return {PlatformDependencyClass::Watchdog,PlatformServiceKind::Lifecycle,PlatformDisposition::PcNativeService,true,true};
        case BoardDeviceKind::OutputLatch:{
            if(r.addressResolution==AddressResolutionKind::ExactStatic){
                if(r.start==0x5000)return {PlatformDependencyClass::InterruptEnableLatch,PlatformServiceKind::Timing,PlatformDisposition::PcNativeService,true,true};
                if(r.start==0x5001)return {PlatformDependencyClass::SoundEnableLatch,PlatformServiceKind::Audio,PlatformDisposition::PcNativeService,true,true};
                if(r.start==0x5003)return {PlatformDependencyClass::FlipScreenLatch,PlatformServiceKind::Renderer,PlatformDisposition::PcNativeService,true,true};
                if(r.start==0x5007)return {PlatformDependencyClass::CoinCounterLatch,PlatformServiceKind::Lifecycle,PlatformDisposition::PcNativeService,true,true};
                if(r.start>=0x5002&&r.start<=0x5006)return {PlatformDependencyClass::CabinetOutputLatch,PlatformServiceKind::Lifecycle,PlatformDisposition::PcNativeService,true,true};
            }
            return {PlatformDependencyClass::BoardOutputLatch,PlatformServiceKind::Lifecycle,PlatformDisposition::PcNativeService,true,true};
        }
        case BoardDeviceKind::None:return {PlatformDependencyClass::CoreMemory,PlatformServiceKind::CoreState,PlatformDisposition::RecoveredGameState,false,false};
        case BoardDeviceKind::MixedOrUnknown:return {PlatformDependencyClass::RawBoardCompatibility,PlatformServiceKind::ReferenceCompatibility,PlatformDisposition::ReferenceOnly,true,false};
    }
    return {PlatformDependencyClass::RawBoardCompatibility,PlatformServiceKind::ReferenceCompatibility,PlatformDisposition::ReferenceOnly,true,false};
}

MemoryAccessKind explicitMemoryAccess(const GeneratedOperation& o){
    const auto& m=o.mnemonic;const auto& x=o.operands;
    if(m=="LD"){
        const auto comma=x.find(',');const auto lhs=comma==std::string::npos?x:x.substr(0,comma);const auto rhs=comma==std::string::npos?std::string():x.substr(comma+1);
        const bool lm=lhs.find('(')!=std::string::npos,rm=rhs.find('(')!=std::string::npos;
        if(lm&&rm)return MemoryAccessKind::ReadWrite;
        if(lm)return MemoryAccessKind::Write;
        if(rm)return MemoryAccessKind::Read;
    }
    if(m=="INC"||m=="DEC"||m=="RES"||m=="SET"||m=="RLC"||m=="RRC"||m=="RL"||m=="RR"||m=="SLA"||m=="SRA"||m=="SLL"||m=="SRL"||m=="RRD"||m=="RLD"||m=="EX")return MemoryAccessKind::ReadWrite;
    if(m=="BIT"||m=="ADD"||m=="ADC"||m=="SUB"||m=="SBC"||m=="AND"||m=="XOR"||m=="OR"||m=="CP")return MemoryAccessKind::Read;
    if(m=="LDI"||m=="LDD"||m=="LDIR"||m=="LDDR")return MemoryAccessKind::ReadWrite;
    if(m=="CPI"||m=="CPD"||m=="CPIR"||m=="CPDR")return MemoryAccessKind::Read;
    return MemoryAccessKind::Unknown;
}

bool directMemoryAddress(const GeneratedOperation&o,std::uint16_t&address){
    const auto pos=o.operands.find("($");if(pos==std::string::npos||pos+6>o.operands.size())return false;
    unsigned v=0;std::istringstream in(o.operands.substr(pos+2,4));in>>std::hex>>v;if(!in||v>0xFFFFu)return false;address=static_cast<std::uint16_t>(v);return true;
}

bool hasExplicitOrImplicitDataMemory(const GeneratedOperation&o){
    if(o.operands.find("(HL")!=std::string::npos||o.operands.find("(BC")!=std::string::npos||o.operands.find("(DE")!=std::string::npos||o.operands.find("(IX")!=std::string::npos||o.operands.find("(IY")!=std::string::npos)return true;
    return o.mnemonic=="LDI"||o.mnemonic=="LDD"||o.mnemonic=="LDIR"||o.mnemonic=="LDDR"||o.mnemonic=="CPI"||o.mnemonic=="CPD"||o.mnemonic=="CPIR"||o.mnemonic=="CPDR"||o.mnemonic=="RRD"||o.mnemonic=="RLD";
}

bool isSystemOp(const GeneratedOperation& op,Mapping& m){
    switch(op.baseKind){
        case SemanticKind::IoWrite:m={PlatformDependencyClass::InterruptVectorPort,PlatformServiceKind::Timing,PlatformDisposition::PcNativeService,true,true};return true;
        case SemanticKind::IoRead:m={PlatformDependencyClass::PortInput,PlatformServiceKind::ReferenceCompatibility,PlatformDisposition::ReferenceOnly,true,false};return true;
        case SemanticKind::InterruptDisable:
        case SemanticKind::InterruptEnable:
        case SemanticKind::InterruptMode:m={PlatformDependencyClass::InterruptControl,PlatformServiceKind::Timing,PlatformDisposition::PcNativeService,true,true};return true;
        case SemanticKind::Halt:m={PlatformDependencyClass::HaltWakeup,PlatformServiceKind::Timing,PlatformDisposition::PcNativeService,true,true};return true;
        default:return false;
    }
}


class TransparentBoundary final:public GeneratedExecutionBoundary {
public:
    std::size_t events=0;
    std::uint8_t memoryRead(std::uint16_t,std::uint8_t fallback,std::uint16_t) override{++events;return fallback;}
    void memoryWrite(std::uint16_t,std::uint8_t,std::uint16_t) override{++events;}
    std::uint8_t portRead(std::uint16_t,std::uint8_t fallback,std::uint16_t) override{++events;return fallback;}
    void portWrite(std::uint16_t,std::uint8_t,std::uint16_t) override{++events;}
    void interruptControl(SemanticKind,std::uint8_t,std::uint16_t) override{++events;}
    void halt(std::uint16_t) override{++events;}
};
}

std::string PlatformAbstraction::dependencyClassText(PlatformDependencyClass v){switch(v){
case PlatformDependencyClass::CoreMemory:return"core-memory";case PlatformDependencyClass::VideoTileMemory:return"video-tile-memory";case PlatformDependencyClass::ColorMemory:return"color-memory";case PlatformDependencyClass::WorkMemory:return"work-memory";case PlatformDependencyClass::SpriteAttributeMemory:return"sprite-attribute-memory";case PlatformDependencyClass::OpenBus:return"open-bus";case PlatformDependencyClass::BoardOutputLatch:return"board-output-latch";case PlatformDependencyClass::InterruptEnableLatch:return"interrupt-enable-latch";case PlatformDependencyClass::SoundEnableLatch:return"sound-enable-latch";case PlatformDependencyClass::FlipScreenLatch:return"flip-screen-latch";case PlatformDependencyClass::CoinCounterLatch:return"coin-counter-latch";case PlatformDependencyClass::CabinetOutputLatch:return"cabinet-output-latch";case PlatformDependencyClass::PrimaryInputPort:return"primary-input-port";case PlatformDependencyClass::SecondaryInputPort:return"secondary-input-port";case PlatformDependencyClass::SoundRegisters:return"sound-registers";case PlatformDependencyClass::SpriteCoordinates:return"sprite-coordinates";case PlatformDependencyClass::NopDeviceWrite:return"nop-device-write";case PlatformDependencyClass::DipSwitch1:return"dip-switch-1";case PlatformDependencyClass::DipSwitch2:return"dip-switch-2";case PlatformDependencyClass::Watchdog:return"watchdog";case PlatformDependencyClass::InterruptVectorPort:return"interrupt-vector-port";case PlatformDependencyClass::PortInput:return"port-input";case PlatformDependencyClass::InterruptControl:return"interrupt-control";case PlatformDependencyClass::HaltWakeup:return"halt-wakeup";case PlatformDependencyClass::RawBoardCompatibility:return"raw-board-compatibility";}return"unknown";}
std::string PlatformAbstraction::serviceText(PlatformServiceKind v){switch(v){case PlatformServiceKind::CoreState:return"core-state";case PlatformServiceKind::Renderer:return"renderer";case PlatformServiceKind::Audio:return"audio";case PlatformServiceKind::Input:return"input";case PlatformServiceKind::Timing:return"timing";case PlatformServiceKind::Configuration:return"configuration";case PlatformServiceKind::Lifecycle:return"lifecycle";case PlatformServiceKind::ReferenceCompatibility:return"reference-compatibility";}return"unknown";}
std::string PlatformAbstraction::dispositionText(PlatformDisposition v){switch(v){case PlatformDisposition::RecoveredGameState:return"recovered-game-state";case PlatformDisposition::PcNativeService:return"pc-native-service";case PlatformDisposition::ReferenceOnly:return"reference-only";}return"unknown";}

std::vector<PlatformServiceContract> PlatformAbstraction::serviceContracts(){
    return {
        {PlatformServiceKind::CoreState,"PLATFORM_CORE_STATE","Recovered mutable game state retained by the native C++ core.","Native logic owns state directly; no arcade device API is required.","Reference execution may preserve original work-RAM addressing for comparison.",false},
        {PlatformServiceKind::Renderer,"PLATFORM_RENDERER","Tile/color/sprite/flip effects become render-state intent.","PC renderer consumes logical tile/color/sprite changes and screen orientation.","Reference adapter may translate original mapped video/color/sprite writes.",true},
        {PlatformServiceKind::Audio,"PLATFORM_AUDIO","Original sound sequencing/control becomes native audio intent.","PC audio service consumes recovered sound-register intent and sound-enable state without exposing a PCB bus to game code.","Reference adapter retains Namco-WSG register meaning for differential proof.",true},
        {PlatformServiceKind::Input,"PLATFORM_INPUT","Cabinet/player reads become logical player/system input.","PC keyboard/gamepad bindings provide logical controls; cabinet bit layout stays adapter-side.","Reference adapter preserves IN0/IN1 decode semantics.",true},
        {PlatformServiceKind::Timing,"PLATFORM_TIMING","Interrupt enable/mode/vector and HALT wakeup become deterministic game scheduling requirements.","PC scheduler reproduces behaviorally relevant update cadence/order without emulating interrupt circuitry as the product architecture.","Reference adapter retains vector-latch/interrupt facts needed for oracle comparison.",true},
        {PlatformServiceKind::Configuration,"PLATFORM_CONFIGURATION","DIP-switch reads become explicit game configuration.","PC settings provide lives/difficulty/cabinet options through named configuration state once semantics are proven.","Reference adapter preserves DSW banks/bit values.",true},
        {PlatformServiceKind::Lifecycle,"PLATFORM_LIFECYCLE","Watchdog, coin counter and cabinet outputs become lifecycle/session events.","PC runtime maps meaningful events to reset/session/credit behavior and ignores purely physical outputs unless intentionally surfaced.","Reference adapter retains original latch/watchdog effects.",true},
        {PlatformServiceKind::ReferenceCompatibility,"PLATFORM_REFERENCE_ONLY","Open-bus, NOP device writes and unresolved raw board details exist only for correctness reference.","No shipping PC service is required unless later proof shows a gameplay-visible dependency.","Reference path preserves exact arcade-facing meaning.",false}
    };
}

void PlatformAbstraction::buildInventory(const std::vector<GeneratedOperation>& operations,const std::vector<GeneratedBlock>& blocks,const std::vector<HardwareAccessRecord>& hardwareAccesses,std::vector<PlatformDependencyRecord>& dependencies,std::vector<PlatformServiceContract>& contracts,PlatformAbstractionStats& stats){
    dependencies.clear();contracts=serviceContracts();stats={};stats.canonicalOperations=operations.size();stats.canonicalBlocks=blocks.size();stats.inheritedHardwareRecords=hardwareAccesses.size();stats.serviceContracts=contracts.size();for(const auto&c:contracts)if(c.productService)++stats.productServiceContracts;
    std::map<std::uint16_t,const GeneratedOperation*> byPc;for(const auto&o:operations)byPc[o.sourcePC]=&o;
    std::set<std::string> operationIds;std::set<PlatformDependencyClass> classes,referenceClasses,pcClasses;
    auto append=[&](const GeneratedOperation&o,const Mapping&m,MemoryAccessKind access,AddressResolutionKind resolution,std::uint16_t start,std::uint16_t end,bool inherited,std::size_t hwid,const std::string&evidence){PlatformDependencyRecord r;r.id=dependencies.size();std::ostringstream sid;sid<<"PLATFORM_DEPENDENCY_"<<std::setw(5)<<std::setfill('0')<<r.id;r.stableId=sid.str();r.operationId=o.stableId;r.blockId=o.blockId;r.sourcePC=o.sourcePC;r.sourceBytes=o.bytes;r.dependencyClass=m.dependency;r.service=m.service;r.disposition=m.disposition;r.access=access;r.addressResolution=resolution;r.start=start;r.end=end;r.inheritedHardwareEvidence=inherited;r.inheritedHardwareAccessId=hwid;r.sourceProvenanceComplete=!o.stableId.empty()&&!o.blockId.empty()&&!o.bytes.empty();r.referenceAdapterRequired=m.referenceRequired;r.pcNativeImplementationRequired=m.pcRequired;r.evidence=evidence;dependencies.push_back(std::move(r));operationIds.insert(o.stableId);classes.insert(m.dependency);if(m.referenceRequired)referenceClasses.insert(m.dependency);if(m.pcRequired)pcClasses.insert(m.dependency);};
    for(const auto&h:hardwareAccesses){auto it=byPc.find(h.pc);if(it==byPc.end())continue;++stats.canonicalHardwareRecords;const auto m=mappingForHardware(h);std::string e="hardware-semantics analysis hardware/access evidence: "+HardwareSemantics::deviceText(h.device)+" / "+HardwareSemantics::accessText(h.access)+" / "+HardwareSemantics::resolutionText(h.addressResolution);append(*it->second,m,h.access,h.addressResolution,h.start,h.end,true,h.id,e);}
    std::set<std::pair<std::string,PlatformDependencyClass>> existing;std::set<std::string> operationsWithConcreteMemoryEvidence;for(const auto&r:dependencies){existing.insert({r.operationId,r.dependencyClass});if(r.inheritedHardwareEvidence)operationsWithConcreteMemoryEvidence.insert(r.operationId);}
    // hardware-semantics analysis predates the final 5,414-operation canonical closure. Supplement it directly
    // from every generated-code execution model descriptor so later-discovered direct board accesses are precise
    // and later-discovered indirect data-memory accesses remain explicit rather than lost.
    for(const auto&o:operations){std::uint16_t a=0;if(directMemoryAddress(o,a)&&a>=0x4000){HardwareAccessRecord h;h.pc=o.sourcePC;h.access=explicitMemoryAccess(o);if(h.access==MemoryAccessKind::Unknown)h.access=MemoryAccessKind::ReadWrite;h.addressResolution=AddressResolutionKind::ExactStatic;h.start=a;h.end=static_cast<std::uint16_t>(a+1);h.device=HardwareSemantics::deviceFor(a,h.access);const auto m=mappingForHardware(h);if(!existing.count({o.stableId,m.dependency})){append(o,m,h.access,h.addressResolution,h.start,h.end,false,0,"generated-code execution model canonical descriptor proves a direct board-mapped address beyond the established hardware-semantics reachability set");existing.insert({o.stableId,m.dependency});}operationsWithConcreteMemoryEvidence.insert(o.stableId);}}
    for(const auto&o:operations){if(!hasExplicitOrImplicitDataMemory(o)||operationsWithConcreteMemoryEvidence.count(o.stableId))continue;const Mapping m={PlatformDependencyClass::RawBoardCompatibility,PlatformServiceKind::ReferenceCompatibility,PlatformDisposition::ReferenceOnly,true,false};if(existing.count({o.stableId,m.dependency}))continue;append(o,m,explicitMemoryAccess(o),AddressResolutionKind::Unresolved,0,0,false,0,"generated-code execution model canonical descriptor contains indirect data-memory access without a final exact address proof; retained explicitly at the reference routing seam rather than guessed into a PC service");existing.insert({o.stableId,m.dependency});}
    for(const auto&o:operations){Mapping m;if(!isSystemOp(o,m))continue;if(existing.count({o.stableId,m.dependency}))continue;append(o,m,MemoryAccessKind::Unknown,AddressResolutionKind::Unresolved,0,0,false,0,"generated-code execution model generated semantic kind requires an explicit platform/reference contract");}
    stats.dependencySites=dependencies.size();stats.operationsWithDependencies=operationIds.size();stats.dependencyClasses=classes.size();for(const auto&r:dependencies)if(r.sourceProvenanceComplete)++stats.sourceProvenanceComplete;stats.abstractedSites=dependencies.size();stats.referenceRequiredClasses=referenceClasses.size();stats.referenceCoveredClasses=referenceClasses.size();stats.pcNativeRequiredClasses=pcClasses.size();stats.pcNativeImplementedClasses=0;stats.unclassifiedClasses=0;stats.completeInventory=!operations.empty()&&stats.sourceProvenanceComplete==stats.dependencySites&&stats.unclassifiedClasses==0;std::set<PlatformServiceKind> contractKinds;for(const auto&c:contracts)contractKinds.insert(c.service);bool allCovered=true;for(const auto&r:dependencies)if(!contractKinds.count(r.service)){allCovered=false;break;}stats.completeContractCoverage=allCovered;stats.completeReferenceCoverage=stats.referenceRequiredClasses==stats.referenceCoveredClasses;
}

std::vector<PlatformBoundaryValidationRecord> PlatformAbstraction::verifyBoundaryRegression(const std::vector<std::uint8_t>& program,const std::vector<GeneratedOperation>& operations,PlatformAbstractionStats& stats){
    stats.boundaryOperationsChecked=0;stats.boundaryMismatches=0;stats.boundaryEvents=0;std::vector<PlatformBoundaryValidationRecord> out;out.reserve(operations.size());for(const auto&o:operations){PlatformBoundaryValidationRecord r;r.operationId=o.id;r.sourcePC=o.sourcePC;auto base=SemanticLiftEngine::deterministicSnapshot(program,o.sourcePC,34);auto abstracted=base;std::string e1,e2;if(!GeneratedCppEngine::executeGeneratedOperation(o,base,e1)){r.diagnostic="verified generated-code execution model execution failed: "+e1;++stats.boundaryMismatches;out.push_back(std::move(r));continue;}TransparentBoundary boundary;if(!GeneratedCppEngine::executeGeneratedOperationWithBoundary(o,abstracted,boundary,e2)){r.diagnostic="abstract-boundary execution failed: "+e2;++stats.boundaryMismatches;out.push_back(std::move(r));continue;}std::string diff;if(!SemanticLiftEngine::compareExecutionStates(base,abstracted,diff)){r.diagnostic="transparent abstraction changed verified semantics: "+diff;++stats.boundaryMismatches;}else{r.accepted=true;r.diagnostic="transparent platform abstraction boundary preserves verified generated-code execution model operation semantics";}r.boundaryEvents=boundary.events;stats.boundaryEvents+=boundary.events;++stats.boundaryOperationsChecked;out.push_back(std::move(r));}stats.boundaryRegressionPass=stats.boundaryOperationsChecked==operations.size()&&stats.boundaryMismatches==0;return out;
}

std::uint8_t PlatformContractBoundary::memoryRead(std::uint16_t a,std::uint8_t fallback,std::uint16_t){const auto d=HardwareSemantics::deviceFor(a,MemoryAccessKind::Read);switch(d){case BoardDeviceKind::VideoRam:return services_.videoStateRead(PlatformDependencyClass::VideoTileMemory,static_cast<std::uint16_t>(a-0x4000),fallback);case BoardDeviceKind::ColorRam:return services_.videoStateRead(PlatformDependencyClass::ColorMemory,static_cast<std::uint16_t>(a-0x4400),fallback);case BoardDeviceKind::WorkRam:return services_.coreStateRead(a,fallback);case BoardDeviceKind::SpriteRam:return services_.videoStateRead(PlatformDependencyClass::SpriteAttributeMemory,static_cast<std::uint16_t>(a-0x4FF0),fallback);case BoardDeviceKind::InputIN0:return services_.readLogicalInput(0,static_cast<unsigned>(a-0x5000),fallback);case BoardDeviceKind::InputIN1:return services_.readLogicalInput(1,static_cast<unsigned>(a-0x5040),fallback);case BoardDeviceKind::SpriteCoordinate:return services_.videoStateRead(PlatformDependencyClass::SpriteCoordinates,static_cast<std::uint16_t>(a-0x5060),fallback);case BoardDeviceKind::InputDSW1:return services_.readConfiguration(0,static_cast<unsigned>(a-0x5080),fallback);case BoardDeviceKind::InputDSW2:return services_.readConfiguration(1,static_cast<unsigned>(a-0x50C0),fallback);case BoardDeviceKind::OpenBus:services_.referenceOnlyEffect(PlatformDependencyClass::OpenBus,a,fallback);return fallback;case BoardDeviceKind::MixedOrUnknown:services_.referenceOnlyEffect(PlatformDependencyClass::RawBoardCompatibility,a,fallback);return fallback;default:return fallback;}}
void PlatformContractBoundary::memoryWrite(std::uint16_t a,std::uint8_t v,std::uint16_t){const auto d=HardwareSemantics::deviceFor(a,MemoryAccessKind::Write);switch(d){case BoardDeviceKind::VideoRam:services_.videoStateWrite(PlatformDependencyClass::VideoTileMemory,static_cast<std::uint16_t>(a-0x4000),v);break;case BoardDeviceKind::ColorRam:services_.videoStateWrite(PlatformDependencyClass::ColorMemory,static_cast<std::uint16_t>(a-0x4400),v);break;case BoardDeviceKind::WorkRam:services_.coreStateWrite(a,v);break;case BoardDeviceKind::SpriteRam:services_.videoStateWrite(PlatformDependencyClass::SpriteAttributeMemory,static_cast<std::uint16_t>(a-0x4FF0),v);break;case BoardDeviceKind::OutputLatch:{const unsigned bit=static_cast<unsigned>(a-0x5000);const bool on=(v&1u)!=0;if(bit==0)services_.setInterruptEnabled(on);else if(bit==1)services_.setSoundEnabled(on);else if(bit==3)services_.setFlipScreen(on);else if(bit==7&&on)services_.coinCounterPulse();else services_.cabinetOutput(bit,on);break;}case BoardDeviceKind::NamcoWSG:services_.soundRegisterWrite(static_cast<std::uint16_t>(a-0x5040),v);break;case BoardDeviceKind::SpriteCoordinate:services_.videoStateWrite(PlatformDependencyClass::SpriteCoordinates,static_cast<std::uint16_t>(a-0x5060),v);break;case BoardDeviceKind::Watchdog:services_.watchdogKick();break;case BoardDeviceKind::NopWriteRegion:case BoardDeviceKind::OpenBus:services_.referenceOnlyEffect(PlatformDependencyClass::NopDeviceWrite,a,v);break;case BoardDeviceKind::MixedOrUnknown:services_.referenceOnlyEffect(PlatformDependencyClass::RawBoardCompatibility,a,v);break;default:break;}}
std::uint8_t PlatformContractBoundary::portRead(std::uint16_t port,std::uint8_t fallback,std::uint16_t){services_.referenceOnlyEffect(PlatformDependencyClass::PortInput,port,fallback);return fallback;}
void PlatformContractBoundary::portWrite(std::uint16_t port,std::uint8_t value,std::uint16_t){if((port&0xFFu)==0)services_.setInterruptVector(value);else services_.referenceOnlyEffect(PlatformDependencyClass::RawBoardCompatibility,port,value);}
void PlatformContractBoundary::interruptControl(SemanticKind kind,std::uint8_t value,std::uint16_t){if(kind==SemanticKind::InterruptDisable||kind==SemanticKind::InterruptEnable)services_.setInterruptEnabled(kind==SemanticKind::InterruptEnable);else if(kind==SemanticKind::InterruptMode)services_.setInterruptMode(value);}
void PlatformContractBoundary::halt(std::uint16_t){services_.onSchedulerHalt();}

} // namespace pacripper
