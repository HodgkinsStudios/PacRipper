// PacRipper native runtime native PC runtime/platform foundation
// Created by Jacob Hodgkins

#include "NativeRuntime.h"

#include <algorithm>
#include <fstream>
#include <set>
#include <sstream>

namespace pacripper {

bool RuntimeResourceStore::addUserSupplied(const std::string& name,const std::vector<std::uint8_t>& bytes,const std::string& path,std::string& error){
    if(name.empty()){error="resource logical name is empty";return false;}
    if(bytes.empty()){error="resource is empty";return false;}
    Entry e;e.bytes=bytes;e.record.logicalName=name;e.record.sourcePath=path;e.record.size=bytes.size();e.record.userSupplied=true;entries_[name]=std::move(e);error.clear();return true;
}
bool RuntimeResourceStore::loadUserSuppliedFile(const std::string& name,const std::string& path,std::size_t expected,std::string& error){
    std::ifstream in(path.c_str(),std::ios::binary);if(!in){error="failed to open user-supplied resource: "+path;return false;}
    std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(in)),std::istreambuf_iterator<char>());
    if(!in.eof()){error="failed while reading user-supplied resource: "+path;return false;}
    if(expected&&bytes.size()!=expected){std::ostringstream o;o<<"resource size mismatch: expected "<<expected<<" got "<<bytes.size();error=o.str();return false;}
    return addUserSupplied(name,bytes,path,error);
}
const std::vector<std::uint8_t>* RuntimeResourceStore::find(const std::string& name) const{auto it=entries_.find(name);return it==entries_.end()?nullptr:&it->second.bytes;}
std::vector<RuntimeResourceRecord> RuntimeResourceStore::records() const{std::vector<RuntimeResourceRecord> out;for(const auto&kv:entries_)out.push_back(kv.second.record);return out;}
void RuntimeResourceStore::clear(){entries_.clear();}

NativeRuntime::NativeRuntime():videoTiles_(0x400,0),colors_(0x400,0),spriteAttributes_(0x10,0),spriteCoordinates_(0x10,0){powerOnReset();}

std::size_t NativeRuntime::inputIndex(LogicalInput input){return static_cast<std::size_t>(input);}
void NativeRuntime::powerOnReset(){
    inputs_.fill(false);config_={};phase_=RuntimeLifecycleState::Stopped;elapsedNanoseconds_=0;schedulerNumerator_=0;frameCounter_=0;schedulerYieldCount_=0;logicTicksEnabled_=false;compatibilityInterruptMode_=0;compatibilityInterruptVector_=0;watchdogKickCount_=0;watchdogKickBaseline_=0;watchdogAgeFrames_=0;watchdogResetRequests_=0;resetRequested_=false;coinCounterPulses_=0;cabinetOutputs_.fill(false);coreState_.clear();std::fill(videoTiles_.begin(),videoTiles_.end(),0);std::fill(colors_.begin(),colors_.end(),0);std::fill(spriteAttributes_.begin(),spriteAttributes_.end(),0);std::fill(spriteCoordinates_.begin(),spriteCoordinates_.end(),0);flipScreenStub_=false;soundRegistersStub_.fill(0);soundEnabledStub_=false;referenceOnlyEvents_=0;++resetCount_;
}
void NativeRuntime::softReset(){
    releaseMomentaryInputs();phase_=RuntimeLifecycleState::Running;elapsedNanoseconds_=0;schedulerNumerator_=0;frameCounter_=0;schedulerYieldCount_=0;logicTicksEnabled_=false;compatibilityInterruptMode_=0;compatibilityInterruptVector_=0;watchdogKickBaseline_=watchdogKickCount_;watchdogAgeFrames_=0;resetRequested_=false;cabinetOutputs_.fill(false);flipScreenStub_=false;soundEnabledStub_=false;++resetCount_;
}
void NativeRuntime::startSession(){++sessionId_;phase_=RuntimeLifecycleState::Running;elapsedNanoseconds_=0;schedulerNumerator_=0;frameCounter_=0;watchdogAgeFrames_=0;watchdogKickBaseline_=watchdogKickCount_;resetRequested_=false;}
void NativeRuntime::stopSession(){phase_=RuntimeLifecycleState::Stopped;releaseMomentaryInputs();}
void NativeRuntime::setPaused(bool paused){if(phase_==RuntimeLifecycleState::Stopped)return;phase_=paused?RuntimeLifecycleState::Paused:RuntimeLifecycleState::Running;}
void NativeRuntime::setInput(LogicalInput input,bool pressed){inputs_[inputIndex(input)]=pressed;}
bool NativeRuntime::input(LogicalInput input) const{return inputs_[inputIndex(input)];}
void NativeRuntime::releaseMomentaryInputs(){const bool cocktail=input(LogicalInput::CocktailCabinet);const bool rack=input(LogicalInput::RackAdvance);inputs_.fill(false);setInput(LogicalInput::CocktailCabinet,cocktail);setInput(LogicalInput::RackAdvance,rack);}
std::uint8_t NativeRuntime::canonicalInputByte(unsigned bank) const{
    std::uint8_t v=0xFF;auto low=[&](unsigned bit,LogicalInput i){if(input(i))v=static_cast<std::uint8_t>(v&~(1u<<bit));};
    if(bank==0){low(0,LogicalInput::P1Up);low(1,LogicalInput::P1Left);low(2,LogicalInput::P1Right);low(3,LogicalInput::P1Down);low(4,LogicalInput::RackAdvance);low(5,LogicalInput::Coin1);low(6,LogicalInput::Coin2);low(7,LogicalInput::Service);return v;}
    if(bank==1){low(0,LogicalInput::P2Up);low(1,LogicalInput::P2Left);low(2,LogicalInput::P2Right);low(3,LogicalInput::P2Down);low(4,LogicalInput::ServiceTest);low(5,LogicalInput::Start1);low(6,LogicalInput::Start2);low(7,LogicalInput::CocktailCabinet);return v;}
    return 0xFF;
}
std::uint64_t NativeRuntime::advanceNanoseconds(std::uint64_t ns){
    if(phase_!=RuntimeLifecycleState::Running)return 0;
    elapsedNanoseconds_+=ns;
    // Rational accumulator avoids floating-point timing drift. ns*6.144MHz is safe
    // for normal host deltas; chunk large deltas to avoid integer overflow.
    std::uint64_t frames=0;const std::uint64_t threshold=kPixelsPerFrame*kNanosecondsPerSecond;
    while(ns){const std::uint64_t chunk=std::min<std::uint64_t>(ns,1000000000ULL);schedulerNumerator_+=chunk*kPixelClockHz;ns-=chunk;while(schedulerNumerator_>=threshold){schedulerNumerator_-=threshold;++frameCounter_;++frames;if(watchdogKickCount_!=watchdogKickBaseline_){watchdogKickBaseline_=watchdogKickCount_;watchdogAgeFrames_=0;}else if(++watchdogAgeFrames_>=kWatchdogFrames){++watchdogResetRequests_;watchdogAgeFrames_=0;resetRequested_=true;}}}
    return frames;
}
bool NativeRuntime::consumeResetRequest(){const bool r=resetRequested_;resetRequested_=false;return r;}

std::uint8_t NativeRuntime::coreStateRead(std::uint16_t a,std::uint8_t fallback){auto it=coreState_.find(a);return it==coreState_.end()?fallback:it->second;}
void NativeRuntime::coreStateWrite(std::uint16_t a,std::uint8_t v){coreState_[a]=v;}
std::vector<std::uint8_t>* NativeRuntime::videoRegion(PlatformDependencyClass r){switch(r){case PlatformDependencyClass::VideoTileMemory:return &videoTiles_;case PlatformDependencyClass::ColorMemory:return &colors_;case PlatformDependencyClass::SpriteAttributeMemory:return &spriteAttributes_;case PlatformDependencyClass::SpriteCoordinates:return &spriteCoordinates_;default:return nullptr;}}
const std::vector<std::uint8_t>* NativeRuntime::videoRegion(PlatformDependencyClass r) const{switch(r){case PlatformDependencyClass::VideoTileMemory:return &videoTiles_;case PlatformDependencyClass::ColorMemory:return &colors_;case PlatformDependencyClass::SpriteAttributeMemory:return &spriteAttributes_;case PlatformDependencyClass::SpriteCoordinates:return &spriteCoordinates_;default:return nullptr;}}
std::uint8_t NativeRuntime::videoStateRead(PlatformDependencyClass r,std::uint16_t o,std::uint8_t fallback){const auto*p=videoRegion(r);return p&&o<p->size()?(*p)[o]:fallback;}
void NativeRuntime::videoStateWrite(PlatformDependencyClass r,std::uint16_t o,std::uint8_t v){auto*p=videoRegion(r);if(p&&o<p->size())(*p)[o]=v;}
void NativeRuntime::setFlipScreen(bool e){flipScreenStub_=e;}
void NativeRuntime::soundRegisterWrite(std::uint16_t i,std::uint8_t v){if(i<soundRegistersStub_.size())soundRegistersStub_[i]=v;}
void NativeRuntime::setSoundEnabled(bool e){soundEnabledStub_=e;}
std::uint8_t NativeRuntime::readLogicalInput(unsigned bank,unsigned,std::uint8_t fallback){return bank<2?canonicalInputByte(bank):fallback;}
std::uint8_t NativeRuntime::readConfiguration(unsigned bank,unsigned,std::uint8_t fallback){if(bank==0)return config_.canonicalDip1;if(bank==1)return config_.canonicalDip2;return fallback;}
void NativeRuntime::setInterruptEnabled(bool e){logicTicksEnabled_=e;}
void NativeRuntime::setInterruptMode(std::uint8_t m){compatibilityInterruptMode_=m;}
void NativeRuntime::setInterruptVector(std::uint8_t v){compatibilityInterruptVector_=v;}
void NativeRuntime::onSchedulerHalt(){++schedulerYieldCount_;}
void NativeRuntime::watchdogKick(){++watchdogKickCount_;watchdogAgeFrames_=0;watchdogKickBaseline_=watchdogKickCount_;}
void NativeRuntime::cabinetOutput(unsigned o,bool e){if(o<cabinetOutputs_.size())cabinetOutputs_[o]=e;}
void NativeRuntime::coinCounterPulse(){++coinCounterPulses_;}
void NativeRuntime::referenceOnlyEffect(PlatformDependencyClass,std::uint16_t,std::uint8_t){++referenceOnlyEvents_;}

std::string NativeRuntimeFoundation::logicalInputText(LogicalInput i){switch(i){case LogicalInput::P1Up:return"p1-up";case LogicalInput::P1Left:return"p1-left";case LogicalInput::P1Right:return"p1-right";case LogicalInput::P1Down:return"p1-down";case LogicalInput::P2Up:return"p2-up";case LogicalInput::P2Left:return"p2-left";case LogicalInput::P2Right:return"p2-right";case LogicalInput::P2Down:return"p2-down";case LogicalInput::Coin1:return"coin-1";case LogicalInput::Coin2:return"coin-2";case LogicalInput::Start1:return"start-1";case LogicalInput::Start2:return"start-2";case LogicalInput::Service:return"service";case LogicalInput::ServiceTest:return"service-test";case LogicalInput::RackAdvance:return"rack-advance";case LogicalInput::CocktailCabinet:return"cocktail-cabinet";}return"unknown";}
std::string NativeRuntimeFoundation::lifecyclePhaseText(RuntimeLifecycleState p){switch(p){case RuntimeLifecycleState::Stopped:return"stopped";case RuntimeLifecycleState::Running:return"running";case RuntimeLifecycleState::Paused:return"paused";}return"unknown";}
void NativeRuntimeFoundation::buildProgress(const std::vector<PlatformDependencyRecord>& deps,std::vector<RuntimeNativeClassRecord>& out,NativeRuntimeStats& stats){
    out.clear();stats={};stats.dependencySites=deps.size();std::map<PlatformDependencyClass,RuntimeNativeClassRecord> m;
    for(const auto&d:deps){auto&r=m[d.dependencyClass];r.dependencyClass=d.dependencyClass;r.service=d.service;r.required=r.required||d.pcNativeImplementationRequired;++r.dependencySites;}
    stats.dependencyClasses=m.size();for(auto&kv:m){auto&r=kv.second;if(r.required){++stats.pcNativeRequiredClasses;switch(r.service){case PlatformServiceKind::Input:case PlatformServiceKind::Timing:case PlatformServiceKind::Configuration:case PlatformServiceKind::Lifecycle:r.implemented=true;r.evidence="native runtime provides deterministic PC-native host state/service implementation";break;case PlatformServiceKind::Renderer:case PlatformServiceKind::Audio:r.stubOnly=true;r.evidence="native runtime integration backing only; dedicated native fidelity replacement remains native video/audio";break;default:r.evidence="not a native runtime native product dependency";break;}if(r.implemented)++stats.pcNativeImplementedClasses;if(r.stubOnly)++stats.rendererAudioStubClasses;}else r.evidence="not part of the PC-native-required denominator";out.push_back(r);}
    stats.pcNativeRemainingClasses=stats.pcNativeRequiredClasses-stats.pcNativeImplementedClasses;
}
std::vector<RuntimeValidationRecord> NativeRuntimeFoundation::runDeterministicValidation(NativeRuntimeStats& stats){
    std::vector<RuntimeValidationRecord> out;auto add=[&](const std::string&id,bool ok,const std::string&diag){RuntimeValidationRecord r;r.stableId=id;r.passed=ok;r.diagnostic=diag;out.push_back(r);};
    NativeRuntime h;h.startSession();h.setInput(LogicalInput::P1Up,true);h.setInput(LogicalInput::Coin1,true);add("RUNTIME_INPUT",h.canonicalInputByte(0)==0xDE,"logical action state composes deterministic active-low compatibility input");
    RuntimeConfig c;c.canonicalDip1=0x49;c.canonicalDip2=0xFE;h.setConfiguration(c);add("RUNTIME_CONFIG",h.readConfiguration(0,0,0)==0x49&&h.readConfiguration(1,0,0)==0xFE,"PC configuration state is deterministic and independent of frontend bindings");
    const auto f1=h.advanceNanoseconds(1000000000ULL);const auto f2=h.advanceNanoseconds(1000000000ULL);add("RUNTIME_SCHEDULER",f1==60&&f2==61&&h.frameCounter()==121,"rational host scheduler reproduces 6.144MHz/(384*264) frame cadence without floating drift");
    h.setPaused(true);const auto before=h.frameCounter();h.advanceNanoseconds(500000000ULL);add("RUNTIME_PAUSE",h.frameCounter()==before,"paused native host does not advance game frames");h.setPaused(false);
    h.softReset();h.watchdogKick();h.advanceNanoseconds(100000000ULL);add("RUNTIME_LIFECYCLE",h.watchdogKickCount()==1&&!h.consumeResetRequest(),"lifecycle heartbeat/reset state remains deterministic after a host watchdog kick");
    const auto sid=h.sessionId();h.softReset();add("RUNTIME_RESET",h.sessionId()==sid&&h.frameCounter()==0&&h.phase()==RuntimeLifecycleState::Running,"soft reset preserves session identity while resetting scheduler/lifecycle state");
    std::string e;std::vector<std::uint8_t> blob={1,2,3,4};const bool ar=h.resources().addUserSupplied("test.asset",blob,"<headless>",e);const auto*p=h.resources().find("test.asset");add("RUNTIME_RESOURCES",ar&&p&&*p==blob,"user-supplied resource catalog stores external bytes by logical name without embedding them in source");
    PlatformContractBoundary b(h);b.memoryWrite(0x5000,1,0x1234);b.memoryWrite(0x5007,1,0x1235);add("RUNTIME_PLATFORM_ADAPTER",h.logicTicksEnabled()&&h.coinCounterPulses()==1,"verified platform abstraction adapter routes timing/lifecycle events into the native host without a PCB runtime");
    stats.validationChecks=out.size();for(const auto&r:out)if(r.passed)++stats.validationPassed;else ++stats.validationFailed;stats.deterministicHostValidation=stats.validationFailed==0;stats.foundationReady=stats.deterministicHostValidation&&stats.pcNativeRequiredClasses>0&&stats.pcNativeImplementedClasses>0;return out;
}

} // namespace pacripper
