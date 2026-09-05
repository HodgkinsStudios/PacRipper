// PacRipper native audio native PC audio replacement
// Created by Jacob Hodgkins

#include "NativeAudio.h"

#include <algorithm>
#include <cstdlib>
#include <map>

namespace pacripper {

const char* NativeAudio::waveformResourceName(){return "pacman.audio.waveform-prom";}

NativeAudio::NativeAudio(){resetPlayback();}

bool NativeAudio::loadCanonicalWaveforms(const RuntimeResourceStore& resources,std::string& error){
    const auto* bytes=resources.find(waveformResourceName());
    if(bytes==nullptr){error="missing user-supplied canonical audio waveform resource";return false;}
    return loadWaveformProm(*bytes,error);
}

bool NativeAudio::loadWaveformProm(const std::vector<std::uint8_t>& bytes,std::string& error){
    if(bytes.size()!=WaveformPromSize){error="native audio waveform resource must be exactly 256 bytes";return false;}
    if(!PacmanWaveformCodec::decode(bytes,waveformEntries_,nullptr,error))return false;
    waveformsReady_=true;error.clear();return true;
}

void NativeAudio::resetPlayback(){
    for(auto& voice:voices_)voice={};
    enabled_=false;samplesGenerated_=0;
}

bool NativeAudio::setVoiceWaveform(std::size_t voice,std::uint8_t waveform){
    if(voice>=VoiceCount)return false;
    voices_[voice].waveform=static_cast<std::uint8_t>(waveform&7u);
    return true;
}
bool NativeAudio::setVoiceFrequency(std::size_t voice,std::uint32_t frequencyWord){
    if(voice>=VoiceCount)return false;
    voices_[voice].frequencyWord=frequencyWord&FrequencyMask;
    return true;
}
bool NativeAudio::setVoiceVolume(std::size_t voice,std::uint8_t volume){
    if(voice>=VoiceCount)return false;
    voices_[voice].volume=static_cast<std::uint8_t>(volume&0x0Fu);
    return true;
}
bool NativeAudio::setVoice(std::size_t voice,std::uint32_t frequencyWord,std::uint8_t waveform,std::uint8_t volume){
    if(voice>=VoiceCount)return false;
    voices_[voice].frequencyWord=frequencyWord&FrequencyMask;
    voices_[voice].waveform=static_cast<std::uint8_t>(waveform&7u);
    voices_[voice].volume=static_cast<std::uint8_t>(volume&0x0Fu);
    return true;
}

std::int16_t NativeAudio::generateSample(){
    if(!enabled_||!waveformsReady_)return 0;
    int mix=0;
    for(auto& voice:voices_){
        if(voice.volume==0)continue;
        const std::uint32_t position=(voice.phase>>16)&0x1Fu;
        const std::size_t address=PacmanWaveformCodec::address(voice.waveform,static_cast<std::uint8_t>(position));
        const int wave=static_cast<int>(waveformEntries_[address].signedSample);
        mix+=wave*static_cast<int>(voice.volume);
        voice.phase+=voice.frequencyWord;
    }
    constexpr int mixResolution=128*static_cast<int>(VoiceCount);
    int scaled=(mix*32768)/mixResolution;
    scaled=std::max(-32768,std::min(32767,scaled));
    return static_cast<std::int16_t>(scaled);
}

std::vector<std::int16_t> NativeAudio::renderSamples(std::size_t sampleCount){
    std::vector<std::int16_t> out;renderSamples(sampleCount,out);return out;
}
void NativeAudio::renderSamples(std::size_t sampleCount,std::vector<std::int16_t>& output){
    output.clear();output.reserve(sampleCount);
    for(std::size_t i=0;i<sampleCount;++i)output.push_back(generateSample());
    samplesGenerated_+=sampleCount;
}

std::uint64_t NativeAudio::pcmFnv1a(const std::vector<std::int16_t>& samples){
    std::uint64_t hash=1469598103934665603ULL;constexpr std::uint64_t prime=1099511628211ULL;
    for(const auto sample:samples){const std::uint16_t u=static_cast<std::uint16_t>(sample);const std::uint8_t bytes[2]={static_cast<std::uint8_t>(u&0xFFu),static_cast<std::uint8_t>((u>>8)&0xFFu)};for(const auto byte:bytes){hash^=byte;hash*=prime;}}
    return hash;
}
int NativeAudio::peakAmplitude(const std::vector<std::int16_t>& samples){
    int peak=0;for(const auto sample:samples){const int v=static_cast<int>(sample);peak=std::max(peak,v<0?-v:v);}return peak;
}
bool NativeAudio::allSilent(const std::vector<std::int16_t>& samples){return std::all_of(samples.begin(),samples.end(),[](std::int16_t sample){return sample==0;});}

void ReferenceAudioAdapter::reset(){registers_.fill(0);}
std::uint8_t ReferenceAudioAdapter::registerValue(std::size_t index) const{return index<registers_.size()?registers_[index]:0xFF;}
void ReferenceAudioAdapter::syncWaveform(std::size_t voice,NativeAudio& audio){
    static constexpr std::size_t indexes[3]={0x05,0x0A,0x0F};audio.setVoiceWaveform(voice,registers_[indexes[voice]]);
}
void ReferenceAudioAdapter::syncFrequency(std::size_t voice,NativeAudio& audio){
    std::uint32_t frequency=0;
    if(voice==0){frequency=static_cast<std::uint32_t>(registers_[0x10]);frequency|=static_cast<std::uint32_t>(registers_[0x11])<<4;frequency|=static_cast<std::uint32_t>(registers_[0x12])<<8;frequency|=static_cast<std::uint32_t>(registers_[0x13])<<12;frequency|=static_cast<std::uint32_t>(registers_[0x14])<<16;}
    else {const std::size_t base=voice==1?0x16:0x1B;frequency=static_cast<std::uint32_t>(registers_[base])<<4;frequency|=static_cast<std::uint32_t>(registers_[base+1])<<8;frequency|=static_cast<std::uint32_t>(registers_[base+2])<<12;frequency|=static_cast<std::uint32_t>(registers_[base+3])<<16;}
    audio.setVoiceFrequency(voice,frequency);
}
void ReferenceAudioAdapter::syncVolume(std::size_t voice,NativeAudio& audio){
    static constexpr std::size_t indexes[3]={0x15,0x1A,0x1F};audio.setVoiceVolume(voice,registers_[indexes[voice]]);
}
void ReferenceAudioAdapter::write(std::uint16_t index,std::uint8_t value,NativeAudio& audio){
    if(index>=registers_.size())return;
    registers_[index]=static_cast<std::uint8_t>(value&0x0Fu);
    if(index==0x05){syncWaveform(0,audio);return;}if(index==0x0A){syncWaveform(1,audio);return;}if(index==0x0F){syncWaveform(2,audio);return;}
    if(index>=0x10&&index<=0x14){syncFrequency(0,audio);return;}if(index==0x15){syncVolume(0,audio);return;}
    if(index>=0x16&&index<=0x19){syncFrequency(1,audio);return;}if(index==0x1A){syncVolume(1,audio);return;}
    if(index>=0x1B&&index<=0x1E){syncFrequency(2,audio);return;}if(index==0x1F)syncVolume(2,audio);
}

AudioNativeRuntime::AudioNativeRuntime(){referenceAudioAdapter_.reset();}
void AudioNativeRuntime::resetNativeAudio(){audio_.resetPlayback();referenceAudioAdapter_.reset();}
void AudioNativeRuntime::soundRegisterWrite(std::uint16_t index,std::uint8_t value){referenceAudioAdapter_.write(index,value,audio_);}
void AudioNativeRuntime::setSoundEnabled(bool enabled){audio_.setEnabled(enabled);}

void NativeAudioReplacement::buildProgress(const std::vector<PlatformDependencyRecord>& dependencies,bool rendererVerified,bool audioVerified,std::vector<AudioNativeClassRecord>& classes,NativeAudioStats& stats){
    classes.clear();
    stats.dependencySites=0;stats.dependencyClasses=0;
    stats.pcNativeRequiredClasses=0;stats.pcNativeImplementedClasses=0;stats.pcNativeRemainingClasses=0;
    stats.requiredDependencySites=0;stats.nativeCompleteRequiredSites=0;stats.remainingRequiredSites=0;
    stats.audioRequiredClasses=0;stats.audioImplementedClasses=0;stats.audioRequiredSites=0;stats.audioImplementedSites=0;
    stats.audioReady=false;stats.allNativeHardwareClassesComplete=false;
    std::map<PlatformDependencyClass,AudioNativeClassRecord> grouped;
    for(const auto& dependency:dependencies){auto& record=grouped[dependency.dependencyClass];record.dependencyClass=dependency.dependencyClass;record.service=dependency.service;record.required=record.required||dependency.pcNativeImplementationRequired;++record.dependencySites;}
    stats.dependencySites=dependencies.size();stats.dependencyClasses=grouped.size();
    for(auto& entry:grouped){auto& record=entry.second;if(record.required){++stats.pcNativeRequiredClasses;stats.requiredDependencySites+=record.dependencySites;switch(record.service){case PlatformServiceKind::Input:case PlatformServiceKind::Timing:case PlatformServiceKind::Configuration:case PlatformServiceKind::Lifecycle:record.implemented=true;record.evidence="native runtime deterministic PC-native host implementation retained";break;case PlatformServiceKind::Renderer:record.implemented=rendererVerified;record.evidence=rendererVerified?"native video renderer native decoded-asset/framebuffer renderer retained":"native video renderer renderer validation incomplete";break;case PlatformServiceKind::Audio:record.audioClass=true;++stats.audioRequiredClasses;stats.audioRequiredSites+=record.dependencySites;record.implemented=audioVerified;record.evidence=audioVerified?"native audio native three-voice waveform/pitch/volume PCM engine with deterministic proof":"native audio native audio validation incomplete";break;default:record.evidence="not a native product class completed by native audio";break;}if(record.implemented){++stats.pcNativeImplementedClasses;stats.nativeCompleteRequiredSites+=record.dependencySites;if(record.audioClass){++stats.audioImplementedClasses;stats.audioImplementedSites+=record.dependencySites;}}}else record.evidence="not part of PC-native-required denominator";classes.push_back(record);}
    stats.pcNativeRemainingClasses=stats.pcNativeRequiredClasses-stats.pcNativeImplementedClasses;stats.remainingRequiredSites=stats.requiredDependencySites-stats.nativeCompleteRequiredSites;stats.audioReady=audioVerified&&stats.audioRequiredClasses>0&&stats.audioRequiredClasses==stats.audioImplementedClasses;stats.allNativeHardwareClassesComplete=stats.pcNativeRequiredClasses>0&&stats.pcNativeRemainingClasses==0&&stats.remainingRequiredSites==0&&stats.audioReady&&rendererVerified;
}

std::vector<AudioValidationRecord> NativeAudioReplacement::runSyntheticValidation(NativeAudioStats& stats){
    std::vector<AudioValidationRecord> out;auto add=[&](const std::string& id,bool passed,const std::string& diagnostic){AudioValidationRecord record;record.stableId=id;record.passed=passed;record.evidenceKind="internal-synthetic";record.diagnostic=diagnostic;out.push_back(record);};
    std::vector<std::uint8_t> waveform(NativeAudio::WaveformPromSize);for(std::size_t i=0;i<waveform.size();++i)waveform[i]=static_cast<std::uint8_t>(i&0x0Fu);
    NativeAudio audio;std::string error;add("AUDIO_ASSET_CONTRACT",!audio.loadWaveformProm(std::vector<std::uint8_t>(32,0),error)&&audio.loadWaveformProm(waveform,error),"native audio rejects malformed waveform data and accepts an exact 256-byte user-supplied table");
    const bool setters=audio.setVoice(0,0x1ABCDEu,0xFF,0xFF)&&audio.setVoice(1,0x23450u,3,11)&&audio.setVoice(2,0x34560u,6,7)&&!audio.setVoice(3,1,1,1);add("AUDIO_VOICE_API",setters&&audio.voices()[0].frequencyWord==(0x1ABCDEu&NativeAudio::FrequencyMask)&&audio.voices()[0].waveform==7&&audio.voices()[0].volume==15,"product-facing API owns bounded voice waveform, 20-bit pitch and volume state without public board registers");
    const auto phaseBefore=audio.voices()[0].phase;const auto silent=audio.renderSamples(128);add("AUDIO_DISABLED_SILENCE",NativeAudio::allSilent(silent)&&audio.voices()[0].phase==phaseBefore,"disabled native audio emits deterministic silence and does not advance voice phase");
    audio.resetPlayback();audio.loadWaveformProm(waveform,error);audio.setVoice(0,0x12345,0,15);audio.setVoice(1,0x23450,3,11);audio.setVoice(2,0x34560,6,7);audio.setEnabled(true);const auto toneA=audio.renderSamples(2048);const auto hashA=NativeAudio::pcmFnv1a(toneA);NativeAudio repeat;repeat.loadWaveformProm(waveform,error);repeat.setVoice(0,0x12345,0,15);repeat.setVoice(1,0x23450,3,11);repeat.setVoice(2,0x34560,6,7);repeat.setEnabled(true);const auto toneB=repeat.renderSamples(2048);const auto hashB=NativeAudio::pcmFnv1a(toneB);stats.syntheticTonePcmHash=hashA;add("AUDIO_REPEATABLE_PCM",hashA==hashB&&!NativeAudio::allSilent(toneA),"identical native voice state produces byte-stable non-silent signed-16-bit PCM");
    const int peak=NativeAudio::peakAmplitude(toneA);add("AUDIO_PCM_RANGE",peak>0&&peak<=32767,"three-voice mixer remains inside signed-16-bit PCM range under bounded 4-bit voice volumes");
    audio.setVoice(0,0x24680,5,9);const auto transitioned=audio.renderSamples(1024);const auto unmodifiedContinuation=repeat.renderSamples(1024);add("AUDIO_TRANSITION",NativeAudio::pcmFnv1a(transitioned)!=NativeAudio::pcmFnv1a(unmodifiedContinuation)&&audio.voices()[0].phase!=0,"native tone/SFX state changes alter subsequent PCM while preserving running oscillator phase");
    NativeAudio direct;NativeAudio adapted;direct.loadWaveformProm(waveform,error);adapted.loadWaveformProm(waveform,error);direct.setVoice(0,0x12345,0,15);direct.setVoice(1,0x23450,3,11);direct.setVoice(2,0x34560,6,7);ReferenceAudioAdapter adapter;adapter.reset();const struct Write{std::uint16_t index;std::uint8_t value;} writes[]={{0x05,0},{0x10,5},{0x11,4},{0x12,3},{0x13,2},{0x14,1},{0x15,15},{0x0A,3},{0x16,5},{0x17,4},{0x18,3},{0x19,2},{0x1A,11},{0x0F,6},{0x1B,6},{0x1C,5},{0x1D,4},{0x1E,3},{0x1F,7}};for(const auto& write:writes)adapter.write(write.index,write.value,adapted);direct.setEnabled(true);adapted.setEnabled(true);const auto directPcm=direct.renderSamples(1024);const auto adaptedPcm=adapted.renderSamples(1024);add("AUDIO_REFERENCE_ADAPTER",NativeAudio::pcmFnv1a(directPcm)==NativeAudio::pcmFnv1a(adaptedPcm)&&adapted.voices()[0].frequencyWord==0x12345&&adapted.voices()[1].frequencyWord==0x23450&&adapted.voices()[2].frequencyWord==0x34560,"compatibility register decoder maps full reference voice state into the same product-side PCM semantics");
    AudioNativeRuntime host;host.resources().addUserSupplied(NativeAudio::waveformResourceName(),waveform,"<synthetic>",error);const bool loaded=host.loadAudioAssets(error);PlatformContractBoundary boundary(host);boundary.memoryWrite(0x5001,1,0);boundary.memoryWrite(0x5045,2,0);boundary.memoryWrite(0x504A,4,0);boundary.memoryWrite(0x504F,6,0);add("AUDIO_DIRECT_SITE_BOUNDARY",loaded&&host.audio().enabled()&&host.audio().voices()[0].waveform==2&&host.audio().voices()[1].waveform==4&&host.audio().voices()[2].waveform==6,"the three canonical direct sound-register sites translate through the verified raw-address seam into native voice waveform state");
    NativeVideoStats videoStats;const auto previous=NativeVideo::runSyntheticValidation(videoStats);add("AUDIO_VIDEO_REGRESSION",previous.size()==8&&videoStats.validationFailed==0&&videoStats.deterministicNativeRenderer,"native video renderer native renderer and inherited native runtime host validation remain green");
    stats.validationChecks=out.size();for(const auto& record:out){if(record.passed)++stats.validationPassed;else ++stats.validationFailed;}stats.deterministicNativeAudio=stats.validationFailed==0;return out;
}

std::vector<AudioValidationRecord> NativeAudioReplacement::runCanonicalAssetValidation(const RuntimeResourceStore& resources,NativeAudioStats& stats){
    std::vector<AudioValidationRecord> out;auto add=[&](const std::string& id,bool passed,const std::string& diagnostic){AudioValidationRecord record;record.stableId=id;record.passed=passed;record.evidenceKind="reference-derived-canonical-assets";record.diagnostic=diagnostic;out.push_back(record);};
    NativeAudio audio;std::string error;if(!audio.loadCanonicalWaveforms(resources,error)){add("AUDIO_CANONICAL_ASSET",false,error);stats.canonicalAssetChecks=out.size();stats.canonicalAssetFailed=out.size();stats.canonicalAssetReferenceMatch=false;return out;}add("AUDIO_CANONICAL_ASSET",true,"canonical user-supplied 82s126.1m waveform PROM loads through the native runtime resource layer");
    audio.setVoice(0,0x12345,0,15);audio.setVoice(1,0x23450,3,11);audio.setVoice(2,0x34560,6,7);audio.setEnabled(true);const auto tone=audio.renderSamples(4096);stats.canonicalTonePcmHash=NativeAudio::pcmFnv1a(tone);stats.canonicalPeakAmplitude=NativeAudio::peakAmplitude(tone);add("AUDIO_CANONICAL_REFERENCE_TONE",stats.canonicalTonePcmHash==0xE727BE5A71B2DFDFULL&&stats.canonicalPeakAmplitude==21589,"4096-sample canonical waveform/pitch/volume PCM matches the independently supplied emulator reference hash E727BE5A71B2DFDF and peak 21589");
    audio.setVoice(0,0x24680,5,9);const auto transition=audio.renderSamples(2048);stats.canonicalTransitionPcmHash=NativeAudio::pcmFnv1a(transition);add("AUDIO_CANONICAL_REFERENCE_TRANSITION",stats.canonicalTransitionPcmHash==0x5406E41502C14097ULL,"post-state-change 2048-sample PCM matches the independently supplied emulator reference hash 5406E41502C14097");
    NativeAudio adapted;adapted.loadCanonicalWaveforms(resources,error);ReferenceAudioAdapter adapter;adapter.reset();const struct Write{std::uint16_t index;std::uint8_t value;} writes[]={{0x05,0},{0x10,5},{0x11,4},{0x12,3},{0x13,2},{0x14,1},{0x15,15},{0x0A,3},{0x16,5},{0x17,4},{0x18,3},{0x19,2},{0x1A,11},{0x0F,6},{0x1B,6},{0x1C,5},{0x1D,4},{0x1E,3},{0x1F,7}};for(const auto& write:writes)adapter.write(write.index,write.value,adapted);adapted.setEnabled(true);const auto adaptedTone=adapted.renderSamples(4096);add("AUDIO_CANONICAL_REFERENCE_ADAPTER",NativeAudio::pcmFnv1a(adaptedTone)==0xE727BE5A71B2DFDFULL,"verified-reference register adapter reaches the same canonical native PCM signature without making register writes the product API");
    stats.canonicalAssetChecks=out.size();for(const auto& record:out){if(record.passed)++stats.canonicalAssetPassed;else ++stats.canonicalAssetFailed;}stats.canonicalAssetReferenceMatch=stats.canonicalAssetFailed==0;return out;
}

} // namespace pacripper
