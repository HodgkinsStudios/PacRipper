#pragma once
// PacRipper native audio native PC audio replacement
// Created by Jacob Hodgkins

#include "NativeRenderer.h"
#include "recovery/PacmanWaveformCodec.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pacripper {

struct VoiceState {
    std::uint32_t frequencyWord=0; // native 20-bit phase increment
    std::uint32_t phase=0;
    std::uint8_t waveform=0;       // 0..7
    std::uint8_t volume=0;         // 0..15
};

struct AudioValidationRecord {
    std::string stableId;
    bool passed=false;
    std::string evidenceKind;
    std::string diagnostic;
};

struct AudioNativeClassRecord {
    PlatformDependencyClass dependencyClass=PlatformDependencyClass::CoreMemory;
    PlatformServiceKind service=PlatformServiceKind::CoreState;
    bool required=false;
    bool implemented=false;
    bool audioClass=false;
    std::size_t dependencySites=0;
    std::string evidence;
};

struct NativeAudioStats {
    std::size_t dependencySites=0;
    std::size_t dependencyClasses=0;
    std::size_t pcNativeRequiredClasses=0;
    std::size_t pcNativeImplementedClasses=0;
    std::size_t pcNativeRemainingClasses=0;
    std::size_t requiredDependencySites=0;
    std::size_t nativeCompleteRequiredSites=0;
    std::size_t remainingRequiredSites=0;
    std::size_t audioRequiredClasses=0;
    std::size_t audioImplementedClasses=0;
    std::size_t audioRequiredSites=0;
    std::size_t audioImplementedSites=0;
    std::size_t validationChecks=0;
    std::size_t validationPassed=0;
    std::size_t validationFailed=0;
    std::size_t canonicalAssetChecks=0;
    std::size_t canonicalAssetPassed=0;
    std::size_t canonicalAssetFailed=0;
    std::uint64_t syntheticTonePcmHash=0;
    std::uint64_t canonicalTonePcmHash=0;
    std::uint64_t canonicalTransitionPcmHash=0;
    int canonicalPeakAmplitude=0;
    bool deterministicNativeAudio=false;
    bool canonicalAssetReferenceMatch=false;
    bool audioReady=false;
    bool allNativeHardwareClassesComplete=false;
};

// Product-facing audio engine. It intentionally exposes voices and PCM rather than
// Pac-Man board addresses/registers. The fixed 192 kHz source rate is a deterministic
// host-consumable PCM stream; a later frontend can resample/feed any PC audio API.
class NativeAudio {
public:
    static constexpr std::size_t VoiceCount=3;
    static constexpr std::uint32_t SampleRateHz=192000;
    static constexpr std::size_t WaveformPromSize=0x100;
    static constexpr std::uint32_t FrequencyMask=0x000FFFFFu;

    static const char* waveformResourceName();

    NativeAudio();

    bool loadCanonicalWaveforms(const RuntimeResourceStore& resources,std::string& error);
    bool loadWaveformProm(const std::vector<std::uint8_t>& bytes,std::string& error);
    bool waveformsReady() const { return waveformsReady_; }

    void resetPlayback();
    void setEnabled(bool enabled) { enabled_=enabled; }
    bool enabled() const { return enabled_; }

    bool setVoiceWaveform(std::size_t voice,std::uint8_t waveform);
    bool setVoiceFrequency(std::size_t voice,std::uint32_t frequencyWord);
    bool setVoiceVolume(std::size_t voice,std::uint8_t volume);
    bool setVoice(std::size_t voice,std::uint32_t frequencyWord,std::uint8_t waveform,std::uint8_t volume);
    const std::array<VoiceState,VoiceCount>& voices() const { return voices_; }

    std::vector<std::int16_t> renderSamples(std::size_t sampleCount);
    void renderSamples(std::size_t sampleCount,std::vector<std::int16_t>& output);
    std::uint64_t samplesGenerated() const { return samplesGenerated_; }

    static std::uint64_t pcmFnv1a(const std::vector<std::int16_t>& samples);
    static int peakAmplitude(const std::vector<std::int16_t>& samples);
    static bool allSilent(const std::vector<std::int16_t>& samples);

private:
    std::int16_t generateSample();

    std::array<VoiceState,VoiceCount> voices_{};
    PacmanWaveformCodec::Entries waveformEntries_{};
    bool enabled_=false;
    bool waveformsReady_=false;
    std::uint64_t samplesGenerated_=0;
};

// Compatibility-only decoder for the verified reference boundary. The register image
// never leaks into the native audio API; each accepted write is translated into a
// voice waveform/frequency/volume update.
class ReferenceAudioAdapter {
public:
    void reset();
    void write(std::uint16_t index,std::uint8_t value,NativeAudio& audio);
    std::uint8_t registerValue(std::size_t index) const;
private:
    void syncWaveform(std::size_t voice,NativeAudio& audio);
    void syncFrequency(std::size_t voice,NativeAudio& audio);
    void syncVolume(std::size_t voice,NativeAudio& audio);
    std::array<std::uint8_t,0x20> registers_{};
};

class AudioNativeRuntime final: public VideoNativeRuntime {
public:
    AudioNativeRuntime();
    NativeAudio& audio() { return audio_; }
    const NativeAudio& audio() const { return audio_; }
    ReferenceAudioAdapter& referenceAudioAdapter() { return referenceAudioAdapter_; }
    const ReferenceAudioAdapter& referenceAudioAdapter() const { return referenceAudioAdapter_; }
    bool loadAudioAssets(std::string& error) { return audio_.loadCanonicalWaveforms(resources(),error); }
    void resetNativeAudio();

    void soundRegisterWrite(std::uint16_t index,std::uint8_t value) override;
    void setSoundEnabled(bool enabled) override;
private:
    NativeAudio audio_;
    ReferenceAudioAdapter referenceAudioAdapter_;
};

class NativeAudioReplacement {
public:
    static void buildProgress(const std::vector<PlatformDependencyRecord>& dependencies,
                              bool rendererVerified,
                              bool audioVerified,
                              std::vector<AudioNativeClassRecord>& classes,
                              NativeAudioStats& stats);
    static std::vector<AudioValidationRecord> runSyntheticValidation(NativeAudioStats& stats);
    static std::vector<AudioValidationRecord> runCanonicalAssetValidation(const RuntimeResourceStore& resources,NativeAudioStats& stats);
};

} // namespace pacripper
