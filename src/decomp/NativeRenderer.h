#pragma once
// PacRipper native video renderer native PC video/rendering replacement
// Created by Jacob Hodgkins

#include "NativeRuntime.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pacripper {

struct SpriteState {
    std::uint8_t code=0;
    std::uint8_t color=0;
    int x=0;
    int y=0;
    bool flipX=false;
    bool flipY=false;
};

struct VideoValidationRecord {
    std::string stableId;
    bool passed=false;
    std::string evidenceKind;
    std::string diagnostic;
};

struct VideoNativeClassRecord {
    PlatformDependencyClass dependencyClass=PlatformDependencyClass::CoreMemory;
    PlatformServiceKind service=PlatformServiceKind::CoreState;
    bool required=false;
    bool implemented=false;
    bool rendererClass=false;
    bool audioRemaining=false;
    std::size_t dependencySites=0;
    std::string evidence;
};

struct NativeVideoStats {
    std::size_t dependencySites=0;
    std::size_t dependencyClasses=0;
    std::size_t pcNativeRequiredClasses=0;
    std::size_t pcNativeImplementedClasses=0;
    std::size_t pcNativeRemainingClasses=0;
    std::size_t requiredDependencySites=0;
    std::size_t nativeCompleteRequiredSites=0;
    std::size_t remainingRequiredSites=0;
    std::size_t rendererRequiredClasses=0;
    std::size_t rendererImplementedClasses=0;
    std::size_t rendererRequiredSites=0;
    std::size_t rendererImplementedSites=0;
    std::size_t validationChecks=0;
    std::size_t validationPassed=0;
    std::size_t validationFailed=0;
    std::size_t canonicalAssetChecks=0;
    std::size_t canonicalAssetPassed=0;
    std::size_t canonicalAssetFailed=0;
    std::uint64_t syntheticFramebufferHash=0;
    std::uint64_t canonicalNormalFramebufferHash=0;
    std::uint64_t canonicalFlipFramebufferHash=0;
    bool deterministicNativeRenderer=false;
    bool canonicalAssetReferenceMatch=false;
    bool rendererReady=false;
};

class NativeRenderer {
public:
    static constexpr int RawWidth=288;
    static constexpr int RawHeight=224;
    static constexpr int DisplayWidth=224;
    static constexpr int DisplayHeight=288;
    static constexpr std::size_t TileStateSize=0x400;
    static constexpr std::size_t SpriteStateSize=0x10;

    static const char* characterResourceName();
    static const char* spriteResourceName();
    static const char* paletteResourceName();
    static const char* colorLookupResourceName();

    NativeRenderer();

    bool loadCanonicalAssets(const RuntimeResourceStore& resources,std::string& error);
    bool loadAssets(const std::vector<std::uint8_t>& characters,
                    const std::vector<std::uint8_t>& sprites,
                    const std::vector<std::uint8_t>& paletteProm,
                    const std::vector<std::uint8_t>& colorLookupProm,
                    std::string& error);
    bool assetsReady() const { return assetsReady_; }

    void clearState();
    bool setTileCode(std::size_t tileIndex,std::uint8_t code);
    bool setTileColor(std::size_t tileIndex,std::uint8_t color);
    bool setTileCell(int rawColumn,int rawRow,std::uint8_t code,std::uint8_t color);
    std::uint8_t tileCode(std::size_t tileIndex) const;
    std::uint8_t tileColor(std::size_t tileIndex) const;
    bool setSpriteAttributeByte(std::size_t index,std::uint8_t value);
    bool setSpriteCoordinateByte(std::size_t index,std::uint8_t value);
    void setFlipScreen(bool enabled) { flipScreen_=enabled; dirty_=true; }
    bool flipScreen() const { return flipScreen_; }

    // Compatibility-only adapter for the verified platform abstraction reference boundary.
    std::uint8_t readReferenceRegion(PlatformDependencyClass region,std::uint16_t offset,std::uint8_t fallback) const;
    void writeReferenceRegion(PlatformDependencyClass region,std::uint16_t offset,std::uint8_t value);

    bool renderFrame(std::string& error);
    const std::vector<std::uint32_t>& framebuffer() const { return framebuffer_; }
    const std::vector<std::uint32_t>& rawFramebuffer() const { return rawFramebuffer_; }
    const std::array<std::uint32_t,32>& palette() const { return palette_; }
    const std::array<SpriteState,8>& spriteStates() const { return spriteStates_; }
    bool dirty() const { return dirty_; }

    std::uint8_t decodedCharacterPixel(std::uint8_t code,int x,int y) const;
    std::uint8_t decodedSpritePixel(std::uint8_t code,int x,int y) const;

    static int tileIndexFor(int rawColumn,int rawRow);
    static std::uint64_t framebufferRgbFnv1a(const std::vector<std::uint32_t>& framebuffer);
    static std::size_t nonBlackPixelCount(const std::vector<std::uint32_t>& framebuffer);

private:
    void rebuildDecodedGraphics();
    void rebuildPalette();
    std::uint32_t lookupColor(std::uint8_t color,std::uint8_t pixel) const;
    bool spritePixelTransparent(std::uint8_t color,std::uint8_t pixel) const;
    void putRawPixel(int x,int y,std::uint32_t color);
    void drawTiles();
    void drawSprite(int slot,bool firstGroup);
    void rotateRawToDisplay();

    std::vector<std::uint8_t> charactersRom_;
    std::vector<std::uint8_t> spritesRom_;
    std::vector<std::uint8_t> paletteProm_;
    std::vector<std::uint8_t> colorLookupProm_;
    std::array<std::array<std::uint8_t,64>,256> decodedCharacters_{};
    std::array<std::array<std::uint8_t,256>,64> decodedSprites_{};
    std::array<std::uint32_t,32> palette_{};
    std::array<std::uint8_t,TileStateSize> tileCodes_{};
    std::array<std::uint8_t,TileStateSize> tileColors_{};
    std::array<std::uint8_t,SpriteStateSize> spriteAttributes_{};
    std::array<std::uint8_t,SpriteStateSize> spriteCoordinates_{};
    std::array<SpriteState,8> spriteStates_{};
    std::vector<std::uint32_t> rawFramebuffer_;
    std::vector<std::uint32_t> framebuffer_;
    bool flipScreen_=false;
    bool dirty_=true;
    bool assetsReady_=false;
};

class VideoNativeRuntime: public NativeRuntime {
public:
    VideoNativeRuntime()=default;
    NativeRenderer& renderer() { return renderer_; }
    const NativeRenderer& renderer() const { return renderer_; }
    bool loadRendererAssets(std::string& error) { return renderer_.loadCanonicalAssets(resources(),error); }

    std::uint8_t videoStateRead(PlatformDependencyClass region,std::uint16_t offset,std::uint8_t fallback) override;
    void videoStateWrite(PlatformDependencyClass region,std::uint16_t offset,std::uint8_t value) override;
    void setFlipScreen(bool enabled) override;
private:
    NativeRenderer renderer_;
};

class NativeVideo {
public:
    static void buildProgress(const std::vector<PlatformDependencyRecord>& dependencies,
                              bool rendererVerified,
                              std::vector<VideoNativeClassRecord>& classes,
                              NativeVideoStats& stats);
    static std::vector<VideoValidationRecord> runSyntheticValidation(NativeVideoStats& stats);
    static std::vector<VideoValidationRecord> runCanonicalAssetValidation(const RuntimeResourceStore& resources,NativeVideoStats& stats);
};

} // namespace pacripper
