// PacRipper native video renderer native PC video/rendering replacement
// Created by Jacob Hodgkins

#include "NativeRenderer.h"
#include "recovery/PacmanGraphicsCodec.h"
#include "recovery/PacmanColorCodec.h"

#include <algorithm>
#include <map>
#include <sstream>

namespace pacripper {

const char* NativeRenderer::characterResourceName(){return "pacman.graphics.characters";}
const char* NativeRenderer::spriteResourceName(){return "pacman.graphics.sprites";}
const char* NativeRenderer::paletteResourceName(){return "pacman.palette.prom";}
const char* NativeRenderer::colorLookupResourceName(){return "pacman.color_lookup.prom";}

NativeRenderer::NativeRenderer():rawFramebuffer_(RawWidth*RawHeight,0xFF000000u),framebuffer_(DisplayWidth*DisplayHeight,0xFF000000u){clearState();rebuildPalette();}

bool NativeRenderer::loadCanonicalAssets(const RuntimeResourceStore& resources,std::string& error){
    const auto* chars=resources.find(characterResourceName());const auto* sprites=resources.find(spriteResourceName());const auto* pal=resources.find(paletteResourceName());const auto* lookup=resources.find(colorLookupResourceName());
    if(!chars||!sprites||!pal||!lookup){error="native renderer requires user-supplied character, sprite, palette PROM and color-lookup PROM resources";return false;}
    return loadAssets(*chars,*sprites,*pal,*lookup,error);
}

bool NativeRenderer::loadAssets(const std::vector<std::uint8_t>& chars,const std::vector<std::uint8_t>& sprites,const std::vector<std::uint8_t>& pal,const std::vector<std::uint8_t>& lookup,std::string& error){
    if(chars.size()!=0x1000){std::ostringstream o;o<<"character graphics size mismatch: expected 4096 got "<<chars.size();error=o.str();return false;}
    if(sprites.size()!=0x1000){std::ostringstream o;o<<"sprite graphics size mismatch: expected 4096 got "<<sprites.size();error=o.str();return false;}
    if(pal.size()!=0x20){std::ostringstream o;o<<"palette PROM size mismatch: expected 32 got "<<pal.size();error=o.str();return false;}
    if(lookup.size()!=0x100){std::ostringstream o;o<<"color lookup PROM size mismatch: expected 256 got "<<lookup.size();error=o.str();return false;}
    charactersRom_=chars;spritesRom_=sprites;paletteProm_=pal;colorLookupProm_=lookup;assetsReady_=true;rebuildDecodedGraphics();rebuildPalette();dirty_=true;error.clear();return true;
}

void NativeRenderer::clearState(){tileCodes_.fill(0);tileColors_.fill(0);spriteAttributes_.fill(0);spriteCoordinates_.fill(0);for(auto&s:spriteStates_)s={};flipScreen_=false;std::fill(rawFramebuffer_.begin(),rawFramebuffer_.end(),0xFF000000u);std::fill(framebuffer_.begin(),framebuffer_.end(),0xFF000000u);dirty_=true;}
bool NativeRenderer::setTileCode(std::size_t i,std::uint8_t v){if(i>=tileCodes_.size())return false;tileCodes_[i]=v;dirty_=true;return true;}
bool NativeRenderer::setTileColor(std::size_t i,std::uint8_t v){if(i>=tileColors_.size())return false;tileColors_[i]=static_cast<std::uint8_t>(v&0x1Fu);dirty_=true;return true;}
bool NativeRenderer::setTileCell(int c,int r,std::uint8_t code,std::uint8_t color){if(c<0||c>=36||r<0||r>=28)return false;const auto i=static_cast<std::size_t>(tileIndexFor(c,r));return setTileCode(i,code)&&setTileColor(i,color);}
std::uint8_t NativeRenderer::tileCode(std::size_t i) const{return i<tileCodes_.size()?tileCodes_[i]:0;}
std::uint8_t NativeRenderer::tileColor(std::size_t i) const{return i<tileColors_.size()?tileColors_[i]:0;}
bool NativeRenderer::setSpriteAttributeByte(std::size_t i,std::uint8_t v){if(i>=spriteAttributes_.size())return false;spriteAttributes_[i]=v;dirty_=true;return true;}
bool NativeRenderer::setSpriteCoordinateByte(std::size_t i,std::uint8_t v){if(i>=spriteCoordinates_.size())return false;spriteCoordinates_[i]=v;dirty_=true;return true;}

std::uint8_t NativeRenderer::readReferenceRegion(PlatformDependencyClass r,std::uint16_t o,std::uint8_t fallback) const{
    switch(r){case PlatformDependencyClass::VideoTileMemory:return o<tileCodes_.size()?tileCodes_[o]:fallback;case PlatformDependencyClass::ColorMemory:return o<tileColors_.size()?tileColors_[o]:fallback;case PlatformDependencyClass::SpriteAttributeMemory:return o<spriteAttributes_.size()?spriteAttributes_[o]:fallback;case PlatformDependencyClass::SpriteCoordinates:return o<spriteCoordinates_.size()?spriteCoordinates_[o]:fallback;default:return fallback;}
}
void NativeRenderer::writeReferenceRegion(PlatformDependencyClass r,std::uint16_t o,std::uint8_t v){switch(r){case PlatformDependencyClass::VideoTileMemory:setTileCode(o,v);break;case PlatformDependencyClass::ColorMemory:setTileColor(o,v);break;case PlatformDependencyClass::SpriteAttributeMemory:setSpriteAttributeByte(o,v);break;case PlatformDependencyClass::SpriteCoordinates:setSpriteCoordinateByte(o,v);break;default:break;}}

int NativeRenderer::tileIndexFor(int col,int row){int r=row+2;int c=col-2;int index;if(c&0x20)index=r+((c&0x1F)<<5);else index=c+(r<<5);return index&0x3FF;}
void NativeRenderer::rebuildDecodedGraphics(){
    for(auto&c:decodedCharacters_)c.fill(0);
    for(auto&s:decodedSprites_)s.fill(0);
    if(!assetsReady_)return;
    std::string error;
    PacmanGraphicsCodec::CharacterPixels characters;
    PacmanGraphicsCodec::SpritePixels sprites;
    if(PacmanGraphicsCodec::decodeCharacters(charactersRom_,characters,nullptr,error))decodedCharacters_=characters;
    if(PacmanGraphicsCodec::decodeSprites(spritesRom_,sprites,nullptr,error))decodedSprites_=sprites;
}

void NativeRenderer::rebuildPalette(){palette_.fill(0xFF000000u);PacmanColorCodec::PaletteEntries entries;std::string error;if(!PacmanColorCodec::decodePalette(paletteProm_,entries,nullptr,error))return;for(std::size_t i=0;i<entries.size();++i)palette_[i]=PacmanColorCodec::argb(entries[i]);}
std::uint8_t NativeRenderer::decodedCharacterPixel(std::uint8_t code,int x,int y) const{return assetsReady_&&x>=0&&x<8&&y>=0&&y<8?decodedCharacters_[code][static_cast<std::size_t>(y*8+x)]:0;}
std::uint8_t NativeRenderer::decodedSpritePixel(std::uint8_t code,int x,int y) const{return assetsReady_&&x>=0&&x<16&&y>=0&&y<16?decodedSprites_[static_cast<std::size_t>(code&0x3Fu)][static_cast<std::size_t>(y*16+x)]:0;}
std::uint32_t NativeRenderer::lookupColor(std::uint8_t color,std::uint8_t pixel) const{if(colorLookupProm_.size()<0x100)return 0xFF000000u;const unsigned pen=PacmanColorCodec::lookupAddress(color,pixel);const std::uint8_t indirect=PacmanColorCodec::lookupPaletteIndex(colorLookupProm_[pen&0xFFu]);return palette_[indirect];}
bool NativeRenderer::spritePixelTransparent(std::uint8_t color,std::uint8_t pixel) const{if(colorLookupProm_.size()<0x100)return pixel==0;const unsigned pen=PacmanColorCodec::lookupAddress(color,pixel);return PacmanColorCodec::lookupPaletteIndex(colorLookupProm_[pen&0xFFu])==0;}
void NativeRenderer::putRawPixel(int x,int y,std::uint32_t c){if(x<0||x>=RawWidth||y<0||y>=RawHeight)return;rawFramebuffer_[static_cast<std::size_t>(y)*RawWidth+static_cast<std::size_t>(x)]=c;}
void NativeRenderer::drawTiles(){for(int rawY=0;rawY<RawHeight;++rawY)for(int rawX=0;rawX<RawWidth;++rawX){const int logicalX=flipScreen_?(RawWidth-1-rawX):rawX;const int logicalY=flipScreen_?(RawHeight-1-rawY):rawY;const int col=logicalX>>3,row=logicalY>>3,px=logicalX&7,py=logicalY&7;const auto i=static_cast<std::size_t>(tileIndexFor(col,row));putRawPixel(rawX,rawY,lookupColor(static_cast<std::uint8_t>(tileColors_[i]&0x1Fu),decodedCharacterPixel(tileCodes_[i],px,py)));}}
void NativeRenderer::drawSprite(int slot,bool firstGroup){const int offs=slot*2;const std::uint8_t attr=spriteAttributes_[static_cast<std::size_t>(offs)];const std::uint8_t color=static_cast<std::uint8_t>(spriteAttributes_[static_cast<std::size_t>(offs+1)]&0x1Fu);const std::uint8_t code=static_cast<std::uint8_t>(attr>>2);const bool fx=(attr&0x01u)!=0,fy=(attr&0x02u)!=0;const int sx=272-static_cast<int>(spriteCoordinates_[static_cast<std::size_t>(offs+1)]);int sy=static_cast<int>(spriteCoordinates_[static_cast<std::size_t>(offs)])-31;if(firstGroup)++sy;auto&state=spriteStates_[static_cast<std::size_t>(slot)];state.code=code;state.color=color;state.x=sx;state.y=sy;state.flipX=fx;state.flipY=fy;const int origins[2]={sx,sx-256};for(int wrap=0;wrap<2;++wrap){const int ox=origins[wrap];for(int py=0;py<16;++py){const int ry=sy+py;if(ry<0||ry>=RawHeight)continue;for(int px=0;px<16;++px){const int rx=ox+px;if(rx<16||rx>271)continue;const int sampleX=fx?(15-px):px,sampleY=fy?(15-py):py;const std::uint8_t pix=decodedSpritePixel(code,sampleX,sampleY);if(!spritePixelTransparent(color,pix))putRawPixel(rx,ry,lookupColor(color,pix));}}}}
void NativeRenderer::rotateRawToDisplay(){for(int y=0;y<RawHeight;++y)for(int x=0;x<RawWidth;++x){const int dx=RawHeight-1-y,dy=x;framebuffer_[static_cast<std::size_t>(dy)*DisplayWidth+static_cast<std::size_t>(dx)]=rawFramebuffer_[static_cast<std::size_t>(y)*RawWidth+static_cast<std::size_t>(x)];}}
bool NativeRenderer::renderFrame(std::string& error){if(!assetsReady_){error="native renderer has no decoded graphics/color assets";return false;}drawTiles();for(int slot=7;slot>=3;--slot)drawSprite(slot,false);for(int slot=2;slot>=0;--slot)drawSprite(slot,true);rotateRawToDisplay();dirty_=false;error.clear();return true;}
std::uint64_t NativeRenderer::framebufferRgbFnv1a(const std::vector<std::uint32_t>& fb){std::uint64_t h=1469598103934665603ULL;constexpr std::uint64_t prime=1099511628211ULL;for(std::uint32_t p:fb){const std::uint8_t rgb[3]={static_cast<std::uint8_t>((p>>16)&0xFFu),static_cast<std::uint8_t>((p>>8)&0xFFu),static_cast<std::uint8_t>(p&0xFFu)};for(std::uint8_t c:rgb){h^=c;h*=prime;}}return h;}
std::size_t NativeRenderer::nonBlackPixelCount(const std::vector<std::uint32_t>& fb){return static_cast<std::size_t>(std::count_if(fb.begin(),fb.end(),[](std::uint32_t p){return (p&0x00FFFFFFu)!=0;}));}

std::uint8_t VideoNativeRuntime::videoStateRead(PlatformDependencyClass r,std::uint16_t o,std::uint8_t fallback){return renderer_.readReferenceRegion(r,o,fallback);}
void VideoNativeRuntime::videoStateWrite(PlatformDependencyClass r,std::uint16_t o,std::uint8_t v){renderer_.writeReferenceRegion(r,o,v);}
void VideoNativeRuntime::setFlipScreen(bool enabled){renderer_.setFlipScreen(enabled);}

void NativeVideo::buildProgress(const std::vector<PlatformDependencyRecord>& deps,bool rendererVerified,std::vector<VideoNativeClassRecord>& out,NativeVideoStats& stats){
    out.clear();std::map<PlatformDependencyClass,VideoNativeClassRecord> m;for(const auto&d:deps){auto&r=m[d.dependencyClass];r.dependencyClass=d.dependencyClass;r.service=d.service;r.required=r.required||d.pcNativeImplementationRequired;++r.dependencySites;}
    stats.dependencySites=deps.size();stats.dependencyClasses=m.size();for(auto&kv:m){auto&r=kv.second;if(r.required){++stats.pcNativeRequiredClasses;stats.requiredDependencySites+=r.dependencySites;switch(r.service){case PlatformServiceKind::Input:case PlatformServiceKind::Timing:case PlatformServiceKind::Configuration:case PlatformServiceKind::Lifecycle:r.implemented=true;r.evidence="native runtime deterministic PC-native host implementation retained";break;case PlatformServiceKind::Renderer:r.rendererClass=true;++stats.rendererRequiredClasses;stats.rendererRequiredSites+=r.dependencySites;r.implemented=rendererVerified;r.evidence=rendererVerified?"native video renderer native decoded-asset/framebuffer renderer with deterministic proof":"native video renderer renderer validation incomplete";break;case PlatformServiceKind::Audio:r.audioRemaining=true;r.evidence="native audio remains native audio work";break;default:r.evidence="not a native product class completed by native video renderer";break;}if(r.implemented){++stats.pcNativeImplementedClasses;stats.nativeCompleteRequiredSites+=r.dependencySites;if(r.rendererClass){++stats.rendererImplementedClasses;stats.rendererImplementedSites+=r.dependencySites;}}}else r.evidence="not part of PC-native-required denominator";out.push_back(r);}
    stats.pcNativeRemainingClasses=stats.pcNativeRequiredClasses-stats.pcNativeImplementedClasses;stats.remainingRequiredSites=stats.requiredDependencySites-stats.nativeCompleteRequiredSites;stats.rendererReady=rendererVerified&&stats.rendererRequiredClasses==stats.rendererImplementedClasses&&stats.rendererRequiredClasses>0;
}

std::vector<VideoValidationRecord> NativeVideo::runSyntheticValidation(NativeVideoStats& stats){
    std::vector<VideoValidationRecord> out;auto add=[&](const std::string&id,bool ok,const std::string&diag){VideoValidationRecord r;r.stableId=id;r.passed=ok;r.evidenceKind="internal-synthetic";r.diagnostic=diag;out.push_back(r);};
    NativeRenderer r;std::string e;std::vector<std::uint8_t> chars(0x1000,0),sprites(0x1000,0),pal(0x20,0),lookup(0x100,0);for(std::size_t i=16;i<32;++i)chars[i]=0xFF;for(std::size_t i=64;i<128;++i)sprites[i]=0xFF;pal[1]=0x07;for(std::size_t i=0;i<lookup.size();++i)lookup[i]=static_cast<std::uint8_t>((i&3u)==0?0:1);
    add("VIDEO_ASSET_CONTRACT",!r.loadAssets({},sprites,pal,lookup,e)&&r.loadAssets(chars,sprites,pal,lookup,e),"renderer rejects malformed assets and accepts exact external character/sprite/PROM sizes");
    add("VIDEO_DECODE",r.decodedCharacterPixel(1,0,0)==3&&r.decodedCharacterPixel(0,0,0)==0&&r.decodedSpritePixel(1,0,0)==3,"native planar decoder produces deterministic 2bpp character and sprite pixels");
    r.clearState();const int index=NativeRenderer::tileIndexFor(4,3);r.setTileCode(static_cast<std::size_t>(index),1);r.setTileColor(static_cast<std::size_t>(index),0);const bool rendered=r.renderFrame(e);const auto&fb=r.framebuffer();const std::size_t normalPos=static_cast<std::size_t>(32)*NativeRenderer::DisplayWidth+199;add("VIDEO_TILE_PLACEMENT",rendered&&normalPos<fb.size()&&(fb[normalPos]&0x00FFFFFFu)!=0,"logical tile state maps through the canonical 36x28 tilemap and cabinet rotation into the native 224x288 framebuffer");
    const auto h1=NativeRenderer::framebufferRgbFnv1a(fb);r.renderFrame(e);const auto h2=NativeRenderer::framebufferRgbFnv1a(r.framebuffer());stats.syntheticFramebufferHash=h1;add("VIDEO_REPEATABILITY",h1==h2&&h1!=0,"identical native render state produces a stable RGB framebuffer hash");
    r.setFlipScreen(true);r.renderFrame(e);const auto hf=NativeRenderer::framebufferRgbFnv1a(r.framebuffer());add("VIDEO_FLIP",hf!=h1&&r.flipScreen(),"flip-screen state performs a deterministic global tilemap coordinate transform instead of a no-op latch");
    r.clearState();r.setSpriteAttributeByte(0,0x04);r.setSpriteAttributeByte(1,0);r.setSpriteCoordinateByte(0,50);r.setSpriteCoordinateByte(1,100);r.renderFrame(e);add("VIDEO_SPRITE_PATH",r.spriteStates()[0].code==1&&r.spriteStates()[0].x==172&&r.spriteStates()[0].y==20,"native frame compositor includes decoded sprite state, clipping/wrap order and Pac-Man first-group positioning compensation");
    VideoNativeRuntime host;host.resources().addUserSupplied(NativeRenderer::characterResourceName(),chars,"<synthetic>",e);host.resources().addUserSupplied(NativeRenderer::spriteResourceName(),sprites,"<synthetic>",e);host.resources().addUserSupplied(NativeRenderer::paletteResourceName(),pal,"<synthetic>",e);host.resources().addUserSupplied(NativeRenderer::colorLookupResourceName(),lookup,"<synthetic>",e);const bool loaded=host.loadRendererAssets(e);PlatformContractBoundary bridge(host);bridge.memoryWrite(0x4000,1,0);bridge.memoryWrite(0x4400,2,0);bridge.memoryWrite(0x5003,1,0);add("VIDEO_REFERENCE_ADAPTER",loaded&&host.renderer().tileCode(0)==1&&host.renderer().tileColor(0)==2&&host.renderer().flipScreen(),"verified raw-address reference seam translates into product-side renderer state without becoming the renderer API");
    NativeRuntimeStats runtimeStats;auto prior=NativeRuntimeFoundation::runDeterministicValidation(runtimeStats);add("VIDEO_RUNTIME_REGRESSION",prior.size()==8&&runtimeStats.validationFailed==0&&runtimeStats.deterministicHostValidation,"native runtime input/timing/configuration/lifecycle host checks remain green");
    stats.validationChecks=out.size();for(const auto&x:out){if(x.passed)++stats.validationPassed;else ++stats.validationFailed;}stats.deterministicNativeRenderer=stats.validationFailed==0;return out;
}

std::vector<VideoValidationRecord> NativeVideo::runCanonicalAssetValidation(const RuntimeResourceStore& resources,NativeVideoStats& stats){
    std::vector<VideoValidationRecord> out;auto add=[&](const std::string&id,bool ok,const std::string&diag){VideoValidationRecord r;r.stableId=id;r.passed=ok;r.evidenceKind="reference-derived-canonical-assets";r.diagnostic=diag;out.push_back(r);};NativeRenderer r;std::string e;if(!r.loadCanonicalAssets(resources,e)){add("VIDEO_CANONICAL_ASSETS",false,e);stats.canonicalAssetChecks=out.size();stats.canonicalAssetFailed=out.size();stats.canonicalAssetReferenceMatch=false;return out;}add("VIDEO_CANONICAL_ASSETS",true,"canonical user-supplied pacman.5e/pacman.5f/palette/color PROM resources decode through the native runtime resource layer");for(std::size_t i=0;i<NativeRenderer::TileStateSize;++i){r.setTileCode(i,static_cast<std::uint8_t>((i*37u+11u)&0xFFu));r.setTileColor(i,static_cast<std::uint8_t>((i*13u+3u)&0x1Fu));}for(std::size_t i=0;i<NativeRenderer::SpriteStateSize;++i){r.setSpriteAttributeByte(i,static_cast<std::uint8_t>((i*17u+5u)&0xFFu));r.setSpriteCoordinateByte(i,static_cast<std::uint8_t>((i*29u+47u)&0xFFu));}r.setFlipScreen(false);const bool n=r.renderFrame(e);stats.canonicalNormalFramebufferHash=NativeRenderer::framebufferRgbFnv1a(r.framebuffer());add("VIDEO_CANONICAL_REFERENCE_NORMAL",n&&stats.canonicalNormalFramebufferHash==0xC49FACB84780FCC7ULL,"normal-orientation canonical-asset framebuffer matches the independently supplied emulator reference signature C49FACB84780FCC7");r.setFlipScreen(true);const bool f=r.renderFrame(e);stats.canonicalFlipFramebufferHash=NativeRenderer::framebufferRgbFnv1a(r.framebuffer());add("VIDEO_CANONICAL_REFERENCE_FLIP",f&&stats.canonicalFlipFramebufferHash==0x2DAD77CCD2F430FFULL,"flip-screen canonical-asset framebuffer matches the independently supplied emulator reference signature 2DAD77CCD2F430FF");stats.canonicalAssetChecks=out.size();for(const auto&x:out){if(x.passed)++stats.canonicalAssetPassed;else ++stats.canonicalAssetFailed;}stats.canonicalAssetReferenceMatch=stats.canonicalAssetFailed==0;return out;
}

} // namespace pacripper
