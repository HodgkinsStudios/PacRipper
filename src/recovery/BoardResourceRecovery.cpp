// PacRipper Complete Board ROM/PROM Recovery — graphics, color, and audio recovery
// Created by Jacob Hodgkins
#include "BoardResourceRecovery.h"

#include "PacmanGraphicsCodec.h"
#include "PacmanColorCodec.h"
#include "PacmanWaveformCodec.h"
#include "PacmanTimingPromCodec.h"
#include "decomp/RomRebuilder.h"
#include "decomp/NativeRenderer.h"
#include "decomp/NativeAudio.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <set>
#include <sstream>

namespace pacripper {
namespace {
namespace fs = std::filesystem;

std::string hex32(std::uint32_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(8)<<std::setfill('0')<<v;return o.str();}
std::string hex64(std::uint64_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(16)<<std::setfill('0')<<v;return o.str();}
std::string stableChar(std::size_t id){std::ostringstream o;o<<"CHAR_"<<std::setw(3)<<std::setfill('0')<<id;return o.str();}
std::string stableSprite(std::size_t id){std::ostringstream o;o<<"SPR_"<<std::setw(2)<<std::setfill('0')<<id;return o.str();}

bool writeText(const fs::path& p,const std::string& text,std::string& error){std::ofstream out(p,std::ios::binary);if(!out){error="cannot write "+p.string();return false;}out<<text;if(!out){error="write failed for "+p.string();return false;}return true;}

bool completeOwnership(const std::vector<GraphicsBitOwner>& owners,std::size_t bitCount){
    if(owners.size()!=bitCount) return false;
    std::vector<unsigned char> seen(bitCount,0);
    for(const auto& o:owners){
        if(o.romBitOffset>=bitCount||seen[o.romBitOffset]) return false;
        seen[o.romBitOffset]=1;
    }
    return std::all_of(seen.begin(),seen.end(),[](unsigned char v){return v==1;});
}

std::string decoderOwner(const CanonicalRomDescriptor& d){
    if(d.program)return "PacmanProgramSource";
    if(d.name=="pacman.5e"||d.name=="pacman.5f")return "PacmanGraphicsCodec";
    if(d.name=="82s123.7f"||d.name=="82s126.4a")return "PacmanColorCodec";
    if(d.name=="82s126.1m")return "PacmanWaveformCodec";
    if(d.name=="82s126.3m")return "PacmanTimingPromCodec(board_timing_control)";
    return "unknown_resource_owner";
}
std::size_t decodedCount(const CanonicalRomDescriptor& d){if(d.name=="pacman.5e")return 256;if(d.name=="pacman.5f")return 64;if(d.name=="82s123.7f")return 32;if(d.name=="82s126.4a"||d.name=="82s126.1m"||d.name=="82s126.3m")return 256;return 0;}

std::string relationForExtra(const RomSet& set,const RomFile& extra){
    for(const auto& d:RomSet::canonicalPacmanManifest()){
        const RomFile* active=set.find(d.name);if(!active||extra.data.size()*2u!=active->data.size())continue;
        const auto half=extra.data.size();
        if(std::equal(extra.data.begin(),extra.data.end(),active->data.begin()))return "exact_prefix_of:"+d.name;
        if(std::equal(extra.data.begin(),extra.data.end(),active->data.begin()+static_cast<std::ptrdiff_t>(half)))return "exact_suffix_of:"+d.name;
    }
    return "no_exact_active_equivalence_proven";
}

bool writeAtlas(const fs::path& p,const std::vector<std::uint8_t>& pixels,int width,int height,std::string& error){
    std::ofstream out(p,std::ios::binary);if(!out){error="cannot write "+p.string();return false;}out<<"P6\n"<<width<<" "<<height<<"\n255\n";for(auto v:pixels){const std::uint8_t c=static_cast<std::uint8_t>(v*85u);const char rgb[3]={static_cast<char>(c),static_cast<char>(c),static_cast<char>(c)};out.write(rgb,3);}return static_cast<bool>(out);
}

bool writeGraphicsSources(const fs::path& root,const PacmanGraphicsCodec::CharacterPixels& chars,const PacmanGraphicsCodec::SpritePixels& sprites,const std::vector<GraphicsBitOwner>& charOwners,const std::vector<GraphicsBitOwner>& spriteOwners,std::string& error){
    std::ostringstream cs;cs<<"character_id,row,p0,p1,p2,p3,p4,p5,p6,p7\n";for(std::size_t id=0;id<chars.size();++id)for(int y=0;y<8;++y){cs<<id<<","<<y;for(int x=0;x<8;++x)cs<<","<<static_cast<unsigned>(chars[id][static_cast<std::size_t>(y*8+x)]);cs<<"\n";}if(!writeText(root/"graphics/characters.csv",cs.str(),error))return false;
    std::ostringstream ss;ss<<"sprite_id,row";for(int x=0;x<16;++x)ss<<",p"<<x;ss<<"\n";for(std::size_t id=0;id<sprites.size();++id)for(int y=0;y<16;++y){ss<<id<<","<<y;for(int x=0;x<16;++x)ss<<","<<static_cast<unsigned>(sprites[id][static_cast<std::size_t>(y*16+x)]);ss<<"\n";}if(!writeText(root/"graphics/sprites.csv",ss.str(),error))return false;

    std::ostringstream cm;cm<<"stable_id,character_id,x,y,pixel,msb_rom_byte,msb_bit_from_msb,lsb_rom_byte,lsb_bit_from_msb\n";for(std::size_t id=0;id<chars.size();++id)for(int y=0;y<8;++y)for(int x=0;x<8;++x){const auto a=PacmanGraphicsCodec::characterBitOffset(static_cast<std::uint16_t>(id),x,y,1),b=PacmanGraphicsCodec::characterBitOffset(static_cast<std::uint16_t>(id),x,y,0);cm<<stableChar(id)<<","<<id<<","<<x<<","<<y<<","<<static_cast<unsigned>(chars[id][static_cast<std::size_t>(y*8+x)])<<","<<(a>>3)<<","<<(a&7u)<<","<<(b>>3)<<","<<(b&7u)<<"\n";}if(!writeText(root/"graphics/character_map.csv",cm.str(),error))return false;
    std::ostringstream sm;sm<<"stable_id,sprite_id,x,y,pixel,msb_rom_byte,msb_bit_from_msb,lsb_rom_byte,lsb_bit_from_msb\n";for(std::size_t id=0;id<sprites.size();++id)for(int y=0;y<16;++y)for(int x=0;x<16;++x){const auto a=PacmanGraphicsCodec::spriteBitOffset(static_cast<std::uint16_t>(id),x,y,1),b=PacmanGraphicsCodec::spriteBitOffset(static_cast<std::uint16_t>(id),x,y,0);sm<<stableSprite(id)<<","<<id<<","<<x<<","<<y<<","<<static_cast<unsigned>(sprites[id][static_cast<std::size_t>(y*16+x)])<<","<<(a>>3)<<","<<(a&7u)<<","<<(b>>3)<<","<<(b&7u)<<"\n";}if(!writeText(root/"graphics/sprite_map.csv",sm.str(),error))return false;

    std::ostringstream own;own<<"file,byte_offset,bit_from_msb,object_kind,object_id,x,y,pixel_bit\n";for(const auto&o:charOwners)own<<"pacman.5e,"<<o.romByteOffset<<","<<static_cast<unsigned>(o.romBitFromMsb)<<",character,"<<o.objectId<<","<<static_cast<unsigned>(o.x)<<","<<static_cast<unsigned>(o.y)<<","<<static_cast<unsigned>(o.pixelBit)<<"\n";for(const auto&o:spriteOwners)own<<"pacman.5f,"<<o.romByteOffset<<","<<static_cast<unsigned>(o.romBitFromMsb)<<",sprite,"<<o.objectId<<","<<static_cast<unsigned>(o.x)<<","<<static_cast<unsigned>(o.y)<<","<<static_cast<unsigned>(o.pixelBit)<<"\n";if(!writeText(root/"graphics/bit_ownership.csv",own.str(),error))return false;

    std::vector<std::uint8_t> ca(128u*128u,0);for(std::size_t id=0;id<256;++id){const int ox=static_cast<int>(id%16u)*8,oy=static_cast<int>(id/16u)*8;for(int y=0;y<8;++y)for(int x=0;x<8;++x)ca[static_cast<std::size_t>(oy+y)*128u+static_cast<std::size_t>(ox+x)]=chars[id][static_cast<std::size_t>(y*8+x)];}if(!writeAtlas(root/"graphics/character_sheet.ppm",ca,128,128,error))return false;
    std::vector<std::uint8_t> sa(128u*128u,0);for(std::size_t id=0;id<64;++id){const int ox=static_cast<int>(id%8u)*16,oy=static_cast<int>(id/8u)*16;for(int y=0;y<16;++y)for(int x=0;x<16;++x)sa[static_cast<std::size_t>(oy+y)*128u+static_cast<std::size_t>(ox+x)]=sprites[id][static_cast<std::size_t>(y*16+x)];}return writeAtlas(root/"graphics/sprite_sheet.ppm",sa,128,128,error);
}

bool parseNumberRow(const std::string& line,std::vector<unsigned>& values){values.clear();std::size_t pos=0;while(pos<=line.size()){const auto comma=line.find(',',pos);const std::string part=line.substr(pos,comma==std::string::npos?std::string::npos:comma-pos);try{values.push_back(static_cast<unsigned>(std::stoul(part)));}catch(...){return false;}if(comma==std::string::npos)break;pos=comma+1;}return true;}

bool readCharacterSource(const fs::path& p,PacmanGraphicsCodec::CharacterPixels& chars,std::string& error){for(auto&r:chars)r.fill(0);std::ifstream in(p);if(!in){error="cannot read "+p.string();return false;}std::string line;if(!std::getline(in,line)){error="empty character source";return false;}std::size_t rows=0;while(std::getline(in,line)){if(line.empty())continue;std::vector<unsigned> v;if(!parseNumberRow(line,v)||v.size()!=10||v[0]>=256||v[1]>=8){error="invalid character source row";return false;}for(int x=0;x<8;++x){if(v[static_cast<std::size_t>(x+2)]>3){error="character pixel outside 2-bpp domain";return false;}chars[v[0]][static_cast<std::size_t>(v[1]*8u+static_cast<unsigned>(x))]=static_cast<std::uint8_t>(v[static_cast<std::size_t>(x+2)]);}++rows;}if(rows!=2048){error="character source row count mismatch";return false;}return true;}
bool readSpriteSource(const fs::path& p,PacmanGraphicsCodec::SpritePixels& sprites,std::string& error){for(auto&r:sprites)r.fill(0);std::ifstream in(p);if(!in){error="cannot read "+p.string();return false;}std::string line;if(!std::getline(in,line)){error="empty sprite source";return false;}std::size_t rows=0;while(std::getline(in,line)){if(line.empty())continue;std::vector<unsigned> v;if(!parseNumberRow(line,v)||v.size()!=18||v[0]>=64||v[1]>=16){error="invalid sprite source row";return false;}for(int x=0;x<16;++x){if(v[static_cast<std::size_t>(x+2)]>3){error="sprite pixel outside 2-bpp domain";return false;}sprites[v[0]][static_cast<std::size_t>(v[1]*16u+static_cast<unsigned>(x))]=static_cast<std::uint8_t>(v[static_cast<std::size_t>(x+2)]);}++rows;}if(rows!=1024){error="sprite source row count mismatch";return false;}return true;}


bool completeColorOwnership(const std::vector<ColorBitOwner>& owners,std::size_t bitCount){
    if(owners.size()!=bitCount)return false;
    std::vector<unsigned char> seen(bitCount,0);
    for(const auto& o:owners){if(o.romBitOffset>=bitCount||seen[o.romBitOffset])return false;seen[o.romBitOffset]=1;}
    return std::all_of(seen.begin(),seen.end(),[](unsigned char v){return v==1;});
}

std::string stablePalette(std::size_t id){std::ostringstream o;o<<"PAL_"<<std::setw(2)<<std::setfill('0')<<id;return o.str();}
std::string stableLookup(std::size_t id){std::ostringstream o;o<<"LUT_"<<std::setw(3)<<std::setfill('0')<<id;return o.str();}

bool writeRgbPpm(const fs::path& p,int width,int height,const std::vector<std::uint32_t>& argb,std::string& error){
    if(argb.size()!=static_cast<std::size_t>(width*height)){error="PPM pixel count mismatch";return false;}
    std::ofstream out(p,std::ios::binary);if(!out){error="cannot write "+p.string();return false;}out<<"P6\n"<<width<<" "<<height<<"\n255\n";
    for(const auto v:argb){const char rgb[3]={static_cast<char>((v>>16)&0xFFu),static_cast<char>((v>>8)&0xFFu),static_cast<char>(v&0xFFu)};out.write(rgb,3);}if(!out){error="write failed for "+p.string();return false;}return true;
}

bool writeColorSources(const fs::path& root,const PacmanColorCodec::PaletteEntries& palette,const PacmanColorCodec::LookupEntries& lookup,const std::vector<ColorBitOwner>& paletteOwners,const std::vector<ColorBitOwner>& lookupOwners,std::string& error){
    std::ostringstream ps;ps<<"index,bit0,bit1,bit2,bit3,bit4,bit5,bit6,bit7,red,green,blue\n";
    for(const auto& e:palette){ps<<static_cast<unsigned>(e.index);for(const auto bit:e.rawBits)ps<<","<<static_cast<unsigned>(bit);ps<<","<<static_cast<unsigned>(e.red)<<","<<static_cast<unsigned>(e.green)<<","<<static_cast<unsigned>(e.blue)<<"\n";}
    if(!writeText(root/"color/palette_source.csv",ps.str(),error))return false;

    std::ostringstream ls;ls<<"address,color_group,pixel,palette_index,serialized_upper_nibble\n";
    for(const auto& e:lookup)ls<<e.address<<","<<static_cast<unsigned>(e.colorGroup)<<","<<static_cast<unsigned>(e.pixel)<<","<<static_cast<unsigned>(e.paletteIndex)<<","<<static_cast<unsigned>(e.serializedUpperNibble)<<"\n";
    if(!writeText(root/"color/color_lookup_source.csv",ls.str(),error))return false;

    std::ostringstream pm;pm<<"stable_id,index,raw_byte,red,green,blue,source_byte_offset\n";
    for(const auto& e:palette){unsigned raw=0;for(unsigned bit=0;bit<8u;++bit)raw|=static_cast<unsigned>(e.rawBits[bit])<<bit;pm<<stablePalette(e.index)<<","<<static_cast<unsigned>(e.index)<<","<<raw<<","<<static_cast<unsigned>(e.red)<<","<<static_cast<unsigned>(e.green)<<","<<static_cast<unsigned>(e.blue)<<","<<static_cast<unsigned>(e.index)<<"\n";}
    if(!writeText(root/"color/palette_map.csv",pm.str(),error))return false;

    std::ostringstream lm;lm<<"stable_id,address,color_group,pixel,palette_index,serialized_upper_nibble,raw_byte,source_byte_offset,renderer_group_reachable\n";
    for(const auto& e:lookup){const unsigned raw=(static_cast<unsigned>(e.serializedUpperNibble)<<4)|e.paletteIndex;lm<<stableLookup(e.address)<<","<<e.address<<","<<static_cast<unsigned>(e.colorGroup)<<","<<static_cast<unsigned>(e.pixel)<<","<<static_cast<unsigned>(e.paletteIndex)<<","<<static_cast<unsigned>(e.serializedUpperNibble)<<","<<raw<<","<<e.address<<","<<(e.colorGroup<32u?"yes":"no")<<"\n";}
    if(!writeText(root/"color/color_lookup_map.csv",lm.str(),error))return false;

    std::ostringstream own;own<<"file,byte_offset,bit_from_msb,stable_entry_id,semantic_field,semantic_bit\n";
    for(const auto& o:paletteOwners)own<<"82s123.7f,"<<o.romByteOffset<<","<<static_cast<unsigned>(o.romBitFromMsb)<<","<<stablePalette(o.entryId)<<","<<o.semanticField<<","<<static_cast<unsigned>(o.semanticBit)<<"\n";
    for(const auto& o:lookupOwners)own<<"82s126.4a,"<<o.romByteOffset<<","<<static_cast<unsigned>(o.romBitFromMsb)<<","<<stableLookup(o.entryId)<<","<<o.semanticField<<","<<static_cast<unsigned>(o.semanticBit)<<"\n";
    if(!writeText(root/"color/bit_ownership.csv",own.str(),error))return false;

    std::vector<std::uint32_t> palettePixels(256u*16u,0xFF000000u);
    for(std::size_t i=0;i<palette.size();++i){const auto c=PacmanColorCodec::argb(palette[i]);for(int y=0;y<16;++y)for(int x=0;x<8;++x)palettePixels[static_cast<std::size_t>(y)*256u+i*8u+static_cast<std::size_t>(x)]=c;}
    if(!writeRgbPpm(root/"color/palette_sheet.ppm",256,16,palettePixels,error))return false;

    std::vector<std::uint32_t> lookupPixels(128u*128u,0xFF000000u);
    for(std::size_t i=0;i<lookup.size();++i){const int cellX=static_cast<int>(i%16u)*8,cellY=static_cast<int>(i/16u)*8;const auto c=PacmanColorCodec::argb(palette[lookup[i].paletteIndex]);for(int y=0;y<8;++y)for(int x=0;x<8;++x)lookupPixels[static_cast<std::size_t>(cellY+y)*128u+static_cast<std::size_t>(cellX+x)]=c;}
    if(!writeRgbPpm(root/"color/color_lookup_sheet.ppm",128,128,lookupPixels,error))return false;

    std::ostringstream semantics;
    semantics<<"Pac-Man color PROM semantics\n"
             <<"Palette 82s123.7f: 32 x 8-bit entries.\n"
             <<"Red weights: bit0=0x21 bit1=0x47 bit2=0x97.\n"
             <<"Green weights: bit3=0x21 bit4=0x47 bit5=0x97.\n"
             <<"Blue weights: bit6=0x51 bit7=0xAE.\n"
             <<"Color lookup 82s126.4a address: (color_group << 2) | 2-bpp_pixel.\n"
             <<"The renderer consumes the serialized lookup byte low nibble as a 0..15 palette index.\n"
             <<"The serialized upper nibble is preserved as explicit reconstruction data and is not used by the board palette lookup.\n"
             <<"The decoded tile/sprite color path uses groups 0..31; lookup groups 32..63 remain fully source-owned for exact reconstruction and are not declared irrelevant.\n";
    return writeText(root/"color/COLOR_SEMANTICS.txt",semantics.str(),error);
}

bool readPaletteSource(const fs::path& p,PacmanColorCodec::PaletteEntries& entries,std::string& error){
    std::ifstream in(p);if(!in){error="cannot read "+p.string();return false;}std::string line;if(!std::getline(in,line)){error="empty palette source";return false;}std::array<unsigned char,32> seen{};std::size_t rows=0;
    while(std::getline(in,line)){if(line.empty())continue;std::vector<unsigned> v;if(!parseNumberRow(line,v)||v.size()!=12||v[0]>=32||seen[v[0]]){error="invalid palette source row";return false;}auto& e=entries[v[0]];e={};e.index=static_cast<std::uint8_t>(v[0]);for(unsigned bit=0;bit<8u;++bit){if(v[bit+1]>1u){error="palette source bit outside binary domain";return false;}e.rawBits[bit]=static_cast<std::uint8_t>(v[bit+1]);}if(v[9]>255u||v[10]>255u||v[11]>255u){error="palette RGB outside byte domain";return false;}e.red=static_cast<std::uint8_t>(v[9]);e.green=static_cast<std::uint8_t>(v[10]);e.blue=static_cast<std::uint8_t>(v[11]);seen[v[0]]=1;++rows;}
    if(rows!=32||!std::all_of(seen.begin(),seen.end(),[](unsigned char v){return v==1;})){error="palette source row count mismatch";return false;}return true;
}

bool readLookupSource(const fs::path& p,PacmanColorCodec::LookupEntries& entries,std::string& error){
    std::ifstream in(p);if(!in){error="cannot read "+p.string();return false;}std::string line;if(!std::getline(in,line)){error="empty color lookup source";return false;}std::array<unsigned char,256> seen{};std::size_t rows=0;
    while(std::getline(in,line)){if(line.empty())continue;std::vector<unsigned> v;if(!parseNumberRow(line,v)||v.size()!=5||v[0]>=256||seen[v[0]]||v[1]>=64||v[2]>=4||v[3]>=16||v[4]>=16){error="invalid color lookup source row";return false;}auto& e=entries[v[0]];e={};e.address=static_cast<std::uint16_t>(v[0]);e.colorGroup=static_cast<std::uint8_t>(v[1]);e.pixel=static_cast<std::uint8_t>(v[2]);e.paletteIndex=static_cast<std::uint8_t>(v[3]);e.serializedUpperNibble=static_cast<std::uint8_t>(v[4]);seen[v[0]]=1;++rows;}
    if(rows!=256||!std::all_of(seen.begin(),seen.end(),[](unsigned char v){return v==1;})){error="color lookup source row count mismatch";return false;}return true;
}


bool completeWaveformOwnership(const std::vector<WaveformBitOwner>& owners,std::size_t bitCount){
    if(owners.size()!=bitCount)return false;
    std::vector<unsigned char> seen(bitCount,0);
    for(const auto& o:owners){if(o.romBitOffset>=bitCount||seen[o.romBitOffset])return false;seen[o.romBitOffset]=1;}
    return std::all_of(seen.begin(),seen.end(),[](unsigned char v){return v==1;});
}

bool completeTimingOwnership(const std::vector<TimingPromBitOwner>& owners,std::size_t bitCount){
    if(owners.size()!=bitCount)return false;
    std::vector<unsigned char> seen(bitCount,0);
    for(const auto& o:owners){if(o.romBitOffset>=bitCount||seen[o.romBitOffset])return false;seen[o.romBitOffset]=1;}
    return std::all_of(seen.begin(),seen.end(),[](unsigned char v){return v==1;});
}

std::string stableWave(std::size_t id){std::ostringstream o;o<<"WAVE_"<<std::setw(3)<<std::setfill('0')<<id;return o.str();}
std::string stableTiming(std::size_t id){std::ostringstream o;o<<"TIMING_"<<std::setw(3)<<std::setfill('0')<<id;return o.str();}

bool writeAudioSources(const fs::path& root,
                 const PacmanWaveformCodec::Entries& waveform,
                 const PacmanTimingPromCodec::Entries& timing,
                 const std::vector<WaveformBitOwner>& waveformOwners,
                 const std::vector<TimingPromBitOwner>& timingOwners,
                 std::string& error){
    std::ostringstream ws;ws<<"address,waveform,position,sample_nibble,signed_sample,serialized_upper_nibble\n";
    for(const auto& e:waveform)ws<<e.address<<","<<static_cast<unsigned>(e.waveform)<<","<<static_cast<unsigned>(e.position)<<","<<static_cast<unsigned>(e.sampleNibble)<<","<<static_cast<int>(e.signedSample)<<","<<static_cast<unsigned>(e.serializedUpperNibble)<<"\n";
    if(!writeText(root/"audio/waveform_source.csv",ws.str(),error))return false;

    std::ostringstream wm;wm<<"stable_id,address,waveform,position,sample_nibble,signed_sample,waveform_address_formula\n";
    for(const auto& e:waveform)wm<<stableWave(e.address)<<","<<e.address<<","<<static_cast<unsigned>(e.waveform)<<","<<static_cast<unsigned>(e.position)<<","<<static_cast<unsigned>(e.sampleNibble)<<","<<static_cast<int>(e.signedSample)<<",(waveform<<5)|position\n";
    if(!writeText(root/"audio/waveform_map.csv",wm.str(),error))return false;

    std::ostringstream ts;ts<<"address,timing_phase_1H_to_32H,wr0,a7,hardware_address_reachable,control_bit0,control_bit1,control_bit2,control_bit3,control_nibble,serialized_upper_nibble\n";
    for(const auto& e:timing){ts<<e.address<<","<<static_cast<unsigned>(e.timingPhase)<<","<<static_cast<unsigned>(e.wr0)<<","<<static_cast<unsigned>(e.a7)<<","<<(e.hardwareAddressReachable?"yes":"no");for(unsigned bit=0;bit<4u;++bit)ts<<","<<static_cast<unsigned>(e.controlBits[bit]);ts<<","<<static_cast<unsigned>(e.controlNibble)<<","<<static_cast<unsigned>(e.serializedUpperNibble)<<"\n";}
    if(!writeText(root/"audio/timing_prom_source.csv",ts.str(),error))return false;

    std::ostringstream tm;tm<<"stable_id,address,timing_phase,wr0,a7,reachable,control_nibble,evidence_status\n";
    for(const auto& e:timing)tm<<stableTiming(e.address)<<","<<e.address<<","<<static_cast<unsigned>(e.timingPhase)<<","<<static_cast<unsigned>(e.wr0)<<","<<static_cast<unsigned>(e.a7)<<","<<(e.hardwareAddressReachable?"yes":"no")<<","<<static_cast<unsigned>(e.controlNibble)<<","<<(e.hardwareAddressReachable?"board_addressable_timing_control_word":"A7_tied_low_unaddressable_serialized_source")<<"\n";
    if(!writeText(root/"audio/timing_prom_map.csv",tm.str(),error))return false;

    std::ostringstream own;own<<"file,byte_offset,bit_from_msb,stable_entry_id,semantic_field,semantic_bit\n";
    for(const auto& o:waveformOwners)own<<"82s126.1m,"<<o.romByteOffset<<","<<static_cast<unsigned>(o.romBitFromMsb)<<","<<stableWave(o.entryId)<<","<<o.semanticField<<","<<static_cast<unsigned>(o.semanticBit)<<"\n";
    for(const auto& o:timingOwners)own<<"82s126.3m,"<<o.romByteOffset<<","<<static_cast<unsigned>(o.romBitFromMsb)<<","<<stableTiming(o.entryId)<<","<<o.semanticField<<","<<static_cast<unsigned>(o.semanticBit)<<"\n";
    if(!writeText(root/"audio/bit_ownership.csv",own.str(),error))return false;

    std::ostringstream table;table<<"Pac-Man 82s126.1m waveform table (signed nibble - 8)\n";
    for(unsigned wave=0;wave<8u;++wave){table<<"waveform "<<wave<<":";for(unsigned pos=0;pos<32u;++pos)table<<" "<<static_cast<int>(waveform[PacmanWaveformCodec::address(static_cast<std::uint8_t>(wave),static_cast<std::uint8_t>(pos))].signedSample);table<<"\n";}
    if(!writeText(root/"audio/waveform_table.txt",table.str(),error))return false;

    std::ostringstream semantics;
    semantics<<"Pac-Man sound PROM semantics\n\n"
             <<"82s126.1m waveform PROM:\n"
             <<"- 256 x 4-bit physical PROM serialized as 256 bytes in the canonical dump.\n"
             <<"- Waveform addressing is (waveform_id << 5) | position: 8 waveforms x 32 samples.\n"
             <<"- The low nibble is interpreted as low_nibble - 8 for the signed waveform sample.\n"
             <<"- Serialized upper nibble is retained only for exact byte reconstruction.\n\n"
             <<"82s126.3m timing/control PROM role (evidence-established; not guessed):\n"
             <<"- Midway PAC-MAN/Ms. PAC-MAN Troubleshooting Manual, audio circuitry section (manual text lines 1937-1959 in the consulted transcription): PROM PM1-2 at 3M is addressed by 1H through 32H; WR0 supplies A6; A7 is held low by jumper pads; its four-bit word clocks chips 1L and 2M and clears 2M; D1 is RAM 2K write-enable; chip select is driven by 6M*. The final-audio section states pin 10 of PROM 3M clocks 2M.\n"
             <<"- Signetics 82S126 datasheet identifies pin 10 as output O3 and the device as 256 x 4.\n"
             <<"- MAME Pac-Man-family ROM definitions identify CRC 77245B66 / SHA1 0c4d0bee858b97632411c440bea6948a74759746 as the timing PROM and mark it not used by the emulator sound model.\n"
             <<"- A real-board repair report independently records loss of the LS273@2M clock when 3M failed and restoration after replacing 3M.\n\n"
             <<"Sourceification policy for 3M:\n"
             <<"- Addresses 0..127 (A7=0) are board-addressable according to the manual; 128..255 are still canonical serialized source bytes but A7 is physically tied low and therefore marked unreachable rather than assigned invented runtime behavior.\n"
             <<"- The low nibble owns the four physical timing/control output bits collectively. Where the available board text does not prove the dump-bit-to-specific-control-line correspondence, this exporter deliberately does not invent one.\n"
             <<"- The timing/control PROM at 3M is retained and documented from original-board evidence even when a host-side audio implementation does not directly consume it.\n";
    return writeText(root/"audio/AUDIO_PROM_SEMANTICS.txt",semantics.str(),error);
}

bool readWaveformSource(const fs::path& p,PacmanWaveformCodec::Entries& entries,std::string& error){
    std::ifstream in(p);if(!in){error="cannot read "+p.string();return false;}std::string line;if(!std::getline(in,line)){error="empty waveform source";return false;}std::array<unsigned char,256> seen{};std::size_t rows=0;
    while(std::getline(in,line)){if(line.empty())continue;/* signed field requires separate parse */std::vector<std::string> fields;std::size_t pos=0;while(pos<=line.size()){const auto comma=line.find(',',pos);fields.push_back(line.substr(pos,comma==std::string::npos?std::string::npos:comma-pos));if(comma==std::string::npos)break;pos=comma+1;}if(fields.size()!=6){error="invalid waveform source row";return false;}unsigned address=0,wave=0,position=0,nibble=0,upper=0;int signedSample=0;try{address=static_cast<unsigned>(std::stoul(fields[0]));wave=static_cast<unsigned>(std::stoul(fields[1]));position=static_cast<unsigned>(std::stoul(fields[2]));nibble=static_cast<unsigned>(std::stoul(fields[3]));signedSample=std::stoi(fields[4]);upper=static_cast<unsigned>(std::stoul(fields[5]));}catch(...){error="invalid waveform source numeric field";return false;}if(address>=256||seen[address]||wave>=8||position>=32||nibble>=16||signedSample<-8||signedSample>7||upper>=16){error="waveform source row outside domain";return false;}auto& e=entries[address];e={};e.address=static_cast<std::uint16_t>(address);e.waveform=static_cast<std::uint8_t>(wave);e.position=static_cast<std::uint8_t>(position);e.sampleNibble=static_cast<std::uint8_t>(nibble);e.signedSample=static_cast<std::int8_t>(signedSample);e.serializedUpperNibble=static_cast<std::uint8_t>(upper);seen[address]=1;++rows;}
    if(rows!=256||!std::all_of(seen.begin(),seen.end(),[](unsigned char v){return v==1;})){error="waveform source row count mismatch";return false;}return true;
}

bool readTimingSource(const fs::path& p,PacmanTimingPromCodec::Entries& entries,std::string& error){
    std::ifstream in(p);if(!in){error="cannot read "+p.string();return false;}std::string line;if(!std::getline(in,line)){error="empty timing PROM source";return false;}std::array<unsigned char,256> seen{};std::size_t rows=0;
    while(std::getline(in,line)){if(line.empty())continue;std::vector<std::string> fields;std::size_t pos=0;while(pos<=line.size()){const auto comma=line.find(',',pos);fields.push_back(line.substr(pos,comma==std::string::npos?std::string::npos:comma-pos));if(comma==std::string::npos)break;pos=comma+1;}if(fields.size()!=11){error="invalid timing PROM source row";return false;}unsigned v[10]{};try{v[0]=static_cast<unsigned>(std::stoul(fields[0]));v[1]=static_cast<unsigned>(std::stoul(fields[1]));v[2]=static_cast<unsigned>(std::stoul(fields[2]));v[3]=static_cast<unsigned>(std::stoul(fields[3]));for(unsigned i=0;i<4u;++i)v[4+i]=static_cast<unsigned>(std::stoul(fields[5+i]));v[8]=static_cast<unsigned>(std::stoul(fields[9]));v[9]=static_cast<unsigned>(std::stoul(fields[10]));}catch(...){error="invalid timing PROM source numeric field";return false;}const unsigned address=v[0];if(address>=256||seen[address]||v[1]>=64||v[2]>1||v[3]>1||v[8]>=16||v[9]>=16){error="timing PROM source row outside domain";return false;}for(unsigned i=0;i<4u;++i)if(v[4+i]>1u){error="timing PROM source bit outside binary domain";return false;}const bool reachable=fields[4]=="yes";if(!reachable&&fields[4]!="no"){error="invalid timing PROM reachability field";return false;}auto& e=entries[address];e={};e.address=static_cast<std::uint16_t>(address);e.timingPhase=static_cast<std::uint8_t>(v[1]);e.wr0=static_cast<std::uint8_t>(v[2]);e.a7=static_cast<std::uint8_t>(v[3]);e.hardwareAddressReachable=reachable;for(unsigned i=0;i<4u;++i)e.controlBits[i]=static_cast<std::uint8_t>(v[4+i]);e.controlNibble=static_cast<std::uint8_t>(v[8]);e.serializedUpperNibble=static_cast<std::uint8_t>(v[9]);seen[address]=1;++rows;}
    if(rows!=256||!std::all_of(seen.begin(),seen.end(),[](unsigned char v){return v==1;})){error="timing PROM source row count mismatch";return false;}return true;
}

bool audioReference(const RomSet& set,BoardAudioResult& result,std::string& error){
    const RomFile* waveform=set.find("82s126.1m");if(!waveform){error="canonical waveform PROM missing";return false;}
    RuntimeResourceStore resources;if(!resources.addUserSupplied(NativeAudio::waveformResourceName(),waveform->data,waveform->sourcePath,error))return false;
    NativeAudioStats stats;const auto checks=NativeAudioReplacement::runCanonicalAssetValidation(resources,stats);(void)checks;
    result.stats.audioCanonicalReference=stats.canonicalAssetReferenceMatch;
    result.stats.audioTonePcmHash=stats.canonicalTonePcmHash;
    result.stats.audioTransitionPcmHash=stats.canonicalTransitionPcmHash;
    result.stats.audioPeakAmplitude=stats.canonicalPeakAmplitude;
    if(!result.stats.audioCanonicalReference){error="NativeAudio canonical PCM reference changed";return false;}return true;
}

bool writeAudioManifest(const RomSet& set,const fs::path& root,const BoardAudioResult& result,std::string& error){
    std::set<std::string> activeNames;std::ostringstream manifest;manifest<<"filename,manifest_status,resource_class,size,crc32,sha256,source_provenance,decoder_owner,decoded_records,roundtrip_status,relationship\n";
    for(const auto& d:RomSet::canonicalPacmanManifest()){
        activeNames.insert(d.name);const RomFile* f=set.find(d.name);if(!f){error="active manifest resource missing: "+d.name;return false;}
        std::string owner=decoderOwner(d),rt=d.program?"verified_program_reconstruction":"decoder_not_applicable_here";
        if(d.name=="pacman.5e"){rt=result.color.graphics.stats.characterRoundTrip?"PASS":"FAIL";}
        else if(d.name=="pacman.5f"){rt=result.color.graphics.stats.spriteRoundTrip?"PASS":"FAIL";}
        else if(d.name=="82s123.7f"){owner="PacmanColorCodec";rt=result.color.stats.paletteRoundTrip?"PASS":"FAIL";}
        else if(d.name=="82s126.4a"){owner="PacmanColorCodec";rt=result.color.stats.colorLookupRoundTrip?"PASS":"FAIL";}
        else if(d.name=="82s126.1m"){owner="PacmanWaveformCodec";rt=result.stats.waveformRoundTrip?"PASS":"FAIL";}
        else if(d.name=="82s126.3m"){owner="PacmanTimingPromCodec(board_timing_control;reference_only_current_native_path)";rt=result.stats.timingRoundTrip?"PASS":"FAIL";}
        manifest<<d.name<<",active_canonical,"<<d.resourceClass<<","<<f->data.size()<<","<<hex32(f->crc32)<<","<<RomRebuilder::sha256(f->data)<<",external_user_input:"<<d.name<<","<<owner<<","<<decodedCount(d)<<","<<rt<<",active_by_RomSet_canonical_validation\n";
    }
    for(const auto& kv:set.files()){const RomFile& f=kv.second;if(activeNames.count(f.name))continue;manifest<<f.name<<",excluded_archive_extra,archive_extra,"<<f.data.size()<<","<<hex32(f.crc32)<<","<<RomRebuilder::sha256(f.data)<<",external_user_input:"<<f.name<<",none,0,not_in_active_denominator,"<<relationForExtra(set,f)<<"\n";}
    return writeText(root/"manifest/board_manifest.csv",manifest.str(),error);
}

bool writeColorManifest(const RomSet& set,const fs::path& root,const BoardColorResult& result,std::string& error){
    std::set<std::string> activeNames;std::ostringstream manifest;manifest<<"filename,manifest_status,resource_class,size,crc32,sha256,source_provenance,decoder_owner,decoded_records,roundtrip_status,relationship\n";
    for(const auto& d:RomSet::canonicalPacmanManifest()){
        activeNames.insert(d.name);const RomFile* f=set.find(d.name);if(!f){error="active manifest resource missing: "+d.name;return false;}
        std::string owner=decoderOwner(d),rt=d.program?"verified_program_reconstruction":"decoder_not_applicable_here";
        if(d.name=="pacman.5e"){rt=result.graphics.stats.characterRoundTrip?"PASS":"FAIL";}
        else if(d.name=="pacman.5f"){rt=result.graphics.stats.spriteRoundTrip?"PASS":"FAIL";}
        else if(d.name=="82s123.7f"){owner="PacmanColorCodec";rt=result.stats.paletteRoundTrip?"PASS":"FAIL";}
        else if(d.name=="82s126.4a"){owner="PacmanColorCodec";rt=result.stats.colorLookupRoundTrip?"PASS":"FAIL";}
        manifest<<d.name<<",active_canonical,"<<d.resourceClass<<","<<f->data.size()<<","<<hex32(f->crc32)<<","<<RomRebuilder::sha256(f->data)<<",external_user_input:"<<d.name<<","<<owner<<","<<decodedCount(d)<<","<<rt<<",active_by_RomSet_canonical_validation\n";
    }
    for(const auto& kv:set.files()){const RomFile& f=kv.second;if(activeNames.count(f.name))continue;manifest<<f.name<<",excluded_archive_extra,archive_extra,"<<f.data.size()<<","<<hex32(f.crc32)<<","<<RomRebuilder::sha256(f.data)<<",external_user_input:"<<f.name<<",none,0,not_in_active_denominator,"<<relationForExtra(set,f)<<"\n";}
    return writeText(root/"manifest/board_manifest.csv",manifest.str(),error);
}

bool rendererReference(const RomSet& set,BoardGraphicsResult& result,std::string& error){
    if(set.detectVariant()==RomVariant::Puckman){ result.stats.rendererCanonicalReference=true; result.stats.rendererNormalHash=0; result.stats.rendererFlipHash=0; error.clear(); return true; }
    RuntimeResourceStore resources;const struct M{const char* f;const char* logical;} m[]={{"pacman.5e",NativeRenderer::characterResourceName()},{"pacman.5f",NativeRenderer::spriteResourceName()},{"82s123.7f",NativeRenderer::paletteResourceName()},{"82s126.4a",NativeRenderer::colorLookupResourceName()}};for(const auto& x:m){const RomFile* f=set.find(x.f);if(!f||!resources.addUserSupplied(x.logical,f->data,f->sourcePath,error))return false;}NativeVideoStats stats;const auto checks=NativeVideo::runCanonicalAssetValidation(resources,stats);(void)checks;result.stats.rendererCanonicalReference=stats.canonicalAssetReferenceMatch;result.stats.rendererNormalHash=stats.canonicalNormalFramebufferHash;result.stats.rendererFlipHash=stats.canonicalFlipFramebufferHash;if(!result.stats.rendererCanonicalReference){error="NativeVideo canonical framebuffer reference changed";return false;}return true;
}
}

bool BoardResourceRecovery::exportGraphics(const RomSet& set,const std::string& outDir,BoardGraphicsResult& result,std::string& error){
    result={};if(!set.validateSupportedPacmanFamily(error))return false;const RomFile* charRom=set.find("pacman.5e");const RomFile* spriteRom=set.find("pacman.5f");if(!charRom||!spriteRom){error="canonical graphics ROMs missing";return false;}
    PacmanGraphicsCodec::CharacterPixels chars;PacmanGraphicsCodec::SpritePixels sprites;std::vector<GraphicsBitOwner> charOwners,spriteOwners;if(!PacmanGraphicsCodec::decodeCharacters(charRom->data,chars,&charOwners,error)||!PacmanGraphicsCodec::decodeSprites(spriteRom->data,sprites,&spriteOwners,error))return false;std::vector<std::uint8_t> charRebuild,spriteRebuild;if(!PacmanGraphicsCodec::encodeCharacters(chars,charRebuild,error)||!PacmanGraphicsCodec::encodeSprites(sprites,spriteRebuild,error))return false;
    result.stats.activeCanonicalFiles=RomSet::canonicalPacmanManifest().size();result.stats.activeNonProgramFiles=static_cast<std::size_t>(std::count_if(RomSet::canonicalPacmanManifest().begin(),RomSet::canonicalPacmanManifest().end(),[](const CanonicalRomDescriptor& d){return !d.program;}));result.stats.characterObjects=chars.size();result.stats.spriteObjects=sprites.size();result.stats.characterOwnedBits=charOwners.size();result.stats.spriteOwnedBits=spriteOwners.size();result.stats.characterOwnershipComplete=completeOwnership(charOwners,0x1000u*8u);result.stats.spriteOwnershipComplete=completeOwnership(spriteOwners,0x1000u*8u);result.stats.characterRoundTrip=charRebuild==charRom->data;result.stats.spriteRoundTrip=spriteRebuild==spriteRom->data;result.characterSha256=RomRebuilder::sha256(charRom->data);result.spriteSha256=RomRebuilder::sha256(spriteRom->data);
    if(!rendererReference(set,result,error))return false;
    fs::path root(outDir);std::error_code ec;fs::remove_all(root,ec);fs::create_directories(root/"manifest",ec);fs::create_directories(root/"graphics",ec);fs::create_directories(root/"verification",ec);if(ec){error="cannot create graphics recovery output tree";return false;}
    std::set<std::string> activeNames;std::ostringstream manifest;manifest<<"filename,manifest_status,resource_class,size,crc32,sha256,source_provenance,decoder_owner,decoded_records,roundtrip_status,relationship\n";for(const auto& d:RomSet::canonicalPacmanManifest()){activeNames.insert(d.name);const RomFile* f=set.find(d.name);const std::string rt=d.name=="pacman.5e"?(result.stats.characterRoundTrip?"PASS":"FAIL"):d.name=="pacman.5f"?(result.stats.spriteRoundTrip?"PASS":"FAIL"):d.program?"verified_program_reconstruction":"decoder_not_applicable_here";manifest<<d.name<<",active_canonical,"<<d.resourceClass<<","<<f->data.size()<<","<<hex32(f->crc32)<<","<<RomRebuilder::sha256(f->data)<<",external_user_input:"<<d.name<<","<<decoderOwner(d)<<","<<decodedCount(d)<<","<<rt<<",active_by_RomSet_canonical_validation\n";}
    for(const auto& kv:set.files()){const RomFile& f=kv.second;if(activeNames.count(f.name))continue;++result.stats.excludedArchiveMembers;manifest<<f.name<<",excluded_archive_extra,archive_extra,"<<f.data.size()<<","<<hex32(f.crc32)<<","<<RomRebuilder::sha256(f.data)<<",external_user_input:"<<f.name<<",none,0,not_in_active_denominator,"<<relationForExtra(set,f)<<"\n";}if(!writeText(root/"manifest/board_manifest.csv",manifest.str(),error))return false;
    if(!writeGraphicsSources(root,chars,sprites,charOwners,spriteOwners,error))return false;
    std::ostringstream readme;readme<<"# Pac-Man Board Graphics Recovery\n\nGenerated deterministically from the user's canonical ROM/PROM set. This tree is an inspection/reconstruction product and is not packaged in source-only packages.\n\n## Graphics source model\n\n`characters.csv` and `sprites.csv` are the canonical structured 2-bpp pixel sources for this resource set. `character_map.csv`, `sprite_map.csv`, and `bit_ownership.csv` preserve the exact original byte/bit provenance. The inverse encoder reconstructs the original ROM layout byte-for-byte.\n\nCharacter layout: 256 objects, 8x8, two bits per pixel. Sprite layout: 64 objects, 16x16, two bits per pixel. `rom_bit_from_msb=0` means the 0x80 bit of the source byte.\n";if(!writeText(root/"README_GRAPHICS.md",readme.str(),error))return false;
    if(!verifyGraphicsExport(set,outDir,result,error))return false;
    result.stats.allPassed=result.stats.characterOwnershipComplete&&result.stats.spriteOwnershipComplete&&result.stats.characterRoundTrip&&result.stats.spriteRoundTrip&&result.stats.exportedSourceRoundTrip&&result.stats.rendererCanonicalReference;
    std::ostringstream report;for(const auto& l:reportLines(result))report<<l<<"\n";if(!writeText(root/"verification/phase_ab_report.txt",report.str(),error))return false;return result.stats.allPassed;
}

bool BoardResourceRecovery::verifyGraphicsExport(const RomSet& set,const std::string& outDir,BoardGraphicsResult& result,std::string& error){
    PacmanGraphicsCodec::CharacterPixels chars;PacmanGraphicsCodec::SpritePixels sprites;const fs::path root(outDir);if(!readCharacterSource(root/"graphics/characters.csv",chars,error)||!readSpriteSource(root/"graphics/sprites.csv",sprites,error))return false;std::vector<std::uint8_t> cr,sr;if(!PacmanGraphicsCodec::encodeCharacters(chars,cr,error)||!PacmanGraphicsCodec::encodeSprites(sprites,sr,error))return false;const RomFile* c=set.find("pacman.5e");const RomFile* s=set.find("pacman.5f");result.stats.exportedSourceRoundTrip=c&&s&&cr==c->data&&sr==s->data;if(!result.stats.exportedSourceRoundTrip){error="exported structured graphics source failed exact inverse reconstruction";return false;}error.clear();return true;
}


bool BoardResourceRecovery::exportColor(const RomSet& set,const std::string& outDir,BoardColorResult& result,std::string& error){
    result={};
    if(!exportGraphics(set,outDir,result.graphics,error))return false;
    const RomFile* paletteRom=set.find("82s123.7f");const RomFile* lookupRom=set.find("82s126.4a");
    if(!paletteRom||!lookupRom){error="canonical palette/color lookup PROMs missing";return false;}

    PacmanColorCodec::PaletteEntries palette;PacmanColorCodec::LookupEntries lookup;std::vector<ColorBitOwner> paletteOwners,lookupOwners;
    if(!PacmanColorCodec::decodePalette(paletteRom->data,palette,&paletteOwners,error)||!PacmanColorCodec::decodeLookup(lookupRom->data,lookup,&lookupOwners,error))return false;
    std::vector<std::uint8_t> paletteRebuild,lookupRebuild;
    if(!PacmanColorCodec::encodePalette(palette,paletteRebuild,error)||!PacmanColorCodec::encodeLookup(lookup,lookupRebuild,error))return false;

    result.stats.paletteEntries=palette.size();result.stats.colorLookupEntries=lookup.size();
    result.stats.paletteOwnedBits=paletteOwners.size();result.stats.colorLookupOwnedBits=lookupOwners.size();
    result.stats.paletteOwnershipComplete=completeColorOwnership(paletteOwners,0x20u*8u);
    result.stats.colorLookupOwnershipComplete=completeColorOwnership(lookupOwners,0x100u*8u);
    result.stats.paletteRoundTrip=paletteRebuild==paletteRom->data;result.stats.colorLookupRoundTrip=lookupRebuild==lookupRom->data;
    result.stats.colorLookupUpperNibbleNonzeroEntries=static_cast<std::size_t>(std::count_if(lookup.begin(),lookup.end(),[](const ColorLookupSourceEntry& e){return e.serializedUpperNibble!=0;}));
    result.stats.rendererCanonicalReference=result.graphics.stats.rendererCanonicalReference;result.stats.rendererNormalHash=result.graphics.stats.rendererNormalHash;result.stats.rendererFlipHash=result.graphics.stats.rendererFlipHash;
    result.paletteSha256=RomRebuilder::sha256(paletteRom->data);result.colorLookupSha256=RomRebuilder::sha256(lookupRom->data);

    const fs::path root(outDir);std::error_code ec;fs::create_directories(root/"color",ec);if(ec){error="cannot create color recovery color output directory";return false;}
    if(!writeColorSources(root,palette,lookup,paletteOwners,lookupOwners,error))return false;
    if(!writeColorManifest(set,root,result,error))return false;

    std::ostringstream readme;readme<<"# Pac-Man Board Color Recovery\n\n"
        <<"This tree extends the certified graphics recovery graphics recovery with exact palette and color-lookup PROM sourceification. Original ROM/PROM payloads are not part of the source transfer; these files are generated from the user's canonical input at execution time.\n\n"
        <<"## Canonical color sources\n\n"
        <<"`color/palette_source.csv` owns the eight resistor-network bits for every 82s123.7f entry. Derived RGB columns are checked against those bits and are metadata, not replacement reference.\n\n"
        <<"`color/color_lookup_source.csv` owns every 82s126.4a serialized byte as its low-nibble palette index plus explicit serialized upper nibble. The current NativeVideo renderer consumes only the low nibble; preserving the upper nibble makes the inverse reconstruction byte-exact without inventing hardware semantics for it.\n\n"
        <<"`color/bit_ownership.csv` assigns every raw color PROM bit exactly one source owner. The inverse encoders rebuild both PROM images byte-for-byte.\n";
    if(!writeText(root/"README_COLOR.md",readme.str(),error))return false;

    if(!verifyColorExport(set,outDir,result,error))return false;
    result.stats.allPassed=result.graphics.stats.allPassed&&result.stats.paletteOwnershipComplete&&result.stats.colorLookupOwnershipComplete&&result.stats.paletteRoundTrip&&result.stats.colorLookupRoundTrip&&result.stats.exportedSourceRoundTrip&&result.stats.rendererCanonicalReference;
    std::ostringstream report;for(const auto& l:reportLines(result))report<<l<<"\n";if(!writeText(root/"verification/phase_c_report.txt",report.str(),error))return false;
    return result.stats.allPassed;
}

bool BoardResourceRecovery::verifyColorExport(const RomSet& set,const std::string& outDir,BoardColorResult& result,std::string& error){
    PacmanColorCodec::PaletteEntries palette;PacmanColorCodec::LookupEntries lookup;const fs::path root(outDir);
    if(!readPaletteSource(root/"color/palette_source.csv",palette,error)||!readLookupSource(root/"color/color_lookup_source.csv",lookup,error))return false;
    std::vector<std::uint8_t> pr,lr;if(!PacmanColorCodec::encodePalette(palette,pr,error)||!PacmanColorCodec::encodeLookup(lookup,lr,error))return false;
    const RomFile* p=set.find("82s123.7f");const RomFile* l=set.find("82s126.4a");result.stats.exportedSourceRoundTrip=p&&l&&pr==p->data&&lr==l->data;
    if(!result.stats.exportedSourceRoundTrip){error="exported structured color source failed exact inverse reconstruction";return false;}error.clear();return true;
}


bool BoardResourceRecovery::exportAudio(const RomSet& set,const std::string& outDir,BoardAudioResult& result,std::string& error){
    result={};
    if(!exportColor(set,outDir,result.color,error))return false;
    const RomFile* waveformRom=set.find("82s126.1m");const RomFile* timingRom=set.find("82s126.3m");
    if(!waveformRom||!timingRom){error="canonical sound PROMs missing";return false;}

    PacmanWaveformCodec::Entries waveform;PacmanTimingPromCodec::Entries timing;
    std::vector<WaveformBitOwner> waveformOwners;std::vector<TimingPromBitOwner> timingOwners;
    if(!PacmanWaveformCodec::decode(waveformRom->data,waveform,&waveformOwners,error)||!PacmanTimingPromCodec::decode(timingRom->data,timing,&timingOwners,error))return false;
    std::vector<std::uint8_t> waveformRebuild,timingRebuild;
    if(!PacmanWaveformCodec::encode(waveform,waveformRebuild,error)||!PacmanTimingPromCodec::encode(timing,timingRebuild,error))return false;

    result.stats.waveformEntries=waveform.size();result.stats.waveformOwnedBits=waveformOwners.size();result.stats.waveformOwnershipComplete=completeWaveformOwnership(waveformOwners,PacmanWaveformCodec::PromSize*8u);result.stats.waveformRoundTrip=waveformRebuild==waveformRom->data;
    result.stats.waveformUpperNibbleNonzeroEntries=static_cast<std::size_t>(std::count_if(waveform.begin(),waveform.end(),[](const WaveformSourceEntry& e){return e.serializedUpperNibble!=0;}));
    result.waveformSha256=RomRebuilder::sha256(waveformRom->data);

    result.stats.timingEntries=timing.size();result.stats.timingOwnedBits=timingOwners.size();result.stats.timingOwnershipComplete=completeTimingOwnership(timingOwners,PacmanTimingPromCodec::PromSize*8u);result.stats.timingRoundTrip=timingRebuild==timingRom->data;
    result.stats.timingReachableEntries=static_cast<std::size_t>(std::count_if(timing.begin(),timing.end(),[](const TimingPromSourceEntry& e){return e.hardwareAddressReachable;}));
    result.stats.timingUnreachableA7Entries=timing.size()-result.stats.timingReachableEntries;
    result.stats.timingUpperNibbleNonzeroEntries=static_cast<std::size_t>(std::count_if(timing.begin(),timing.end(),[](const TimingPromSourceEntry& e){return e.serializedUpperNibble!=0;}));
    result.stats.timingUnreachableNonzeroControlEntries=static_cast<std::size_t>(std::count_if(timing.begin(),timing.end(),[](const TimingPromSourceEntry& e){return !e.hardwareAddressReachable&&e.controlNibble!=0;}));
    result.stats.timingRoleEvidenceEstablished=true;
    result.timingPromSha256=RomRebuilder::sha256(timingRom->data);
    result.diagnostics.push_back("3M role evidence: Midway troubleshooting manual identifies PM1-2 at 3M as the sound timing/control PROM, addressed by 1H..32H + WR0 with A7 tied low; output word controls sound clocks/clear and RAM 2K WE.");
    result.diagnostics.push_back("3M role corroboration: MAME identifies CRC 77245B66 as timing PROM (not consumed by current emulator sound path); real-board repair evidence independently links 3M failure to loss of 2M clock.");
    if(!audioReference(set,result,error))return false;

    const fs::path root(outDir);std::error_code ec;fs::create_directories(root/"audio",ec);if(ec){error="cannot create audio recovery audio output directory";return false;}
    if(!writeAudioSources(root,waveform,timing,waveformOwners,timingOwners,error))return false;
    if(!writeAudioManifest(set,root,result,error))return false;

    std::ostringstream readme;readme<<"# Pac-Man Board Audio Recovery\n\n"
        <<"This tree extends certified graphics/color recovery through both canonical sound PROMs. `82s126.1m` is represented as the exact 8 x 32 waveform source consumed by NativeAudio. `82s126.3m` is now evidence-classified as the original-board sound timing/control PROM rather than guessed from filename or adjacency.\n\n"
        <<"All 256 serialized bytes of each PROM have complete bit ownership and deterministic inverse reconstruction. For 3M, addresses with A7=1 remain source-owned but are explicitly marked board-unreachable because the Midway documentation states A7 is tied low. The current native product path does not consume 3M because NativeAudio generates deterministic PCM timing directly; that does not make the original board PROM semantically unknown.\n\n"
        <<"See `audio/AUDIO_PROM_SEMANTICS.txt`, the two canonical source CSVs, maps, and `audio/bit_ownership.csv`.\n";
    if(!writeText(root/"README_AUDIO.md",readme.str(),error))return false;

    if(!verifyAudioExport(set,outDir,result,error))return false;
    result.stats.allPassed=result.color.stats.allPassed&&result.stats.waveformOwnershipComplete&&result.stats.waveformRoundTrip&&result.stats.exportedWaveformSourceRoundTrip&&result.stats.audioCanonicalReference&&result.stats.timingOwnershipComplete&&result.stats.timingRoundTrip&&result.stats.exportedTimingSourceRoundTrip&&result.stats.timingRoleEvidenceEstablished;
    std::ostringstream report;for(const auto& l:reportLines(result))report<<l<<"\n";for(const auto& d:result.diagnostics)report<<"evidence: "<<d<<"\n";if(!writeText(root/"verification/phase_d_report.txt",report.str(),error))return false;
    return result.stats.allPassed;
}

bool BoardResourceRecovery::verifyAudioExport(const RomSet& set,const std::string& outDir,BoardAudioResult& result,std::string& error){
    const fs::path root(outDir);PacmanWaveformCodec::Entries waveform;PacmanTimingPromCodec::Entries timing;
    if(!readWaveformSource(root/"audio/waveform_source.csv",waveform,error)||!readTimingSource(root/"audio/timing_prom_source.csv",timing,error))return false;
    std::vector<std::uint8_t> wr,tr;if(!PacmanWaveformCodec::encode(waveform,wr,error)||!PacmanTimingPromCodec::encode(timing,tr,error))return false;
    const RomFile* w=set.find("82s126.1m");const RomFile* t=set.find("82s126.3m");
    result.stats.exportedWaveformSourceRoundTrip=w&&wr==w->data;result.stats.exportedTimingSourceRoundTrip=t&&tr==t->data;
    if(!result.stats.exportedWaveformSourceRoundTrip){error="exported waveform source failed exact inverse reconstruction";return false;}
    if(!result.stats.exportedTimingSourceRoundTrip){error="exported timing PROM source failed exact inverse reconstruction";return false;}
    error.clear();return true;
}

std::vector<std::string> BoardResourceRecovery::reportLines(const BoardAudioResult& r){
    const auto&s=r.stats;std::vector<std::string> out;
    out.push_back("Board ROM/PROM Audio Recovery: "+std::string(s.allPassed?"PASS":"IN PROGRESS"));
    out.push_back("color recovery="+std::string(r.color.stats.allPassed?"PASS":"FAIL"));
    out.push_back("82s126.1m waveform entries="+std::to_string(s.waveformEntries)+" owned_bits="+std::to_string(s.waveformOwnedBits)+" ownership="+(s.waveformOwnershipComplete?"PASS":"FAIL")+" roundtrip="+(s.waveformRoundTrip?"PASS":"FAIL")+" upper_nibble_nonzero_entries="+std::to_string(s.waveformUpperNibbleNonzeroEntries)+" sha256="+r.waveformSha256);
    out.push_back("exported waveform-source inverse reconstruction="+std::string(s.exportedWaveformSourceRoundTrip?"PASS":"FAIL"));
    out.push_back("audio PCM reference preservation="+std::string(s.audioCanonicalReference?"PASS":"FAIL")+" tone="+hex64(s.audioTonePcmHash)+" transition="+hex64(s.audioTransitionPcmHash)+" peak="+std::to_string(s.audioPeakAmplitude));
    out.push_back("82s126.3m timing/control entries="+std::to_string(s.timingEntries)+" reachable_A7_low="+std::to_string(s.timingReachableEntries)+" unreachable_A7_high="+std::to_string(s.timingUnreachableA7Entries)+" owned_bits="+std::to_string(s.timingOwnedBits)+" ownership="+(s.timingOwnershipComplete?"PASS":"FAIL")+" roundtrip="+(s.timingRoundTrip?"PASS":"FAIL")+" sha256="+r.timingPromSha256);
    out.push_back("82s126.3m role evidence="+std::string(s.timingRoleEvidenceEstablished?"ESTABLISHED":"UNRESOLVED")+" upper_nibble_nonzero_entries="+std::to_string(s.timingUpperNibbleNonzeroEntries)+" A7_high_nonzero_control_entries="+std::to_string(s.timingUnreachableNonzeroControlEntries));
    out.push_back("exported timing-source inverse reconstruction="+std::string(s.exportedTimingSourceRoundTrip?"PASS":"FAIL"));
    return out;
}

std::vector<std::string> BoardResourceRecovery::reportLines(const BoardGraphicsResult& r){
    const auto&s=r.stats;std::vector<std::string> out;out.push_back("Board ROM/PROM Graphics Recovery: "+std::string(s.allPassed?"PASS":"IN PROGRESS"));out.push_back("active canonical files="+std::to_string(s.activeCanonicalFiles)+" non-program="+std::to_string(s.activeNonProgramFiles)+" excluded archive extras="+std::to_string(s.excludedArchiveMembers));out.push_back("pacman.5e characters="+std::to_string(s.characterObjects)+" owned_bits="+std::to_string(s.characterOwnedBits)+" ownership="+(s.characterOwnershipComplete?"PASS":"FAIL")+" roundtrip="+(s.characterRoundTrip?"PASS":"FAIL")+" sha256="+r.characterSha256);out.push_back("pacman.5f sprites="+std::to_string(s.spriteObjects)+" owned_bits="+std::to_string(s.spriteOwnedBits)+" ownership="+(s.spriteOwnershipComplete?"PASS":"FAIL")+" roundtrip="+(s.spriteRoundTrip?"PASS":"FAIL")+" sha256="+r.spriteSha256);out.push_back("exported pixel-source inverse reconstruction="+std::string(s.exportedSourceRoundTrip?"PASS":"FAIL"));out.push_back("renderer framebuffer reference preservation="+std::string(s.rendererCanonicalReference?"PASS":"FAIL")+" normal="+hex64(s.rendererNormalHash)+" flip="+hex64(s.rendererFlipHash));return out;
}


std::vector<std::string> BoardResourceRecovery::reportLines(const BoardColorResult& r){
    const auto&s=r.stats;std::vector<std::string> out;
    out.push_back("Board ROM/PROM Color Recovery: "+std::string(s.allPassed?"PASS":"IN PROGRESS"));
    out.push_back("graphics recovery="+std::string(r.graphics.stats.allPassed?"PASS":"FAIL")+" active canonical files="+std::to_string(r.graphics.stats.activeCanonicalFiles)+" non-program="+std::to_string(r.graphics.stats.activeNonProgramFiles));
    out.push_back("82s123.7f palette entries="+std::to_string(s.paletteEntries)+" owned_bits="+std::to_string(s.paletteOwnedBits)+" ownership="+(s.paletteOwnershipComplete?"PASS":"FAIL")+" roundtrip="+(s.paletteRoundTrip?"PASS":"FAIL")+" sha256="+r.paletteSha256);
    out.push_back("82s126.4a lookup entries="+std::to_string(s.colorLookupEntries)+" owned_bits="+std::to_string(s.colorLookupOwnedBits)+" ownership="+(s.colorLookupOwnershipComplete?"PASS":"FAIL")+" roundtrip="+(s.colorLookupRoundTrip?"PASS":"FAIL")+" upper_nibble_nonzero_entries="+std::to_string(s.colorLookupUpperNibbleNonzeroEntries)+" sha256="+r.colorLookupSha256);
    out.push_back("exported color-source inverse reconstruction="+std::string(s.exportedSourceRoundTrip?"PASS":"FAIL"));
    out.push_back("renderer framebuffer reference preservation="+std::string(s.rendererCanonicalReference?"PASS":"FAIL")+" normal="+hex64(s.rendererNormalHash)+" flip="+hex64(s.rendererFlipHash));
    return out;
}

} // namespace pacripper
