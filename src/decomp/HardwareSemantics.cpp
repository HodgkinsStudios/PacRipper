// PacRipper hardware-semantics analysis hardware semantic layer
// Created by Jacob Hodgkins

#include "HardwareSemantics.h"

#include <algorithm>
#include <sstream>

namespace pacripper {
namespace {

std::string latchWriteIdentity(std::uint16_t a){
    static const char* names[8]={
        "irq_enable_write","sound_enable_write","aux_output_write","flip_screen_write",
        "lamp_1_write","lamp_2_write","coin_lockout_write","coin_counter_write"
    };
    return (a>=0x5000&&a<=0x5007)?names[a-0x5000]:std::string();
}

bool sameDeviceSpan(std::uint16_t start,std::uint16_t end,MemoryAccessKind access,BoardDeviceKind& device){
    if(end<=start)return false;
    device=HardwareSemantics::deviceFor(start,access);
    if(device==BoardDeviceKind::None||device==BoardDeviceKind::MixedOrUnknown)return false;
    for(std::uint32_t a=static_cast<std::uint32_t>(start)+1;a<end;++a){
        if(HardwareSemantics::deviceFor(static_cast<std::uint16_t>(a),access)!=device)return false;
    }
    return true;
}

std::string indexedIdentity(const char* base,std::uint16_t address,std::uint16_t rangeStart){
    std::ostringstream o;o<<base<<"["<<static_cast<unsigned>(address-rangeStart)<<"]";return o.str();
}

} // namespace

bool HardwareSemantics::isBoardMapped(std::uint16_t a){
    return a>=0x4000&&a<=0x50FF;
}

BoardDeviceKind HardwareSemantics::deviceFor(std::uint16_t a,MemoryAccessKind access){
    const bool read=access==MemoryAccessKind::Read||access==MemoryAccessKind::ReadWrite;
    const bool write=access==MemoryAccessKind::Write||access==MemoryAccessKind::ReadWrite;
    if(a>=0x4000&&a<=0x43FF)return BoardDeviceKind::VideoRam;
    if(a>=0x4400&&a<=0x47FF)return BoardDeviceKind::ColorRam;
    if(a>=0x4800&&a<=0x4BFF)return BoardDeviceKind::OpenBus;
    if(a>=0x4C00&&a<=0x4FEF)return BoardDeviceKind::WorkRam;
    if(a>=0x4FF0&&a<=0x4FFF)return BoardDeviceKind::SpriteRam;
    if(a>=0x5000&&a<=0x5007){if(read&&!write)return BoardDeviceKind::InputIN0;if(write&&!read)return BoardDeviceKind::OutputLatch;return BoardDeviceKind::MixedOrUnknown;}
    if(a>=0x5040&&a<=0x505F){if(read&&!write)return BoardDeviceKind::InputIN1;if(write&&!read)return BoardDeviceKind::NamcoWSG;return BoardDeviceKind::MixedOrUnknown;}
    if(a>=0x5060&&a<=0x506F)return BoardDeviceKind::SpriteCoordinate;
    if(a>=0x5070&&a<=0x507F){if(write&&!read)return BoardDeviceKind::NopWriteRegion;return BoardDeviceKind::MixedOrUnknown;}
    if(a>=0x5080&&a<=0x50BF){if(read&&!write)return BoardDeviceKind::InputDSW1;if(write&&!read)return BoardDeviceKind::NopWriteRegion;return BoardDeviceKind::MixedOrUnknown;}
    if(a>=0x50C0&&a<=0x50FF){if(read&&!write)return BoardDeviceKind::InputDSW2;if(write&&!read)return BoardDeviceKind::Watchdog;return BoardDeviceKind::MixedOrUnknown;}
    return BoardDeviceKind::None;
}

std::string HardwareSemantics::deviceText(BoardDeviceKind k){
    switch(k){
        case BoardDeviceKind::None:return"none";case BoardDeviceKind::VideoRam:return"video-ram";case BoardDeviceKind::ColorRam:return"color-ram";
        case BoardDeviceKind::OpenBus:return"open-bus";case BoardDeviceKind::WorkRam:return"work-ram";case BoardDeviceKind::SpriteRam:return"sprite-ram";
        case BoardDeviceKind::OutputLatch:return"output-latch";case BoardDeviceKind::InputIN0:return"input-IN0";case BoardDeviceKind::NamcoWSG:return"namco-wsg";
        case BoardDeviceKind::InputIN1:return"input-IN1";case BoardDeviceKind::SpriteCoordinate:return"sprite-coordinate";case BoardDeviceKind::NopWriteRegion:return"nop-write-region";
        case BoardDeviceKind::InputDSW1:return"input-DSW1";case BoardDeviceKind::InputDSW2:return"input-DSW2";case BoardDeviceKind::Watchdog:return"watchdog";
        case BoardDeviceKind::MixedOrUnknown:return"mixed-or-unknown";
    }return"unknown";
}
std::string HardwareSemantics::accessText(MemoryAccessKind k){switch(k){case MemoryAccessKind::Read:return"read";case MemoryAccessKind::Write:return"write";case MemoryAccessKind::ReadWrite:return"read/write";case MemoryAccessKind::Unknown:return"unknown";}return"unknown";}
std::string HardwareSemantics::resolutionText(AddressResolutionKind k){switch(k){case AddressResolutionKind::ExactStatic:return"exact-static";case AddressResolutionKind::BoundedStatic:return"bounded-static";case AddressResolutionKind::DynamicObserved:return"dynamic-observed";case AddressResolutionKind::Unresolved:return"unresolved";}return"unresolved";}
std::string HardwareSemantics::effectText(MemoryEffectClass k){switch(k){case MemoryEffectClass::OrdinaryMemory:return"ordinary-memory";case MemoryEffectClass::VolatileRead:return"volatile-read";case MemoryEffectClass::VolatileWrite:return"volatile-write";case MemoryEffectClass::SideEffectingWrite:return"side-effecting-write";case MemoryEffectClass::ExternalInputRead:return"external-input-read";case MemoryEffectClass::OpenBusRead:return"open-bus-read";case MemoryEffectClass::NopDeviceWrite:return"nop-device-write";case MemoryEffectClass::Unknown:return"unknown";}return"unknown";}

HardwareAccessRecord HardwareSemantics::classify(const HardwareAccessInput& in){
    HardwareAccessRecord r;r.pc=in.pc;r.instructionLength=in.instructionLength;r.access=in.access;r.width=in.width?r.width:1;r.addressResolution=in.addressResolution;r.start=in.start;r.end=in.end;r.staticProof=in.staticProof;r.dynamicObserved=in.dynamicObserved;r.addressEntity=in.addressEntity;r.addressDefinitionIds=in.addressDefinitionIds;r.valueDefinitionIds=in.valueDefinitionIds;r.readResultDefinitionIds=in.readResultDefinitionIds;r.provenancePCs=in.provenancePCs;r.rawInstruction=in.rawInstruction;r.note=in.note;
    if(r.end<=r.start&&(r.addressResolution==AddressResolutionKind::ExactStatic||r.addressResolution==AddressResolutionKind::DynamicObserved))r.end=static_cast<std::uint16_t>(static_cast<std::uint32_t>(r.start)+r.width);
    if(r.addressResolution==AddressResolutionKind::Unresolved){r.device=BoardDeviceKind::MixedOrUnknown;r.effect=MemoryEffectClass::Unknown;return r;}
    BoardDeviceKind d=BoardDeviceKind::None;
    if(!sameDeviceSpan(r.start,r.end,r.access,d)){r.device=BoardDeviceKind::MixedOrUnknown;r.effect=MemoryEffectClass::Unknown;r.note+=(r.note.empty()?"":"; ")+std::string("resolved span crosses device identities or lacks a unique access-direction meaning");return r;}
    r.device=d;

    const bool read=r.access==MemoryAccessKind::Read||r.access==MemoryAccessKind::ReadWrite;
    const bool write=r.access==MemoryAccessKind::Write||r.access==MemoryAccessKind::ReadWrite;
    const bool exact=r.addressResolution==AddressResolutionKind::ExactStatic||r.addressResolution==AddressResolutionKind::DynamicObserved;
    const auto a=r.start;

    switch(d){
        case BoardDeviceKind::VideoRam:
            r.readIdentity="video_ram_read";r.writeIdentity="video_ram_write";r.effect=MemoryEffectClass::OrdinaryMemory;
            if(exact)r.intrinsic=read&&!write?"video_ram_read($"+Z80Disassembler::hex16(a).substr(1)+")":write&&!read?"video_ram_write($"+Z80Disassembler::hex16(a).substr(1)+", value)":std::string();
            break;
        case BoardDeviceKind::ColorRam:
            r.readIdentity="color_ram_read";r.writeIdentity="color_ram_write";r.effect=MemoryEffectClass::OrdinaryMemory;
            if(exact)r.intrinsic=read&&!write?"color_ram_read($"+Z80Disassembler::hex16(a).substr(1)+")":write&&!read?"color_ram_write($"+Z80Disassembler::hex16(a).substr(1)+", value)":std::string();
            break;
        case BoardDeviceKind::WorkRam:
            r.readIdentity="work_ram_read";r.writeIdentity="work_ram_write";r.effect=MemoryEffectClass::OrdinaryMemory;
            if(exact)r.intrinsic=read&&!write?"work_ram_read($"+Z80Disassembler::hex16(a).substr(1)+")":write&&!read?"work_ram_write($"+Z80Disassembler::hex16(a).substr(1)+", value)":std::string();
            break;
        case BoardDeviceKind::SpriteRam:
            r.readIdentity="sprite_ram_read";r.writeIdentity="sprite_ram_write";r.effect=MemoryEffectClass::OrdinaryMemory;
            if(exact)r.intrinsic=read&&!write?"sprite_ram_read($"+Z80Disassembler::hex16(a).substr(1)+")":write&&!read?"sprite_ram_write($"+Z80Disassembler::hex16(a).substr(1)+", value)":std::string();
            break;
        case BoardDeviceKind::OpenBus:
            r.readIdentity="open_bus_read";r.writeIdentity="unconnected_write";r.volatileAccess=true;
            if(read&&!write){r.effect=MemoryEffectClass::OpenBusRead;if(exact)r.intrinsic="open_bus_read($"+Z80Disassembler::hex16(a).substr(1)+")";}
            else if(write&&!read){r.effect=MemoryEffectClass::NopDeviceWrite;if(exact)r.intrinsic="unconnected_write($"+Z80Disassembler::hex16(a).substr(1)+", value)";}
            break;
        case BoardDeviceKind::InputIN0:
            r.readIdentity=exact?indexedIdentity("IN0_decode",a,0x5000):"IN0_decode";r.volatileAccess=true;r.effect=MemoryEffectClass::ExternalInputRead;if(exact)r.intrinsic="input_port_read(IN0, "+std::to_string(a-0x5000)+")";break;
        case BoardDeviceKind::OutputLatch:
            r.writeIdentity=exact?latchWriteIdentity(a):"output_latch_write";r.volatileAccess=true;r.sideEffecting=true;r.effect=MemoryEffectClass::SideEffectingWrite;if(exact)r.intrinsic=r.writeIdentity+"(value)";break;
        case BoardDeviceKind::InputIN1:
            r.readIdentity=exact?indexedIdentity("IN1_decode",a,0x5040):"IN1_decode";r.volatileAccess=true;r.effect=MemoryEffectClass::ExternalInputRead;if(exact)r.intrinsic="input_port_read(IN1, "+std::to_string(a-0x5040)+")";break;
        case BoardDeviceKind::NamcoWSG:
            r.writeIdentity=exact?indexedIdentity("sound_register_write",a,0x5040):"sound_register_write";r.volatileAccess=true;r.sideEffecting=true;r.effect=MemoryEffectClass::SideEffectingWrite;if(exact)r.intrinsic="sound_register_write("+std::to_string(a-0x5040)+", value)";break;
        case BoardDeviceKind::SpriteCoordinate:
            r.readIdentity=exact?indexedIdentity("sprite_coordinate_read",a,0x5060):"sprite_coordinate_read";r.writeIdentity=exact?indexedIdentity("sprite_coordinate_write",a,0x5060):"sprite_coordinate_write";r.volatileAccess=true;
            if(write){r.sideEffecting=true;r.effect=MemoryEffectClass::SideEffectingWrite;if(exact&&r.access==MemoryAccessKind::Write)r.intrinsic="sprite_coordinate_write("+std::to_string(a-0x5060)+", value)";}else{r.effect=MemoryEffectClass::VolatileRead;if(exact)r.intrinsic="sprite_coordinate_read("+std::to_string(a-0x5060)+")";}break;
        case BoardDeviceKind::NopWriteRegion:
            r.writeIdentity="nop_device_write";r.volatileAccess=true;r.effect=MemoryEffectClass::NopDeviceWrite;if(exact)r.intrinsic="nop_device_write($"+Z80Disassembler::hex16(a).substr(1)+", value)";break;
        case BoardDeviceKind::InputDSW1:
            r.readIdentity="DSW1_input_decode";r.volatileAccess=true;r.effect=MemoryEffectClass::ExternalInputRead;if(exact)r.intrinsic="input_port_read(DSW1, "+std::to_string(a-0x5080)+")";break;
        case BoardDeviceKind::InputDSW2:
            r.readIdentity="DSW2_input_decode";r.volatileAccess=true;r.effect=MemoryEffectClass::ExternalInputRead;if(exact)r.intrinsic="input_port_read(DSW2, "+std::to_string(a-0x50C0)+")";break;
        case BoardDeviceKind::Watchdog:
            r.writeIdentity="watchdog_write";r.volatileAccess=true;r.sideEffecting=true;r.effect=MemoryEffectClass::SideEffectingWrite;if(exact)r.intrinsic="watchdog_write(value)";break;
        case BoardDeviceKind::None:case BoardDeviceKind::MixedOrUnknown:break;
    }
    if(r.effect==MemoryEffectClass::Unknown){if(read&&!write){r.effect=MemoryEffectClass::VolatileRead;r.volatileAccess=true;}else if(write&&!read){r.effect=MemoryEffectClass::VolatileWrite;r.volatileAccess=true;}}
    return r;
}

HardwareSemanticStats HardwareSemantics::stats(const std::vector<HardwareAccessRecord>& records){
    HardwareSemanticStats s;s.records=records.size();for(const auto& r:records){if(r.addressResolution==AddressResolutionKind::ExactStatic)++s.exactStatic;else if(r.addressResolution==AddressResolutionKind::BoundedStatic)++s.boundedStatic;else if(r.addressResolution==AddressResolutionKind::DynamicObserved&&!r.staticProof)++s.dynamicOnly;if(r.dynamicObserved&&r.staticProof)++s.corroboratedDynamic;if(r.effect==MemoryEffectClass::ExternalInputRead||r.effect==MemoryEffectClass::OpenBusRead||r.effect==MemoryEffectClass::VolatileRead)++s.volatileReads;if(r.sideEffecting)++s.sideEffectingWrites;++s.byDevice[r.device];}return s;
}

ResolvedAddressFact HardwareSemantics::resolveAddressFact(const ReachingDefinitionFact& f,const std::map<std::size_t,ExpressionRecord>& expressions,int displacement){
    ResolvedAddressFact r;if(f.includesEntryValue||f.includesClobberedUnknown||f.definitionIds.empty())return r;
    std::vector<std::uint16_t> values;for(auto id:f.definitionIds){auto it=expressions.find(id);if(it==expressions.end()||!it->second.exact||!it->second.constantKnown)return r;const std::uint16_t v=static_cast<std::uint16_t>(it->second.constantValue+displacement);values.push_back(v);r.definitionIds.insert(id);r.provenancePCs.insert(it->second.provenance.begin(),it->second.provenance.end());r.provenancePCs.insert(it->second.instructionAddress);}if(values.empty())return r;
    const auto mm=std::minmax_element(values.begin(),values.end());r.start=*mm.first;r.end=static_cast<std::uint16_t>(static_cast<std::uint32_t>(*mm.second)+1);r.resolution=values.size()==1?AddressResolutionKind::ExactStatic:AddressResolutionKind::BoundedStatic;return r;
}

} // namespace pacripper
