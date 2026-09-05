// Created by Jacob Hodgkins
#include "RomClosure.h"

namespace pacripper {

RomClosurePrimary RomClosure::classify(const RomByteClosureRecord& r) {
    if(r.code && (r.staticExactDataUse || r.dynamicDataUse)) return RomClosurePrimary::CodeAndDataUse;
    if(r.code) return RomClosurePrimary::Code;
    if(r.hardData) return RomClosurePrimary::HardData;
    if(r.staticExactDataUse || r.dynamicDataUse) return RomClosurePrimary::ProvenDataUse;
    if(r.boundedConsumer) return RomClosurePrimary::BoundedConsumer;
    if(r.candidate) return RomClosurePrimary::Candidate;
    if(r.pointerTarget) return RomClosurePrimary::PointerTarget;
    if(r.provenUnused) return RomClosurePrimary::ProvenUnused;
    return RomClosurePrimary::Unresolved;
}

std::string RomClosure::primaryText(RomClosurePrimary kind) {
    switch(kind) {
        case RomClosurePrimary::Code: return "proven code";
        case RomClosurePrimary::CodeAndDataUse: return "proven code + data use";
        case RomClosurePrimary::HardData: return "hard-typed data";
        case RomClosurePrimary::ProvenDataUse: return "proven ROM data use";
        case RomClosurePrimary::BoundedConsumer: return "bounded ROM consumer";
        case RomClosurePrimary::Candidate: return "heuristic data candidate";
        case RomClosurePrimary::PointerTarget: return "ROM pointer target only";
        case RomClosurePrimary::ProvenUnused: return "proven unused ROM";
        case RomClosurePrimary::Unresolved: return "unresolved";
    }
    return "unresolved";
}

std::string RomClosure::consumerKindText(RomConsumerKind kind) {
    switch(kind) {
        case RomConsumerKind::DirectAbsoluteRead: return "direct absolute ROM read";
        case RomConsumerKind::IndirectRegisterRead: return "resolved indirect register ROM read";
        case RomConsumerKind::IndexedRegisterRead: return "resolved indexed-register ROM read";
        case RomConsumerKind::BlockTransferRead: return "bounded block-transfer ROM read";
        case RomConsumerKind::StackRead: return "resolved ROM stack read";
        case RomConsumerKind::Rst10ByteLookup: return "RST $10 byte lookup";
        case RomConsumerKind::Rst18WordLookup: return "RST $18 word lookup";
        case RomConsumerKind::DynamicObservedRead: return "dynamic non-fetch ROM read";
        case RomConsumerKind::CountedSequentialRead: return "counted sequential ROM table read";
        case RomConsumerKind::SentinelSequentialRead: return "sentinel-terminated ROM stream read";
        case RomConsumerKind::EncodedSentinelRead: return "encoded sentinel ROM command stream";
        case RomConsumerKind::InterproceduralRead: return "call-edge propagated ROM read";
        case RomConsumerKind::DelimitedStreamRead: return "RST18-decoded delimited ROM stream";
        case RomConsumerKind::PreservedCalleeRead: return "callee-preserved interprocedural ROM read";
        case RomConsumerKind::RamPointerReloadRead: return "RAM-stored/reloaded ROM pointer read";
        case RomConsumerKind::StackPointerRestoreRead: return "stack-restored ROM pointer read";
    }
    return "ROM consumer";
}

bool RomClosure::boundedLookupRange(std::uint16_t base,std::uint16_t indexLo,std::uint16_t indexHi,
                                    std::uint16_t scale,std::size_t romSize,
                                    std::uint16_t& start,std::uint16_t& end) {
    if(scale==0 || indexLo>indexHi) return false;
    const std::uint32_t lo=static_cast<std::uint32_t>(base)+static_cast<std::uint32_t>(scale)*indexLo;
    const std::uint32_t hi=static_cast<std::uint32_t>(base)+static_cast<std::uint32_t>(scale)*indexHi+scale;
    if(lo>=hi || hi>romSize || hi>0x10000u) return false;
    start=static_cast<std::uint16_t>(lo);
    // A 64 KiB exclusive end cannot be represented by uint16_t. Pac-Man ROM is
    // 16 KiB, so reject that boundary rather than silently wrapping.
    if(hi==0x10000u) return false;
    end=static_cast<std::uint16_t>(hi);
    return true;
}

} // namespace pacripper
