// PacRipper IM2/vector-domain analysis final IM2 vector-latch domain / ROM-tail closure helpers
// Created by Jacob Hodgkins

#include "Im2VectorAnalysis.h"

namespace pacripper {

std::uint16_t Im2VectorAnalysis::vectorWordAddress(std::uint8_t interruptPage,std::uint8_t vectorByte){
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(interruptPage)<<8)|vectorByte);
}

bool Im2VectorAnalysis::vectorWordIntersects(std::uint8_t interruptPage,std::uint8_t vectorByte,
                                          std::uint16_t start,std::uint16_t end){
    if(start>=end)return false;
    const std::uint16_t lo=vectorWordAddress(interruptPage,vectorByte);
    const std::uint16_t hi=static_cast<std::uint16_t>(lo+1u);
    return (lo>=start&&lo<end)||(hi>=start&&hi<end);
}

bool Im2VectorAnalysis::qualifiesFinalUnused(const Im2VectorSystemNegativeRecord& r){
    return r.residualExtentGenericNegativeExhaustive&&r.cpuModeProofAccepted&&
           r.vectorDomainProofAccepted&&r.tailNotSelected;
}

std::string Im2VectorAnalysis::outputKindText(Im2VectorOutputKind kind){
    switch(kind){
        case Im2VectorOutputKind::ImmediatePortA:return "immediate-port-a";
        case Im2VectorOutputKind::RegisterPort:return "register-port";
        case Im2VectorOutputKind::BlockOutput:return "block-output";
    }
    return "unknown";
}

} // namespace pacripper
