// PacRipper residual-extent analysis residual extent / exhaustive unused-region proof helpers
// Created by Jacob Hodgkins

#include "ResidualExtentAnalysis.h"

namespace pacripper {

bool ResidualExtentAnalysis::intersects(std::uint16_t a0,std::uint16_t a1,std::uint16_t b0,std::uint16_t b1){
    return a0<a1&&b0<b1&&a0<b1&&b0<a1;
}

bool ResidualExtentAnalysis::addressSetIntersects(const std::set<std::uint16_t>& values,std::uint16_t start,std::uint16_t end){
    const auto it=values.lower_bound(start);
    return it!=values.end()&&*it<end;
}

bool ResidualExtentAnalysis::completeFiniteDomain(const AddressLatticeValue& value,std::set<std::uint16_t>& out){
    return RootContextAnalysis::completeFiniteDomain(value,out,65536);
}

bool ResidualExtentAnalysis::qualifiesUnused(const ResidualExtentNegativeReferenceRecord& r){
    const bool left=r.leftBoundaryProven||r.leftRomBoundary;
    const bool right=r.rightBoundaryProven||r.rightRomBoundary;
    return r.callerInventoryComplete&&r.indirectControlInventoryComplete&&r.allReadAlternativesBounded&&
           r.directReferenceAbsent&&r.finiteIndirectReferenceAbsent&&r.controlReferenceAbsent&&r.systemSemanticAbsent&&
           r.unresolvedReadPCs.empty()&&r.dynamicReadEvents==0&&left&&right&&
           r.exhaustiveModeledStaticAbsence&&!r.incompletePointerDomainPotentialReference&&!r.guardExcluded;
}

std::string ResidualExtentAnalysis::extentKindText(ResidualExtentExtentKind kind){
    switch(kind){
        case ResidualExtentExtentKind::SparsePointerDomain:return "sparse-pointer-domain";
        case ResidualExtentExtentKind::DelimitedStreamDomain:return "delimited-stream-domain";
        case ResidualExtentExtentKind::ExactRecordDomain:return "exact-record-domain";
        case ResidualExtentExtentKind::SentinelStreamDomain:return "sentinel-stream-domain";
        case ResidualExtentExtentKind::CommandStreamGraph:return "command-stream-graph";
        case ResidualExtentExtentKind::SystemTailGuard:return "system-tail-guard";
    }
    return "unknown";
}

} // namespace pacripper
