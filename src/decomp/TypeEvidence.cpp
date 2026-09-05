// PacRipper type/contract analysis evidence-backed value/type roles
// Created by Jacob Hodgkins

#include "TypeEvidence.h"

#include <algorithm>
#include <map>
#include <tuple>

namespace pacripper {

std::string TypeEvidence::targetKindText(TypeTargetKind k){return k==TypeTargetKind::RamRange?"RAM/memory range":"ROM object";}
std::string TypeEvidence::roleText(TypeRoleKind k){
    switch(k){
        case TypeRoleKind::ByteWidth:return"byte-width";
        case TypeRoleKind::LittleEndianWord:return"little-endian-word";
        case TypeRoleKind::Signed8Use:return"signed-8-use";
        case TypeRoleKind::Unsigned8Use:return"unsigned-8-use";
        case TypeRoleKind::BitFieldUse:return"bit-field-use";
        case TypeRoleKind::MaskedUse:return"masked-use";
        case TypeRoleKind::RangeCheckUse:return"range-check-use";
        case TypeRoleKind::Pointer16:return"pointer-16";
        case TypeRoleKind::HardwareValue:return"hardware-value";
    }
    return"unknown";
}

bool TypeEvidence::incompatible(TypeRoleKind a,TypeRoleKind b){
    if(a==b)return false;
    if((a==TypeRoleKind::Signed8Use&&b==TypeRoleKind::Unsigned8Use)||(a==TypeRoleKind::Unsigned8Use&&b==TypeRoleKind::Signed8Use))return true;
    if((a==TypeRoleKind::ByteWidth&&b==TypeRoleKind::LittleEndianWord)||(a==TypeRoleKind::LittleEndianWord&&b==TypeRoleKind::ByteWidth))return true;
    return false;
}

std::vector<TypeEvidenceRecord> TypeEvidence::reconstruct(const std::vector<TypeEvidenceInput>& inputs){
    struct Key {
        TypeTargetKind targetKind;std::uint16_t start,end;std::size_t objectId;TypeRoleKind role;unsigned bits;bool maskKnown;std::uint16_t mask;bool rangeMinKnown;std::uint16_t rangeMin;bool rangeMaxKnown;std::uint16_t rangeMax;std::string pathCondition;BoardDeviceKind device;bool staticProof;bool dynamicOnly;
        bool operator<(const Key& o)const{return std::tie(targetKind,start,end,objectId,role,bits,maskKnown,mask,rangeMinKnown,rangeMin,rangeMaxKnown,rangeMax,pathCondition,device,staticProof,dynamicOnly)<std::tie(o.targetKind,o.start,o.end,o.objectId,o.role,o.bits,o.maskKnown,o.mask,o.rangeMinKnown,o.rangeMin,o.rangeMaxKnown,o.rangeMax,o.pathCondition,o.device,o.staticProof,o.dynamicOnly);}
    };
    std::map<Key,TypeEvidenceRecord> merged;
    for(const auto& in:inputs){
        if(in.targetKind==TypeTargetKind::RamRange&&in.end<=in.start)continue;
        if(in.dynamicOnly&&in.staticProof)continue;
        Key k{in.targetKind,in.start,in.end,in.romObjectId,in.role,in.bits,in.maskKnown,in.mask,in.rangeMinKnown,in.rangeMin,in.rangeMaxKnown,in.rangeMax,in.pathCondition,in.device,in.staticProof,in.dynamicOnly};
        auto it=merged.find(k);
        if(it==merged.end()){TypeEvidenceRecord r;static_cast<TypeEvidenceInput&>(r)=in;merged.emplace(k,r);}
        else{
            it->second.sourcePCs.insert(in.sourcePCs.begin(),in.sourcePCs.end());
            it->second.exact=it->second.exact&&in.exact;
            if(in.postMaskMaxKnown){if(!it->second.postMaskMaxKnown||in.postMaskMax<it->second.postMaskMax)it->second.postMaskMax=in.postMaskMax;it->second.postMaskMaxKnown=true;}
            if(!in.note.empty()&&it->second.note.find(in.note)==std::string::npos){if(!it->second.note.empty())it->second.note+="; ";it->second.note+=in.note;}
        }
    }
    std::vector<TypeEvidenceRecord> out;out.reserve(merged.size());
    for(auto& kv:merged){kv.second.id=out.size();out.push_back(kv.second);}
    return out;
}

TypeEvidenceStats TypeEvidence::stats(const std::vector<TypeEvidenceRecord>& records){
    TypeEvidenceStats s;s.records=records.size();
    struct TargetKey{TypeTargetKind k;std::uint16_t a,b;std::size_t id;bool operator<(const TargetKey&o)const{return std::tie(k,a,b,id)<std::tie(o.k,o.a,o.b,o.id);}};
    std::map<TargetKey,std::set<TypeRoleKind>> roles;
    for(const auto&r:records){
        if(r.staticProof) ++s.staticRecords;
        if(r.dynamicOnly) ++s.dynamicOnlyRecords;
        switch(r.role){case TypeRoleKind::ByteWidth:++s.byteWidth;break;case TypeRoleKind::LittleEndianWord:++s.wordWidth;break;case TypeRoleKind::Signed8Use:++s.signedUses;break;case TypeRoleKind::Unsigned8Use:++s.unsignedUses;break;case TypeRoleKind::BitFieldUse:++s.bitFieldUses;break;case TypeRoleKind::MaskedUse:++s.maskedUses;break;case TypeRoleKind::RangeCheckUse:++s.rangeChecks;break;case TypeRoleKind::Pointer16:++s.pointerValues;break;case TypeRoleKind::HardwareValue:++s.hardwareValues;break;}
        if(r.staticProof)roles[{r.targetKind,r.start,r.end,r.romObjectId}].insert(r.role);
    }
    for(const auto& kv:roles){bool bad=false;for(auto a:kv.second)for(auto b:kv.second)if(incompatible(a,b))bad=true;if(bad)++s.ambiguousTargets;}
    return s;
}

} // namespace pacripper
