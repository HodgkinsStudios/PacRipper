// PacRipper hardware-semantics analysis semantic memory cross-reference index
// Created by Jacob Hodgkins

#include "MemoryXrefs.h"

#include <algorithm>
#include <map>

namespace pacripper {

std::vector<MemoryXrefRecord> MemoryXrefs::build(const std::vector<HardwareAccessRecord>& accesses,
                                                 const DefUseResult& defUse,
                                                 const std::map<std::uint16_t,std::set<std::uint16_t>>& functionOwnersByPC,
                                                 const std::vector<RamObjectRecord>& ramObjects){
    std::vector<MemoryXrefRecord> out;
    std::map<std::size_t,std::uint16_t> definitionPC;
    for(const auto& d:defUse.definitions)definitionPC[d.id]=d.instructionAddress;

    std::map<std::size_t,std::set<std::uint16_t>> usesOfDefinition;
    for(const auto& u:defUse.uses)for(auto id:u.reaching.definitionIds)usesOfDefinition[id].insert(u.instructionAddress);

    for(const auto& a:accesses){
        MemoryXrefRecord r;r.id=out.size();r.hardwareAccessId=a.id;r.pc=a.pc;r.access=a.access;r.addressResolution=a.addressResolution;r.start=a.start;r.end=a.end;r.device=a.device;r.staticProof=a.staticProof;r.dynamicObserved=a.dynamicObserved;r.addressDefinitionIds=a.addressDefinitionIds;r.valueDefinitionIds=a.valueDefinitionIds;r.readResultDefinitionIds=a.readResultDefinitionIds;
        auto fo=functionOwnersByPC.find(a.pc);if(fo!=functionOwnersByPC.end())r.functionOwners=fo->second;
        for(auto id:r.valueDefinitionIds){auto it=definitionPC.find(id);if(it!=definitionPC.end())r.valueDefinitionPCs.insert(it->second);}
        for(auto id:r.readResultDefinitionIds){auto it=usesOfDefinition.find(id);if(it!=usesOfDefinition.end())r.downstreamUsePCs.insert(it->second.begin(),it->second.end());}
        if(a.addressResolution==AddressResolutionKind::ExactStatic||a.addressResolution==AddressResolutionKind::DynamicObserved){
            for(const auto& obj:ramObjects)if(a.start<obj.end&&obj.start<a.end)r.ramObjectIds.insert(obj.id);
        }else if(a.addressResolution==AddressResolutionKind::BoundedStatic){
            for(const auto& obj:ramObjects)if(a.start<obj.end&&obj.start<a.end)r.ramObjectIds.insert(obj.id);
        }
        out.push_back(r);
    }
    return out;
}

MemoryXrefStats MemoryXrefs::stats(const std::vector<MemoryXrefRecord>& records){
    MemoryXrefStats s;s.records=records.size();for(const auto& r:records){if(r.addressResolution==AddressResolutionKind::ExactStatic||r.addressResolution==AddressResolutionKind::DynamicObserved)++s.exactAddressRecords;if(r.device==BoardDeviceKind::VideoRam||r.device==BoardDeviceKind::ColorRam||r.device==BoardDeviceKind::WorkRam||r.device==BoardDeviceKind::SpriteRam)++s.ramRecords;else if(r.device!=BoardDeviceKind::None&&r.device!=BoardDeviceKind::MixedOrUnknown)++s.hardwareRecords;s.writeValueLinks+=r.valueDefinitionPCs.size();s.readUseLinks+=r.downstreamUsePCs.size();}return s;
}

std::vector<std::size_t> MemoryXrefs::exactAddressMatches(const std::vector<MemoryXrefRecord>& records,std::uint16_t address,MemoryAccessKind access){
    std::vector<std::size_t> out;for(const auto& r:records){if(!(r.addressResolution==AddressResolutionKind::ExactStatic||r.addressResolution==AddressResolutionKind::DynamicObserved))continue;if(address<r.start||address>=r.end)continue;if(access!=MemoryAccessKind::Unknown&&r.access!=access&&r.access!=MemoryAccessKind::ReadWrite)continue;out.push_back(r.id);}return out;
}

} // namespace pacripper
