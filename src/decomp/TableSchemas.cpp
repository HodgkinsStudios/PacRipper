// PacRipper type/contract analysis proven table/record schemas
// Created by Jacob Hodgkins

#include "TableSchemas.h"

#include <algorithm>
#include <tuple>

namespace pacripper {

std::string TableSchemas::targetKindText(SchemaTargetKind k){return k==SchemaTargetKind::RomObject?"ROM object":"RAM shape";}

std::vector<TableSchemaRecord> TableSchemas::reconstruct(const std::vector<TableSchemaEvidence>& evidence){
    std::vector<TableSchemaRecord> out;
    for(const auto& e:evidence){
        if(!e.staticProof||e.end<=e.start||e.stride==0||e.elementCount<2)continue;
        if(static_cast<std::size_t>(e.end-e.start)<e.stride*e.elementCount)continue;
        std::vector<TableFieldEvidence> fields;
        for(const auto& f:e.fields){
            if(f.width==0||f.offset+f.width>e.stride||f.repeatedAccessCount<2)continue;
            fields.push_back(f);
        }
        if(fields.empty())continue;
        std::sort(fields.begin(),fields.end(),[](const TableFieldEvidence&a,const TableFieldEvidence&b){return std::tie(a.offset,a.width)<std::tie(b.offset,b.width);});
        bool overlap=false;for(std::size_t i=1;i<fields.size();++i)if(fields[i-1].offset+fields[i-1].width>fields[i].offset)overlap=true;if(overlap)continue;
        TableSchemaRecord r;static_cast<TableSchemaEvidence&>(r)=e;r.fields=std::move(fields);r.id=out.size();out.push_back(r);
    }
    return out;
}

TableSchemaStats TableSchemas::stats(const std::vector<TableSchemaRecord>& records){TableSchemaStats s;s.schemas=records.size();for(const auto&r:records){if(r.targetKind==SchemaTargetKind::RomObject)++s.romSchemas;else ++s.ramSchemas;if(r.exactBounds)++s.exactSchemas;s.fields+=r.fields.size();}return s;}

} // namespace pacripper
