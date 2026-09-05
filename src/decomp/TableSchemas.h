#pragma once
// PacRipper type/contract analysis proven table/record schemas
// Created by Jacob Hodgkins

#include "TypeEvidence.h"

#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace pacripper {

enum class SchemaTargetKind { RomObject, RamShape };

struct TableFieldEvidence {
    std::size_t offset=0;
    std::size_t width=1;
    std::size_t repeatedAccessCount=0;
    std::set<TypeRoleKind> roles;
    std::set<std::uint16_t> sourcePCs;
    std::string note;
};

struct TableSchemaEvidence {
    SchemaTargetKind targetKind=SchemaTargetKind::RomObject;
    std::size_t targetId=0;
    std::uint16_t start=0;
    std::uint16_t end=0;
    std::size_t stride=0;
    std::size_t elementCount=0;
    bool exactBounds=false;
    bool staticProof=false;
    std::vector<TableFieldEvidence> fields;
    std::set<std::uint16_t> sourcePCs;
    std::string note;
};

struct TableSchemaRecord : TableSchemaEvidence { std::size_t id=0; };

struct TableSchemaStats {
    std::size_t schemas=0;
    std::size_t romSchemas=0;
    std::size_t ramSchemas=0;
    std::size_t exactSchemas=0;
    std::size_t fields=0;
};

class TableSchemas {
public:
    static std::vector<TableSchemaRecord> reconstruct(const std::vector<TableSchemaEvidence>& evidence);
    static TableSchemaStats stats(const std::vector<TableSchemaRecord>& records);
    static std::string targetKindText(SchemaTargetKind kind);
};

} // namespace pacripper
