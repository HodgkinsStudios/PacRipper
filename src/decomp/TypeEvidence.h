#pragma once
// PacRipper type/contract analysis evidence-backed value/type roles
// Created by Jacob Hodgkins

#include "HardwareSemantics.h"

#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace pacripper {

enum class TypeTargetKind { RamRange, RomObject };
enum class TypeRoleKind {
    ByteWidth,
    LittleEndianWord,
    Signed8Use,
    Unsigned8Use,
    BitFieldUse,
    MaskedUse,
    RangeCheckUse,
    Pointer16,
    HardwareValue
};

struct TypeEvidenceInput {
    TypeTargetKind targetKind=TypeTargetKind::RamRange;
    std::uint16_t start=0;
    std::uint16_t end=0;
    std::size_t romObjectId=0;
    TypeRoleKind role=TypeRoleKind::ByteWidth;
    unsigned bits=0;
    bool staticProof=false;
    bool dynamicOnly=false;
    bool exact=true;
    bool maskKnown=false;
    std::uint16_t mask=0;
    bool postMaskMaxKnown=false;
    std::uint16_t postMaskMax=0;
    bool rangeMinKnown=false;
    std::uint16_t rangeMin=0;
    bool rangeMaxKnown=false;
    std::uint16_t rangeMax=0;
    std::string pathCondition;
    BoardDeviceKind device=BoardDeviceKind::None;
    std::set<std::uint16_t> sourcePCs;
    std::string note;
};

struct TypeEvidenceRecord : TypeEvidenceInput {
    std::size_t id=0;
};

struct TypeEvidenceStats {
    std::size_t records=0;
    std::size_t staticRecords=0;
    std::size_t dynamicOnlyRecords=0;
    std::size_t byteWidth=0;
    std::size_t wordWidth=0;
    std::size_t signedUses=0;
    std::size_t unsignedUses=0;
    std::size_t bitFieldUses=0;
    std::size_t maskedUses=0;
    std::size_t rangeChecks=0;
    std::size_t pointerValues=0;
    std::size_t hardwareValues=0;
    std::size_t ambiguousTargets=0;
};

class TypeEvidence {
public:
    static std::vector<TypeEvidenceRecord> reconstruct(const std::vector<TypeEvidenceInput>& inputs);
    static TypeEvidenceStats stats(const std::vector<TypeEvidenceRecord>& records);
    static std::string targetKindText(TypeTargetKind kind);
    static std::string roleText(TypeRoleKind kind);
    static bool incompatible(TypeRoleKind a,TypeRoleKind b);
};

} // namespace pacripper
