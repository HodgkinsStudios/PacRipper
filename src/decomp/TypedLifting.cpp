// PacRipper contract-aware value flow typed expression propagation and safe statement lifting
// Created by Jacob Hodgkins

#include "TypedLifting.h"

#include <algorithm>
#include <map>
#include <sstream>

namespace pacripper {
namespace {

bool isGlobalRole(TypeRoleKind r){return r!=TypeRoleKind::RangeCheckUse;}
bool rolePreservedByArithmetic(TypeRoleKind r){return r==TypeRoleKind::ByteWidth||r==TypeRoleKind::LittleEndianWord||r==TypeRoleKind::Signed8Use||r==TypeRoleKind::Unsigned8Use;}

bool targetMatches(const TypeEvidenceRecord&t,const ExpressionRecord&e){
    if(!t.staticProof||t.dynamicOnly)return false;
    if(t.targetKind==TypeTargetKind::RomObject)return e.romObjectIds.count(t.romObjectId)!=0;
    return e.memoryAddressKnown&&e.memoryAddress>=t.start&&e.memoryAddress<t.end;
}

const DefOperandSpec* nonConstantOperand(const DefinitionRecord&d){for(const auto&o:d.operands)if(!o.constant)return &o;return nullptr;}

bool constantOperandValue(const DefinitionRecord&d,std::uint16_t&v){for(const auto&o:d.operands)if(o.constant){v=o.constantValue;return true;}return false;}

bool oneSourceDef(const DefinitionRecord&d,std::size_t&out){
    const auto*op=nonConstantOperand(d);if(!op)return false;auto i=d.reachingOperands.find(op->entity);if(i==d.reachingOperands.end())return false;const auto&f=i->second;if(!f.exactDefinition())return false;out=*f.definitionIds.begin();return true;
}

} // namespace

std::vector<TypedValueRecord> TypedLifting::propagateTypes(const DefUseResult&defUse,const std::vector<TypeEvidenceRecord>&types,const std::vector<HardwareAccessRecord>&hardware,const std::vector<PointerBoundEvidence>&pointerBounds){
    std::map<std::size_t,const DefinitionRecord*> defs;for(const auto&d:defUse.definitions)defs[d.id]=&d;
    std::map<std::size_t,const ExpressionRecord*> expr;for(const auto&e:defUse.expressions)expr[e.definitionId]=&e;
    std::map<std::size_t,PointerBoundEvidence> bounds;for(const auto&b:pointerBounds)bounds[b.definitionId]=b;
    std::map<std::size_t,TypedValueRecord> records;
    for(const auto&d:defUse.definitions){auto ei=expr.find(d.id);if(ei==expr.end()||!ei->second->exact||!d.semanticExact||d.callBoundaryClobber||d.aliasInvalidation)continue;TypedValueRecord r;r.id=d.id;r.definitionId=d.id;r.pc=d.instructionAddress;r.entity=d.entity;r.bits=d.bits;r.exact=true;r.staticProof=true;r.expression=ei->second->text;r.provenancePCs=ei->second->provenance;for(const auto&t:types)if(isGlobalRole(t.role)&&targetMatches(t,*ei->second))r.roles.insert(t.role);records[d.id]=r;}
    for(const auto&h:hardware)if(h.staticProof&&h.access!=MemoryAccessKind::Write)for(auto did:h.readResultDefinitionIds){auto i=records.find(did);if(i!=records.end()){i->second.roles.insert(TypeRoleKind::HardwareValue);i->second.devices.insert(h.device);i->second.provenancePCs.insert(h.pc);}}

    bool changed=true;std::size_t rounds=0;
    while(changed&&rounds++<=records.size()+1){changed=false;for(auto&kv:records){auto di=defs.find(kv.first);if(di==defs.end())continue;const auto&d=*di->second;std::size_t sid=0;if(!oneSourceDef(d,sid))continue;auto si=records.find(sid);if(si==records.end())continue;const auto beforeRoles=kv.second.roles;const auto beforeDevices=kv.second.devices;const auto op=d.operation;
            if(op==DefExpressionKind::Copy){kv.second.roles.insert(si->second.roles.begin(),si->second.roles.end());kv.second.devices.insert(si->second.devices.begin(),si->second.devices.end());}
            else if(op==DefExpressionKind::HighByte||op==DefExpressionKind::LowByte){kv.second.roles.insert(TypeRoleKind::ByteWidth);kv.second.devices.insert(si->second.devices.begin(),si->second.devices.end());}
            else if(op==DefExpressionKind::Add||op==DefExpressionKind::Subtract||op==DefExpressionKind::Add16||op==DefExpressionKind::Increment||op==DefExpressionKind::Decrement){for(auto role:si->second.roles)if(rolePreservedByArithmetic(role))kv.second.roles.insert(role);kv.second.devices.insert(si->second.devices.begin(),si->second.devices.end());if(si->second.roles.count(TypeRoleKind::Pointer16)){std::uint16_t cv=0;bool hasConst=(op==DefExpressionKind::Increment||op==DefExpressionKind::Decrement)||constantOperandValue(d,cv);auto bi=bounds.find(sid);if(hasConst&&bi!=bounds.end()&&bi->second.baseValueKnown){long delta=0;if(op==DefExpressionKind::Increment)delta=1;else if(op==DefExpressionKind::Decrement)delta=-1;else if(op==DefExpressionKind::Subtract)delta=-static_cast<long>(cv);else delta=static_cast<long>(cv);const long next=static_cast<long>(bi->second.baseValue)+delta;if(next>=static_cast<long>(bi->second.start)&&next<static_cast<long>(bi->second.end)){kv.second.roles.insert(TypeRoleKind::Pointer16);kv.second.pointerOffsetBounded=true;PointerBoundEvidence nb=bi->second;nb.definitionId=d.id;nb.baseValue=static_cast<std::uint16_t>(next);bounds[d.id]=nb;}}}}
            else if(op==DefExpressionKind::BitAnd||op==DefExpressionKind::BitOr||op==DefExpressionKind::BitXor){kv.second.devices.insert(si->second.devices.begin(),si->second.devices.end());if(kv.second.bits==8)kv.second.roles.insert(TypeRoleKind::ByteWidth);}
            if(kv.second.roles!=beforeRoles||kv.second.devices!=beforeDevices)changed=true;
        }}
    std::vector<TypedValueRecord> out;for(auto&kv:records)if(!kv.second.roles.empty()||!kv.second.devices.empty())out.push_back(kv.second);return out;
}

bool TypedLifting::buildIndexedExpression(const IndexedExpressionInput&in,IndexedExpressionRecord&out){
    if(!in.staticProof||!in.finiteBounds||!in.indexExact||in.stride==0||in.elementCount==0||in.fieldWidth==0||in.fieldOffset+in.fieldWidth>in.stride)return false;
    if(!in.indexMinKnown||!in.indexMaxKnown||in.indexMin>in.indexMax||in.indexMax>=in.elementCount)return false;
    if(in.schemaEnd<=in.schemaStart||static_cast<std::size_t>(in.schemaEnd-in.schemaStart)<in.elementCount*in.stride)return false;
    out=IndexedExpressionRecord{};static_cast<IndexedExpressionInput&>(out)=in;std::ostringstream s;s<<"schema_"<<in.schemaId<<"["<<in.indexExpression<<"].field_"<<in.fieldOffset;out.text=s.str();return true;
}

bool TypedLifting::canLiftStatement(const StatementLiftInput&in){return in.staticProof&&in.expressionExact&&in.singleConsumerChain&&!in.crossesVolatileOrSideEffect&&!in.crossesAmbiguousMerge&&!in.crossesUnknownCall&&in.consumedPCs.size()>=2&&!in.destination.empty()&&!in.expression.empty()&&!in.rawFallback.empty();}

LiftedStatementRecord TypedLifting::makeLiftedStatement(std::size_t id,const StatementLiftInput&in){LiftedStatementRecord r;static_cast<StatementLiftInput&>(r)=in;r.id=id;if(canLiftStatement(in))r.text=in.destination+" = "+in.expression+";";return r;}

TypedLiftingStats TypedLifting::stats(const std::vector<TypedValueRecord>&typed,const std::vector<IndexedExpressionRecord>&indexed,const std::vector<LiftedStatementRecord>&lifted){TypedLiftingStats s;s.typedValues=typed.size();s.indexedExpressions=indexed.size();s.liftedStatements=lifted.size();for(const auto&v:typed){if(v.roles.count(TypeRoleKind::Pointer16))++s.pointerValues;if(!v.devices.empty())++s.hardwareProvenanceValues;if(v.pointerOffsetBounded)++s.boundedPointerArithmetic;}for(const auto&l:lifted){s.liftedInstructions+=l.consumedPCs.size();if(!l.flagProducerPCs.empty())++s.flagPreservingLifts;}return s;}

} // namespace pacripper
