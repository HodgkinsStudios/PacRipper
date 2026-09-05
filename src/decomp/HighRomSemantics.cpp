// PacRipper high-ROM semantic analysis high-ROM decoder grammar and semantic closure
// Created by Jacob Hodgkins

#include "HighRomSemantics.h"

#include <algorithm>
#include <limits>

namespace pacripper {
namespace {
void finalizeParse(StreamParseResult& out){
    if(out.coveredAddresses.empty())return;
    out.start=*out.coveredAddresses.begin();
    const unsigned last=*out.coveredAddresses.rbegin();
    out.end=static_cast<std::uint16_t>(last+1u);
    out.contiguous=true;
    unsigned expected=out.start;
    for(std::uint16_t a:out.coveredAddresses){if(a!=expected){out.contiguous=false;break;}++expected;}
}
const RomDecoderCommandRule* ruleFor(const RomDecoderRecord& decoder,std::uint8_t opcode){
    for(const auto& r:decoder.rules)if(opcode>=r.opcodeLo&&opcode<=r.opcodeHi)return &r;
    return nullptr;
}
}

PointerTableDomainRecord HighRomSemantics::pointerTableDomain(std::uint16_t base,unsigned stride,
                                                               const std::set<std::uint16_t>& indices,
                                                               std::size_t romSize,bool staticProof){
    PointerTableDomainRecord out;out.base=base;out.stride=stride;out.indices=indices;out.staticProof=staticProof;
    if(!staticProof||stride==0||indices.empty())return out;
    for(std::uint16_t index:indices){
        const std::size_t address=static_cast<std::size_t>(base)+static_cast<std::size_t>(index)*stride;
        if(address+stride>romSize){out.entryAddresses.clear();out.staticProof=false;out.note="proven index would exceed ROM bounds";return out;}
        out.entryAddresses.insert(static_cast<std::uint16_t>(address));
    }
    std::uint16_t rangeLo=*indices.begin(),prev=rangeLo;
    for(auto it=std::next(indices.begin());it!=indices.end();++it){
        if(*it!=static_cast<std::uint16_t>(prev+1u)){out.ranges.push_back({rangeLo,prev});rangeLo=*it;}
        prev=*it;
    }
    out.ranges.push_back({rangeLo,prev});
    out.sparse=out.ranges.size()>1;
    out.exact=indices.size()==1;
    out.bounded=indices.size()>1;
    out.note=out.sparse?"sparse statically proven index domain; gaps are intentionally not promoted":"contiguous statically proven index domain";
    return out;
}

StreamParseResult HighRomSemantics::parseDelimited2FNormal(const std::vector<std::uint8_t>& program,
                                                            std::uint16_t start,const RomDecoderRecord& decoder){
    StreamParseResult out;out.start=start;
    if(decoder.grammar!=RomDecoderGrammarKind::Delimited2FNormal||!decoder.staticGrammarProof||!decoder.pointerContinuityProven||decoder.dynamicOnly){out.reason="decoder grammar/pointer continuity is not statically proven";return out;}
    if(decoder.prefixBytes!=2||decoder.delimiter==0||static_cast<std::size_t>(start)+decoder.prefixBytes>=program.size()){out.reason="decoder grammar or stream start is invalid";return out;}
    std::size_t q=static_cast<std::size_t>(start)+decoder.prefixBytes;
    // The consumer has no source-proven 8-bit/256-byte scan cap, so do not
    // invent one here.  ROM bounds are the only safe static guard: if no
    // delimiter is present before the end of the program image, the stream
    // is rejected rather than assigning an arbitrary extent.
    while(q<program.size()&&program[q]!=decoder.delimiter)++q;
    if(q>=program.size()||q+1>=program.size()){out.reason="proven delimiter was not reached before ROM end";return out;}
    const std::size_t preCount=q-(static_cast<std::size_t>(start)+decoder.prefixBytes);
    if(preCount==0){out.reason="normal path requires a non-empty pre-delimiter payload";return out;}
    std::size_t end=q+2;
    if((program[q+1]&0x80u)==0){end=q+1+preCount;if(end>program.size()){out.reason="post-delimiter payload exceeds ROM";return out;}}
    if(end<=start||end>std::numeric_limits<std::uint16_t>::max()){out.reason="invalid stream extent";return out;}
    for(std::size_t a=start;a<end;++a)out.coveredAddresses.insert(static_cast<std::uint16_t>(a));
    out.accepted=true;out.terminated=true;out.reason="decoder-proven $2F delimiter and branch-local payload count prove exact consumed extent";finalizeParse(out);return out;
}

StreamParseResult HighRomSemantics::parseCommandDispatchF0(const std::vector<std::uint8_t>& program,
                                                            std::uint16_t start,const RomDecoderRecord& decoder,
                                                            std::size_t maxSteps){
    StreamParseResult out;out.start=start;
    if(decoder.grammar!=RomDecoderGrammarKind::CommandDispatchF0||!decoder.staticGrammarProof||!decoder.pointerContinuityProven||decoder.dynamicOnly){out.reason="decoder grammar/pointer continuity is not statically proven";return out;}
    if(start>=program.size()||decoder.rules.empty()){out.reason="invalid stream start or empty command grammar";return out;}
    std::size_t p=start;
    std::set<std::size_t> pointerStates;
    for(std::size_t step=0;step<maxSteps;++step){
        if(p>=program.size()){out.reason="stream pointer escaped ROM before a proven termination";return out;}
        if(pointerStates.count(p)){out.accepted=true;out.cyclic=true;out.reason="decoder pointer returned to an already proven stream state";finalizeParse(out);return out;}
        pointerStates.insert(p);
        const std::uint8_t opcode=program[p];out.coveredAddresses.insert(static_cast<std::uint16_t>(p));++p;
        const RomDecoderCommandRule* rule=ruleFor(decoder,opcode);
        if(!rule){out.reason="opcode has no statically proven decoder rule";return out;}
        if(rule->terminates){out.accepted=true;out.terminated=true;out.reason="decoder-proven terminating command reached";finalizeParse(out);return out;}
        if(p+rule->payloadBytes>program.size()){out.reason="command payload exceeds ROM";return out;}
        const std::size_t payloadStart=p;
        for(unsigned i=0;i<rule->payloadBytes;++i)out.coveredAddresses.insert(static_cast<std::uint16_t>(p+i));
        p+=rule->payloadBytes;
        if(rule->littleEndianJump){
            if(rule->payloadBytes!=2){out.reason="jump command does not have a proven 16-bit payload";return out;}
            const std::uint16_t target=static_cast<std::uint16_t>(program[payloadStart]|(static_cast<std::uint16_t>(program[payloadStart+1])<<8));
            if(target>=program.size()){out.reason="jump command target lies outside ROM";return out;}
            p=target;
        }
    }
    out.reason="decoder step guard reached without proven termination or cycle";return out;
}

StreamParseResult HighRomSemantics::parseSignedPairZero(const std::vector<std::uint8_t>& program,
                                                         std::uint16_t start,const RomDecoderRecord& decoder,
                                                         std::size_t maxSteps){
    StreamParseResult out;out.start=start;
    if(decoder.grammar!=RomDecoderGrammarKind::SignedPairZero||!decoder.staticGrammarProof||!decoder.pointerContinuityProven||decoder.dynamicOnly){out.reason="decoder grammar/pointer continuity is not statically proven";return out;}
    if(start>=program.size()||decoder.rules.empty()){out.reason="invalid stream start or empty signed-pair grammar";return out;}
    std::size_t p=start;
    for(std::size_t step=0;step<maxSteps;++step){
        if(p>=program.size()){out.reason="stream pointer escaped ROM before zero terminator";return out;}
        const std::uint8_t opcode=program[p];
        const RomDecoderCommandRule* rule=ruleFor(decoder,opcode);
        if(!rule){out.reason="stream byte has no statically proven signed-pair rule";return out;}
        out.coveredAddresses.insert(static_cast<std::uint16_t>(p));++p;
        if(rule->terminates){out.accepted=true;out.terminated=true;out.reason="decoder-proven zero terminator reached";finalizeParse(out);return out;}
        if(p+rule->payloadBytes>program.size()){out.reason="signed-pair payload exceeds ROM";return out;}
        for(unsigned i=0;i<rule->payloadBytes;++i)out.coveredAddresses.insert(static_cast<std::uint16_t>(p+i));
        p+=rule->payloadBytes;
    }
    out.reason="decoder step guard reached before zero terminator";return out;
}

FixedRecordSemanticRecord HighRomSemantics::fixedRecordFieldUnion(std::uint16_t base,unsigned stride,
                                                                   const std::set<std::uint16_t>& recordIndices,
                                                                   const std::set<unsigned>& fieldOffsets,
                                                                   std::size_t romSize,bool staticProof){
    FixedRecordSemanticRecord out;out.base=base;out.stride=stride;out.recordIndices=recordIndices;out.fieldOffsets=fieldOffsets;out.staticProof=staticProof;
    if(!staticProof||stride==0||recordIndices.empty()||fieldOffsets.empty())return out;
    for(unsigned field:fieldOffsets)if(field>=stride){out.staticProof=false;out.coveredAddresses.clear();out.note="field offset is outside record stride";return out;}
    for(std::uint16_t index:recordIndices)for(unsigned field:fieldOffsets){
        const std::size_t address=static_cast<std::size_t>(base)+static_cast<std::size_t>(index)*stride+field;
        if(address>=romSize){out.staticProof=false;out.coveredAddresses.clear();out.note="record field union exceeds ROM bounds";return out;}
        out.coveredAddresses.insert(static_cast<std::uint16_t>(address));
    }
    out.exact=recordIndices.size()==1;
    out.bounded=recordIndices.size()>1;
    out.note="finite record-index domain + literal stride + statically read field offsets; only the field union is semantic coverage";
    return out;
}

BoundedBlockSemanticRecord HighRomSemantics::boundedBlockWindowUnion(std::uint16_t base,
                                                                           std::uint16_t startOffsetLo,
                                                                           std::uint16_t startOffsetHi,
                                                                           unsigned width,
                                                                           std::size_t romSize,bool staticProof){
    BoundedBlockSemanticRecord out;out.base=base;out.startOffsetLo=startOffsetLo;out.startOffsetHi=startOffsetHi;out.width=width;out.staticProof=staticProof;
    if(!staticProof||width==0||startOffsetHi<startOffsetLo){out.staticProof=false;out.note="invalid or non-static bounded block source proof";return out;}
    const std::size_t first=static_cast<std::size_t>(base)+startOffsetLo;
    const std::size_t lastStart=static_cast<std::size_t>(base)+startOffsetHi;
    if(first>=romSize||lastStart>=romSize||lastStart+width>romSize){out.staticProof=false;out.coveredAddresses.clear();out.note="bounded block source union exceeds ROM bounds";return out;}
    for(std::size_t start=first;start<=lastStart;++start)for(unsigned field=0;field<width;++field)
        out.coveredAddresses.insert(static_cast<std::uint16_t>(start+field));
    out.exact=startOffsetLo==startOffsetHi;out.bounded=!out.exact;
    out.note="finite statically proven source-start offset interval + exact block width; coverage is the union of possible source windows";
    return out;
}

bool HighRomSemantics::applySemanticByte(std::vector<RomByteClosureRecord>& overlay,std::uint16_t address,
                                          bool exact,bool bounded,const std::set<std::uint16_t>& readPCs){
    if(address>=overlay.size()||(!exact&&!bounded))return false;
    RomByteClosureRecord& r=overlay[address];const bool wasUnresolved=r.primary==RomClosurePrimary::Unresolved;
    if(exact)r.staticExactDataUse=true;
    if(bounded)r.boundedConsumer=true;
    r.consumerPCs.insert(readPCs.begin(),readPCs.end());r.primary=RomClosure::classify(r);
    return wasUnresolved&&r.primary!=RomClosurePrimary::Unresolved;
}

std::string HighRomSemantics::decoderKindText(RomDecoderGrammarKind kind){
    switch(kind){case RomDecoderGrammarKind::Delimited2FNormal:return"delimited-$2F-normal";case RomDecoderGrammarKind::CommandDispatchF0:return"command-dispatch-$F0";case RomDecoderGrammarKind::SignedPairZero:return"signed-pair-zero";}return"unknown";
}
std::string HighRomSemantics::auditCategoryText(HighRomAuditCategory kind){
    switch(kind){case HighRomAuditCategory::StreamTargetGap:return"stream-target gap";case HighRomAuditCategory::PointerTableGap:return"pointer-table gap";case HighRomAuditCategory::RecordFieldGap:return"record-field gap";case HighRomAuditCategory::PossibleSharedObjectOverlap:return"possible shared object overlap";case HighRomAuditCategory::DecoderUnreachedPayload:return"decoder-unreached payload";case HighRomAuditCategory::ConstantFillCandidate:return"constant-fill candidate";case HighRomAuditCategory::NoSemanticConsumer:return"no semantic consumer";}return"unknown";
}

} // namespace pacripper
