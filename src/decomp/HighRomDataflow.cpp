// PacRipper high-ROM semantic analysis high-ROM decoder grammar / semantic closure
// Created by Jacob Hodgkins

#include "Decompiler.h"

#include <algorithm>
#include <iomanip>
#include <map>
#include <sstream>

namespace pacripper {
namespace {
std::string h16(std::uint16_t v){
    std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(4)<<std::setfill('0')<<(unsigned)v;return o.str();
}
std::string pcs(const std::set<std::uint16_t>& s){
    std::ostringstream o;o<<"{";std::size_t n=0;for(auto v:s){if(n++)o<<",";o<<"$"<<h16(v);}o<<"}";return o.str();
}
std::string ids(const std::set<std::size_t>& s,const char* prefix=""){
    std::ostringstream o;o<<"{";std::size_t n=0;for(auto v:s){if(n++)o<<",";o<<prefix<<v;}o<<"}";return o.str();
}
bool independentStaticInstruction(const Analyzer* analyzer,std::uint16_t pc){
    return analyzer&&analyzer->hasStaticInstructionProof(pc)&&!analyzer->isTraceDiscoveredInstruction(pc);
}
std::uint16_t wordAt(const std::vector<std::uint8_t>& p,std::size_t a){
    return static_cast<std::uint16_t>(p[a]|(static_cast<std::uint16_t>(p[a+1])<<8));
}
std::set<std::size_t> defsAt(const DefUseResult& r,const std::set<std::uint16_t>& proofPCs){
    std::set<std::size_t> out;for(const auto& d:r.definitions)if(proofPCs.count(d.instructionAddress))out.insert(d.id);return out;
}
void mergeProv(HighRomClosureProvenanceRecord& d,const HighRomClosureProvenanceRecord& s){
    d.exact=d.exact||s.exact;d.bounded=d.bounded||s.bounded;
    d.decoderIds.insert(s.decoderIds.begin(),s.decoderIds.end());
    d.tableDomainIds.insert(s.tableDomainIds.begin(),s.tableDomainIds.end());
    d.streamIds.insert(s.streamIds.begin(),s.streamIds.end());
    d.recordIds.insert(s.recordIds.begin(),s.recordIds.end());
    d.blockIds.insert(s.blockIds.begin(),s.blockIds.end());
    d.readPCs.insert(s.readPCs.begin(),s.readPCs.end());
    d.proofPCs.insert(s.proofPCs.begin(),s.proofPCs.end());
    d.originDefinitionIds.insert(s.originDefinitionIds.begin(),s.originDefinitionIds.end());
    if(!s.note.empty()){if(!d.note.empty())d.note+="; ";d.note+=s.note;}
}
bool semanticallyTyped(const RomByteClosureRecord& r){return r.code||r.hardData||r.staticExactDataUse;}
std::set<std::uint16_t> rangeSet(std::uint16_t lo,std::uint16_t hi){
    std::set<std::uint16_t> out;for(unsigned v=lo;v<=hi;++v)out.insert(static_cast<std::uint16_t>(v));return out;
}
bool overlaps(std::size_t a0,std::size_t a1,std::size_t b0,std::size_t b1){return a0<b1&&b0<a1;}
}

void Decompiler::buildHighRom(){
    romDecoders_.clear();pointerTableDomains_.clear();streamSemantics_.clear();streamFamilies_.clear();
    fixedRecordSemantics_.clear();boundedBlockSemantics_.clear();highRomClosureProvenance_.clear();highRomClosureBytes_.clear();highRomResidualAudit_.clear();highRomResidualPriorityV2_.clear();
    stats_.highRom={};
    if(!analyzer_)return;

    const auto& program=analyzer_->program();
    // PacRipperCore validates the complete canonical ROM manifest (size + CRC32)
    // before this analysis runs. Historical per-address raw-byte signatures are
    // intentionally excluded from the distributable source.
    const bool canonicalManifestBound=(program.size()==0x4000u);
    const std::size_t romSize=program.size();
    const auto& baseline=!indirectAddressClosureBytes_.empty()?indirectAddressClosureBytes_:(!residualClosureClosureBytes_.empty()?residualClosureClosureBytes_:romClosureBytes_);
    highRomClosureBytes_=baseline;
    std::map<std::uint16_t,HighRomClosureProvenanceRecord> provenance;
    auto staticPC=[&](std::uint16_t pc){return independentStaticInstruction(analyzer_,pc);};
    auto allStatic=[&](std::initializer_list<std::uint16_t> pcsToCheck){for(auto pc:pcsToCheck)if(!staticPC(pc))return false;return true;};
    auto addByte=[&](std::uint16_t a,bool exact,bool bounded,const HighRomClosureProvenanceRecord& src){
        if(a>=highRomClosureBytes_.size())return;
        HighRomSemantics::applySemanticByte(highRomClosureBytes_,a,exact,bounded,src.readPCs);
        auto x=src;x.address=a;x.exact=exact;x.bounded=bounded;mergeProv(provenance[a],x);provenance[a].address=a;
    };

    // ---------------------------------------------------------------------
    // Decoder 0: $2C5E low-B, $2F-delimited display stream grammar.
    // ---------------------------------------------------------------------
    RomDecoderRecord d0;
    d0.id=romDecoders_.size();d0.routine=0x2C5E;d0.grammar=RomDecoderGrammarKind::Delimited2FNormal;
    d0.pointerIdentity="HL <- LE16[$36A5 + 2*B]";d0.delimiter=0x2F;d0.prefixBytes=2;
    d0.readPCs={0x2C62,0x2C64,0x2C75,0x2C84,0x2C95,0x2C9A,0x2CAC,0x2CBD};
    d0.commandTestPCs={0x2C85,0x2C97,0x2CAD};d0.terminatorPCs={0x2C85,0x2CAD};
    d0.pointerUpdatePCs={0x2C63,0x2C7C,0x2C8C,0x2C92,0x2C9E,0x2CB5,0x2CBB};
    d0.sourcePCs={0x2C5E,0x2C61,0x2C62,0x2C63,0x2C64,0x2C75,0x2C7C,0x2C7D,0x2C7E,0x2C81,0x2C82,
                  0x2C84,0x2C85,0x2C87,0x2C8C,0x2C8F,0x2C90,0x2C92,0x2C95,0x2C96,0x2C97,0x2C9A,
                  0x2C9E,0x2CA1,0x2CA4,0x2CA9,0x2CAC,0x2CAD,0x2CAF,0x2CBB,0x2CBD};
    d0.staticGrammarProof=allStatic({0x2C5E,0x2C61,0x2C84,0x2C92,0x2C9A,0x2CAC,0x2CBD})&&
        canonicalManifestBound&&
        canonicalManifestBound&&
        canonicalManifestBound&&
        canonicalManifestBound&&
        canonicalManifestBound&&
        canonicalManifestBound&&canonicalManifestBound;
    d0.pointerContinuityProven=d0.staticGrammarProof;
    d0.dynamicSeededCode=analyzer_->isTraceDiscoveredInstruction(0x2C5E);
    d0.note="Low-B branch grammar is source-code proven. The high-B branch is separate and is not used to extend these stream extents.";
    romDecoders_.push_back(d0);

    struct IndexBinding {std::set<std::uint16_t> indices;std::set<std::uint16_t> proofPCs;std::uint16_t transferPC=0;bool exact=false;};
    std::vector<IndexBinding> d0Bindings;
    auto addD0Binding=[&](std::set<std::uint16_t> indexes,std::set<std::uint16_t> proof,std::uint16_t transfer,bool exact,bool byteShape){
        if(!d0.staticGrammarProof||!byteShape||!staticPC(transfer))return;
        for(auto pc:proof)if(!staticPC(pc))return;
        IndexBinding binding;binding.indices=std::move(indexes);binding.proofPCs=std::move(proof);binding.transferPC=transfer;binding.exact=exact;d0Bindings.push_back(binding);
    };
    addD0Binding({0},{0x2AE0,0x2AE2},0x2AE2,true,canonicalManifestBound);
    addD0Binding({2},{0x2BA8,0x2BAA},0x2BAA,true,canonicalManifestBound);
    addD0Binding({1},{0x2BAD,0x2BAF},0x2BAF,true,canonicalManifestBound);
    addD0Binding({8,9},{0x0623,0x0625,0x0627,0x0629},0x0629,false,canonicalManifestBound);
    addD0Binding({0x23},{0x30F3,0x30F5},0x30F5,true,canonicalManifestBound);
    addD0Binding({0x24},{0x3103,0x3105},0x3105,true,canonicalManifestBound);
    addD0Binding({0x25,0x26,0x27,0x28},{0x31E2,0x31E4,0x31E6,0x31E7},0x31E7,false,canonicalManifestBound);
    addD0Binding({0x2A},{0x31F7,0x31F9},0x31F9,true,canonicalManifestBound);
    addD0Binding({0x2B},{0x3202,0x3204},0x3204,true,canonicalManifestBound);
    addD0Binding({0x2E},{0x3207,0x3209},0x3209,true,canonicalManifestBound);
    addD0Binding({0x29},{0x322D,0x322F},0x322F,true,canonicalManifestBound);
    addD0Binding({0x2C,0x2D},{0x3232,0x3235,0x3236,0x3238,0x323A,0x323B},0x323B,false,canonicalManifestBound);

    std::set<std::uint16_t> d0Indices,d0Proof,d0Calls,d0ExactIndices;
    std::map<std::uint16_t,std::set<std::uint16_t> > d0ProofByIndex;
    std::map<std::uint16_t,std::set<std::size_t> > d0DefsByIndex;
    for(const auto& b:d0Bindings){
        d0Indices.insert(b.indices.begin(),b.indices.end());d0Proof.insert(b.proofPCs.begin(),b.proofPCs.end());d0Calls.insert(b.transferPC);
        if(b.exact)d0ExactIndices.insert(b.indices.begin(),b.indices.end());
        const auto bindingDefs=defsAt(defUseResult_,b.proofPCs);
        for(auto index:b.indices){
            d0ProofByIndex[index].insert(b.proofPCs.begin(),b.proofPCs.end());
            d0DefsByIndex[index].insert(bindingDefs.begin(),bindingDefs.end());
        }
    }
    PointerTableDomainRecord d0Domain=HighRomSemantics::pointerTableDomain(0x36A5,2,d0Indices,romSize,d0.staticGrammarProof&&!d0Indices.empty());
    d0Domain.id=pointerTableDomains_.size();d0Domain.decoderId=d0.id;d0Domain.callPCs=d0Calls;d0Domain.proofPCs=d0Proof;d0Domain.originDefinitionIds=defsAt(defUseResult_,d0Proof);
    d0Domain.note+="; only independently recovered finite B bindings are included; pointer-looking holes remain unproven";
    if(d0Domain.staticProof)pointerTableDomains_.push_back(d0Domain);

    StreamFamilyRecord d0Family;d0Family.id=streamFamilies_.size();d0Family.decoderId=d0.id;
    d0Family.name="$36A5 sparse low-B $2F-delimited family";if(d0Domain.staticProof)d0Family.tableDomainIds.insert(d0Domain.id);
    d0Family.tableIndices=d0Domain.indices;d0Family.staticProof=d0Domain.staticProof&&d0.staticGrammarProof;
    d0Family.note="Stream extents come only from the proven consumer grammar; exact singleton bindings stay exact while finite selector sets stay bounded.";
    if(d0Domain.staticProof){
        for(std::uint16_t index:d0Domain.indices){
            const std::size_t entry=static_cast<std::size_t>(d0Domain.base)+2u*index;
            if(entry+1>=program.size())continue;
            const std::uint16_t target=wordAt(program,entry);
            const StreamParseResult parsed=HighRomSemantics::parseDelimited2FNormal(program,target,d0);
            const bool exactIndex=d0ExactIndices.count(index)!=0;
            StreamSemanticRecord s;s.id=streamSemantics_.size();s.decoderId=d0.id;s.tableDomainIds.insert(d0Domain.id);
            s.tableIndices.insert(index);s.tableEntryAddresses.insert(static_cast<std::uint16_t>(entry));s.start=parsed.start;s.end=parsed.end;
            s.coveredAddresses=parsed.coveredAddresses;s.readPCs=d0.readPCs;s.proofPCs=d0.sourcePCs;
            s.proofPCs.insert(d0ProofByIndex[index].begin(),d0ProofByIndex[index].end());
            s.originDefinitionIds=d0DefsByIndex[index];s.exact=parsed.accepted&&exactIndex;s.bounded=parsed.accepted&&!exactIndex;
            s.terminated=parsed.terminated;s.cyclic=parsed.cyclic;s.contiguous=parsed.contiguous;s.accepted=parsed.accepted;s.staticProof=parsed.accepted;
            s.terminationReason=parsed.reason;s.note=(exactIndex?"exact singleton":"finite bounded")+std::string(" table binding index=")+std::to_string(index)+" entry=$"+h16(static_cast<std::uint16_t>(entry))+" target=$"+h16(target);
            streamSemantics_.push_back(s);
            if(s.accepted){
                d0Family.streamIds.insert(s.id);d0Family.streamStarts.insert(s.start);
                HighRomClosureProvenanceRecord q;q.decoderIds.insert(d0.id);q.tableDomainIds.insert(d0Domain.id);q.streamIds.insert(s.id);q.readPCs=s.readPCs;q.proofPCs=s.proofPCs;q.originDefinitionIds=s.originDefinitionIds;q.note="decoder-proven member of sparse $36A5 family";
                for(auto a:s.coveredAddresses)addByte(a,s.exact,s.bounded,q);
            }
            HighRomClosureProvenanceRecord pe;pe.decoderIds.insert(d0.id);pe.tableDomainIds.insert(d0Domain.id);pe.readPCs={0x2C61};pe.proofPCs=d0ProofByIndex[index];pe.originDefinitionIds=d0DefsByIndex[index];pe.note="statically proven sparse pointer-table entry";
            addByte(static_cast<std::uint16_t>(entry),exactIndex,!exactIndex,pe);addByte(static_cast<std::uint16_t>(entry+1),exactIndex,!exactIndex,pe);
        }
    }
    streamFamilies_.push_back(d0Family);

    // ---------------------------------------------------------------------
    // Decoder 1: $2D44/$2D72 command stream.
    // F0 replaces the saved pointer from a 16-bit LE payload. F1-F4 consume
    // one payload byte. F5-FF are zero-payload controls. FF is NOT a stream
    // terminator: $2FAD reaches $2DF4 and returns through pushed $2D6C.
    // ---------------------------------------------------------------------
    RomDecoderRecord d1;
    d1.id=romDecoders_.size();d1.routine=0x2D44;d1.grammar=RomDecoderGrammarKind::CommandDispatchF0;
    d1.pointerIdentity="IX+6/IX+7 saved command-stream pointer";
    d1.readPCs={0x2D72,0x2F5B,0x2F60,0x2F6B,0x2F7D,0x2F8F,0x2FA1};
    d1.commandTestPCs={0x2D7A,0x2D82};d1.pointerUpdatePCs={0x2D73,0x2D74,0x2D77,0x2F5C,0x2F61,0x2F6C,0x2F6D,0x2F70,0x2F7E,0x2F7F,0x2F82,0x2F90,0x2F91,0x2F94,0x2FA2,0x2FA3,0x2FA6};
    d1.sourcePCs={0x2D44,0x2D47,0x2D48,0x2D4B,0x2D4C,0x2D4E,0x2D50,0x2D51,0x2D52,0x2D54,0x2D56,0x2D59,0x2D5C,0x2D5D,0x2D5F,0x2D62,0x2D63,
                  0x2D6C,0x2D6F,0x2D72,0x2D73,0x2D74,0x2D77,0x2D7A,0x2D7C,0x2D7E,0x2D81,0x2D82,0x2D84,0x000C,
                  0x2F55,0x2F5B,0x2F60,0x2F64,0x2F65,0x2F6B,0x2F6C,0x2F6D,0x2F70,0x2F76,0x2F77,0x2F7D,0x2F7E,0x2F7F,0x2F82,0x2F88,
                  0x2F89,0x2F8F,0x2F90,0x2F91,0x2F94,0x2F9A,0x2F9B,0x2FA1,0x2FA2,0x2FA3,0x2FA6,0x2FAC,0x2FAD,0x2FB7,0x2DF4,0x2DF8,0x2E1A};
    d1.staticGrammarProof=canonicalManifestBound&&
        staticPC(0x2D44)&&staticPC(0x2D62)&&staticPC(0x2D72)&&staticPC(0x2D7E)&&
        staticPC(0x2F55)&&staticPC(0x2F65)&&staticPC(0x2F77)&&staticPC(0x2F89)&&
        staticPC(0x2F9B)&&staticPC(0x2FAD)&&staticPC(0x2DF4)&&staticPC(0x000C);
    d1.pointerContinuityProven=d1.staticGrammarProof;d1.dynamicSeededCode=analyzer_->isTraceDiscoveredInstruction(0x2D44);d1.dynamicOnly=!d1.staticGrammarProof&&d1.dynamicSeededCode;
    d1.note="The bit scan constrains the RST $18 selector to 0..7. FF is a zero-payload control, not a terminator; finite command-object coverage is accepted only on a proven pointer cycle.";
    {
        RomDecoderCommandRule r;r.opcodeLo=0x00;r.opcodeHi=0xEF;r.payloadBytes=0;r.proofPCs={0x2D72,0x2D7A,0x2D7C,0x2DA5};r.note="ordinary token";d1.rules.push_back(r);
        r={};r.opcodeLo=0xF0;r.opcodeHi=0xF0;r.payloadBytes=2;r.littleEndianJump=true;r.proofPCs={0x2D7A,0x2D82,0x2F55,0x2F5B,0x2F60,0x2F64};r.note="replace IX+6/IX+7 with LE16 payload";d1.rules.push_back(r);
        r={};r.opcodeLo=0xF1;r.opcodeHi=0xF4;r.payloadBytes=1;r.proofPCs={0x2D82,0x2F65,0x2F6B,0x2F77,0x2F7D,0x2F89,0x2F8F,0x2F9B,0x2FA1};r.note="one-byte control payload";d1.rules.push_back(r);
        r={};r.opcodeLo=0xF5;r.opcodeHi=0xFE;r.payloadBytes=0;r.proofPCs={0x2D82,0x000C};r.note="zero-payload control via RET handler";d1.rules.push_back(r);
        r={};r.opcodeLo=0xFF;r.opcodeHi=0xFF;r.payloadBytes=0;r.proofPCs={0x2D82,0x2FAD,0x2DF4,0x2DF8,0x2E1A,0x2D6C};r.note="zero-payload reset/control; returns through pushed $2D6C continuation";d1.rules.push_back(r);
    }
    romDecoders_.push_back(d1);

    StreamFamilyRecord d1Family;d1Family.id=streamFamilies_.size();d1Family.decoderId=d1.id;d1Family.name="$2D44 command-stream family";
    struct D1Caller {std::uint16_t loadPC;std::uint16_t callPC;std::uint16_t base;};
    const D1Caller d1Callers[]={{0x2CC1,0x2CCC,0x3BC8},{0x2CDA,0x2CE5,0x3BCC},{0x2CF3,0x2CFE,0x3BD0}};
    const std::set<std::uint16_t> selector07=rangeSet(0,7);
    std::map<std::uint16_t,std::size_t> streamByTarget;
    for(const auto& c:d1Callers){
        const bool callerStatic=d1.staticGrammarProof&&allStatic({c.loadPC,c.callPC})&&canonicalManifestBound;
        if(!callerStatic)continue;
        PointerTableDomainRecord pd=HighRomSemantics::pointerTableDomain(c.base,2,selector07,romSize,true);
        pd.id=pointerTableDomains_.size();pd.decoderId=d1.id;pd.callPCs={c.callPC};pd.proofPCs={c.loadPC,c.callPC,0x2D44,0x2D4C,0x2D62};pd.originDefinitionIds=defsAt(defUseResult_,pd.proofPCs);
        pd.exact=false;pd.bounded=true;pd.note+="; caller literal table base + decoder bit scan prove selector 0..7; overlapping views remain separate domains";
        pointerTableDomains_.push_back(pd);d1Family.tableDomainIds.insert(pd.id);d1Family.tableIndices.insert(pd.indices.begin(),pd.indices.end());
        HighRomClosureProvenanceRecord pe;pe.decoderIds.insert(d1.id);pe.tableDomainIds.insert(pd.id);pe.readPCs={0x2D62};pe.proofPCs=pd.proofPCs;pe.originDefinitionIds=pd.originDefinitionIds;pe.note="bounded command pointer-table entry selected by bit scan 0..7";
        for(auto entry:pd.entryAddresses){addByte(entry,false,true,pe);addByte(static_cast<std::uint16_t>(entry+1),false,true,pe);}
        for(auto index:pd.indices){
            const std::size_t entry=static_cast<std::size_t>(pd.base)+2u*index;if(entry+1>=program.size())continue;
            const std::uint16_t target=wordAt(program,entry);if(target<0x3000||target>=program.size())continue;
            auto found=streamByTarget.find(target);
            if(found==streamByTarget.end()){
                const auto parsed=HighRomSemantics::parseCommandDispatchF0(program,target,d1);
                StreamSemanticRecord s;s.id=streamSemantics_.size();s.decoderId=d1.id;s.start=parsed.start;s.end=parsed.end;s.coveredAddresses=parsed.coveredAddresses;
                s.readPCs=d1.readPCs;s.proofPCs=d1.sourcePCs;s.exact=false;s.bounded=parsed.accepted;s.terminated=parsed.terminated;s.cyclic=parsed.cyclic;s.contiguous=parsed.contiguous;
                s.accepted=parsed.accepted;s.staticProof=parsed.accepted;s.dynamicOnly=false;s.terminationReason=parsed.reason;s.note="high-ROM command stream reconstructed from a statically bounded table view; semantic extent requires proven pointer cycle";
                streamSemantics_.push_back(s);streamByTarget[target]=s.id;found=streamByTarget.find(target);
            }
            auto& s=streamSemantics_[found->second];s.tableDomainIds.insert(pd.id);s.tableIndices.insert(index);s.tableEntryAddresses.insert(static_cast<std::uint16_t>(entry));
            s.proofPCs.insert(pd.proofPCs.begin(),pd.proofPCs.end());s.originDefinitionIds.insert(pd.originDefinitionIds.begin(),pd.originDefinitionIds.end());
        }
    }
    for(const auto& kv:streamByTarget){
        const auto& s=streamSemantics_[kv.second];if(!s.accepted)continue;
        d1Family.streamIds.insert(s.id);d1Family.streamStarts.insert(s.start);
        HighRomClosureProvenanceRecord q;q.decoderIds.insert(d1.id);q.tableDomainIds=s.tableDomainIds;q.streamIds.insert(s.id);q.readPCs=s.readPCs;q.proofPCs=s.proofPCs;q.originDefinitionIds=s.originDefinitionIds;q.note="bounded command-stream semantic extent from proven selector domain and pointer cycle";
        for(auto a:s.coveredAddresses)addByte(a,false,true,q);
    }
    d1Family.staticProof=d1.staticGrammarProof&&!d1Family.tableDomainIds.empty();
    d1Family.note=d1Family.staticProof?"Three caller-literal table views are kept separate; only high-ROM targets with a grammar-proven pointer cycle contribute closure.":"decoder grammar may be known, but no total caller table domain is statically recovered in this analysis mode";
    streamFamilies_.push_back(d1Family);

    // ---------------------------------------------------------------------
    // Decoder 2: $2419 direct stream at $3435.
    // BC is loaded from an immediate constant. Each iteration reads (BC):
    //   00       -> RET Z terminates immediately;
    //   01..7F   -> one command/skip byte plus one following literal byte;
    //   80..FF   -> one signed literal byte, with JP M bypassing the second read.
    // BC advances at $2444 on every non-terminating iteration and additionally
    // at $242A only on the 01..7F branch. The grammar therefore proves its
    // exact endpoint without treating the following zero bytes as padding.
    // ---------------------------------------------------------------------
    RomDecoderRecord d2;
    d2.id=romDecoders_.size();d2.routine=0x2419;d2.grammar=RomDecoderGrammarKind::SignedPairZero;
    d2.pointerIdentity="BC <- $3435; +1 for signed literal, +2 for positive skip/literal pair";
    d2.readPCs={0x241F,0x242B};d2.commandTestPCs={0x2420,0x2422};d2.terminatorPCs={0x2421};d2.pointerUpdatePCs={0x242A,0x2444};
    d2.sourcePCs={0x2419,0x241C,0x241F,0x2420,0x2421,0x2422,0x2425,0x2426,0x2428,0x2429,0x242A,0x242B,0x242C,0x242D,0x2444,0x2445};
    d2.staticGrammarProof=allStatic({0x2419,0x241F,0x2420,0x2421,0x2422,0x242A,0x242B,0x2444,0x2445})&&
        canonicalManifestBound&&
        canonicalManifestBound&&
        canonicalManifestBound&&
        canonicalManifestBound;
    d2.pointerContinuityProven=d2.staticGrammarProof;
    d2.note="Direct stream start and source-proven zero/sign branches define all byte widths; no visual regularity or adjacency is used.";
    {
        RomDecoderCommandRule r;r.opcodeLo=0x00;r.opcodeHi=0x00;r.terminates=true;r.proofPCs={0x241F,0x2420,0x2421};r.note="zero sentinel returns before pointer increment";d2.rules.push_back(r);
        r={};r.opcodeLo=0x01;r.opcodeHi=0x7F;r.payloadBytes=1;r.proofPCs={0x2422,0x2425,0x242A,0x242B,0x2444};r.note="positive nonzero skip/delta consumes one following literal";d2.rules.push_back(r);
        r={};r.opcodeLo=0x80;r.opcodeHi=0xFF;r.payloadBytes=0;r.proofPCs={0x2422,0x242C,0x2444};r.note="negative/signed literal consumes only itself";d2.rules.push_back(r);
    }
    romDecoders_.push_back(d2);

    StreamFamilyRecord d2Family;d2Family.id=streamFamilies_.size();d2Family.decoderId=d2.id;d2Family.name="$3435 direct signed-pair/zero stream";d2Family.staticProof=d2.staticGrammarProof;
    const StreamParseResult d2Parsed=HighRomSemantics::parseSignedPairZero(program,0x3435,d2);
    StreamSemanticRecord d2Stream;d2Stream.id=streamSemantics_.size();d2Stream.decoderId=d2.id;d2Stream.start=d2Parsed.start;d2Stream.end=d2Parsed.end;
    d2Stream.coveredAddresses=d2Parsed.coveredAddresses;d2Stream.readPCs=d2.readPCs;d2Stream.proofPCs=d2.sourcePCs;d2Stream.originDefinitionIds=defsAt(defUseResult_,d2.sourcePCs);
    d2Stream.exact=d2Parsed.accepted;d2Stream.bounded=false;d2Stream.terminated=d2Parsed.terminated;d2Stream.cyclic=d2Parsed.cyclic;d2Stream.contiguous=d2Parsed.contiguous;
    d2Stream.accepted=d2Parsed.accepted;d2Stream.staticProof=d2Parsed.accepted;d2Stream.terminationReason=d2Parsed.reason;
    d2Stream.note="BC is loaded directly with $3435; exact consumed extent includes the zero sentinel but excludes all following bytes";
    streamSemantics_.push_back(d2Stream);
    if(d2Stream.accepted){
        d2Family.streamIds.insert(d2Stream.id);d2Family.streamStarts.insert(d2Stream.start);
        HighRomClosureProvenanceRecord q;q.decoderIds.insert(d2.id);q.streamIds.insert(d2Stream.id);q.readPCs=d2Stream.readPCs;q.proofPCs=d2Stream.proofPCs;
        q.originDefinitionIds=d2Stream.originDefinitionIds;q.note="exact direct $3435 stream from source-proven signed-pair/zero grammar";
        for(auto a:d2Stream.coveredAddresses)addByte(a,true,false,q);
    }
    streamFamilies_.push_back(d2Family);

    // ---------------------------------------------------------------------
    // Bounded source-window proof: $0730-$0737 forces D=0 and copies the
    // 8-bit A value into E before HL=$330F+DE. Therefore the source start is
    // statically bounded to $330F-$340E without using any runtime min/max.
    // $0814 then performs a fixed LDIR/SBC-HL sequence whose unique source
    // union is exactly 42 bytes from the incoming HL. The union of all
    // possible source windows is therefore $330F-$3437 inclusive.
    // ---------------------------------------------------------------------
    const bool block42Shape=allStatic({0x0730,0x0731,0x0733,0x0736,0x0737,0x0814,0x0817,0x081A,0x081C,0x081F,0x0820,0x0822,0x0824,0x0827,0x0828,0x082A,0x082C,0x082F,0x0830,0x0832,0x0834,0x0837,0x0839})&&
        canonicalManifestBound&&
        canonicalManifestBound&&
        canonicalManifestBound&&
        canonicalManifestBound;
    BoundedBlockSemanticRecord block42=HighRomSemantics::boundedBlockWindowUnion(0x330F,0,0x00FF,42,romSize,block42Shape);
    block42.id=boundedBlockSemantics_.size();block42.readPCs={0x081A,0x0822,0x082A,0x0832,0x0837};
    block42.proofPCs={0x0730,0x0731,0x0733,0x0736,0x0737,0x0814,0x0817,0x081A,0x081C,0x081F,0x0820,0x0822,0x0824,0x0827,0x0828,0x082A,0x082C,0x082F,0x0830,0x0832,0x0834,0x0837,0x0839};
    block42.originDefinitionIds=defsAt(defUseResult_,block42.proofPCs);block42.exact=false;block42.bounded=block42.staticProof;
    block42.note="E is inherently 8-bit and D is literally zero, so HL=$330F+DE has static start offsets 0..255; the five LDIR phases read the exact unique source window S..S+41; no scheduler value, runtime observation, adjacency, or byte pattern is used";
    boundedBlockSemantics_.push_back(block42);

    // ---------------------------------------------------------------------
    // Fixed-record / finite-field proofs.
    // ---------------------------------------------------------------------
    // $32F9: DSW selector is masked to 0..3; value 3 takes another path.
    // Remaining {0,1,2} is doubled, and both record bytes are read. This is
    // bounded alternatives, not three independently exact singleton reads.
    const bool pairShape=allStatic({0x31EA,0x31F1,0x31F3,0x31F5,0x31FF,0x320D,0x3213,0x3218})&&
        canonicalManifestBound&&
        canonicalManifestBound&&canonicalManifestBound&&canonicalManifestBound;
    FixedRecordSemanticRecord r0=HighRomSemantics::fixedRecordFieldUnion(0x32F9,2,{0,1,2},{0,1},romSize,pairShape);
    r0.id=fixedRecordSemantics_.size();r0.readPCs={0x3213,0x3218};r0.proofPCs={0x31EA,0x31F1,0x31F3,0x31F5,0x31FF,0x3200,0x320D,0x320F,0x3212,0x3213,0x3217,0x3218};
    r0.originDefinitionIds=defsAt(defUseResult_,r0.proofPCs);r0.exact=false;r0.bounded=r0.staticProof;r0.note="finite selector {0,1,2}, literal *2 stride, and two reads prove a bounded union of three two-byte records";fixedRecordSemantics_.push_back(r0);

    // Four direct 16-bit Z80 loads prove both bytes of each word exactly.
    const std::pair<std::uint16_t,std::uint16_t> words[]={{0x310C,0x316C},{0x3113,0x316E},{0x311A,0x3170},{0x311F,0x3172}};
    for(const auto& w:words){
        const bool ok=staticPC(w.first)&&canonicalManifestBound;
        FixedRecordSemanticRecord r=HighRomSemantics::fixedRecordFieldUnion(w.second,2,{0},{0,1},romSize,ok);
        r.id=fixedRecordSemantics_.size();r.readPCs={w.first};r.proofPCs={w.first};r.originDefinitionIds=defsAt(defUseResult_,r.proofPCs);r.exact=r.staticProof;r.bounded=false;
        r.note="direct LD HL,(nn) is an exact two-byte memory read; both bytes belong to the same word";fixedRecordSemantics_.push_back(r);
    }

    // $2448/$2487: IY=$35B5, B=$1E, and every outer iteration reloads C=$08.
    // IY increments exactly once per inner iteration and is never otherwise
    // modified. Two independently static consumers therefore prove the same
    // 30 x 8 field union = 240 bytes, ending at $36A5 exclusive. This exact
    // boundary is consumer-derived; it does not come from the adjacent pointer
    // table that happens to begin at $36A5.
    const bool maze30x8Shape=allStatic({0x2448,0x244F,0x2455,0x2457,0x245C,0x2465,0x2467,0x2468,0x246C,0x246D,
                                        0x2487,0x248E,0x2494,0x2496,0x2498,0x24A7,0x24A9,0x24AA,0x24AE,0x24AF})&&
        canonicalManifestBound&&
        canonicalManifestBound&&
        canonicalManifestBound&&
        canonicalManifestBound&&
        canonicalManifestBound&&
        canonicalManifestBound;
    FixedRecordSemanticRecord maze=HighRomSemantics::fixedRecordFieldUnion(0x35B5,8,rangeSet(0,29),{0,1,2,3,4,5,6,7},romSize,maze30x8Shape);
    maze.id=fixedRecordSemantics_.size();maze.readPCs={0x245C,0x2498};
    maze.proofPCs={0x2448,0x244B,0x244F,0x2453,0x2455,0x2457,0x2459,0x245C,0x245F,0x2460,0x2461,0x2463,0x2465,0x2467,0x2468,0x246A,0x246C,0x246D,
                    0x2487,0x248A,0x248E,0x2492,0x2494,0x2496,0x2498,0x249B,0x249C,0x249D,0x249F,0x24A0,0x24A2,0x24A3,0x24A7,0x24A9,0x24AA,0x24AC,0x24AE,0x24AF};
    maze.originDefinitionIds=defsAt(defUseResult_,maze.proofPCs);maze.exact=maze.staticProof;maze.bounded=false;
    maze.note="two static nested-loop consumers prove exactly 30 records x 8 fields at $35B5-$36A4; the $36A5 boundary is not inferred from adjacency";
    fixedRecordSemantics_.push_back(maze);

    // $2BEA low path: DE=$3B08 is literal and the loop body executes before
    // DJNZ, so the first pair $3B08/$3B09 is an exact consumer even if B=0.
    const bool b08FirstShape=allStatic({0x2BEA,0x2BF3,0x2BF9,0x2BFC,0x2BFD,0x2C02,0x2C0A,0x2C0B,0x2C17})&&
        canonicalManifestBound&&
        canonicalManifestBound&&canonicalManifestBound;
    FixedRecordSemanticRecord r3b08=HighRomSemantics::fixedRecordFieldUnion(0x3B08,2,{0},{0,1},romSize,b08FirstShape);
    r3b08.id=fixedRecordSemantics_.size();r3b08.readPCs={0x2C02,0x2C0B};r3b08.proofPCs={0x2BEA,0x2BF3,0x2BF4,0x2BF6,0x2BF9,0x2BFC,0x2BFD,0x2C02,0x2C0A,0x2C0B,0x2C13,0x2C17};
    r3b08.originDefinitionIds=defsAt(defUseResult_,r3b08.proofPCs);r3b08.exact=r3b08.staticProof;r3b08.bounded=false;r3b08.note="literal DE=$3B08 and pre-DJNZ first iteration prove exactly the first two-byte record fields";fixedRecordSemantics_.push_back(r3b08);

    // $2BEA high path: A is clamped at $13, subtracts 7 -> start record 1..12,
    // then B is set to 7. Seven stride-2 iterations therefore prove only the
    // finite field union of records 1..18, never adjacency beyond $3B2D.
    const bool b08HighShape=allStatic({0x2C2E,0x2C30,0x2C32,0x2C34,0x2C36,0x2C39,0x2C3C,0x2C3D,0x2C3F,0x2C41,0x2BFD,0x2C02,0x2C0A,0x2C0B,0x2C17})&&
        canonicalManifestBound;
    FixedRecordSemanticRecord r3b08hi=HighRomSemantics::fixedRecordFieldUnion(0x3B08,2,rangeSet(1,18),{0,1},romSize,b08HighShape);
    r3b08hi.id=fixedRecordSemantics_.size();r3b08hi.readPCs={0x2C02,0x2C0B};r3b08hi.proofPCs={0x2C2E,0x2C30,0x2C32,0x2C34,0x2C36,0x2C37,0x2C39,0x2C3C,0x2C3D,0x2C3E,0x2C3F,0x2C41,0x2BFD,0x2C02,0x2C0A,0x2C0B,0x2C13,0x2C17};
    r3b08hi.originDefinitionIds=defsAt(defUseResult_,r3b08hi.proofPCs);r3b08hi.exact=false;r3b08hi.bounded=r3b08hi.staticProof;r3b08hi.note="clamped start record 1..12 plus exactly seven stride-2 iterations proves bounded field union records 1..18";fixedRecordSemantics_.push_back(r3b08hi);

    // $2DEE: trace discovery may expose this dormant code, but the record proof
    // is accepted only after the analyzer can independently prove the caller,
    // decoder, and LDIR instruction as static instructions. Runtime min/max is
    // never used as the bound.
    const bool rec8Shape=allStatic({0x2D0C,0x2D1D,0x2D2E,0x2DEE,0x2E1B,0x2E20,0x2E32,0x2E42,0x2E45})&&
        canonicalManifestBound&&canonicalManifestBound&&
        canonicalManifestBound&&canonicalManifestBound&&
        canonicalManifestBound&&canonicalManifestBound&&canonicalManifestBound;
    if(rec8Shape)for(std::uint16_t base:{static_cast<std::uint16_t>(0x3B30),static_cast<std::uint16_t>(0x3B40),static_cast<std::uint16_t>(0x3B80)}){
        FixedRecordSemanticRecord r=HighRomSemantics::fixedRecordFieldUnion(base,8,rangeSet(0,7),{0,1,2,3,4,5,6,7},romSize,true);
        r.id=fixedRecordSemantics_.size();r.readPCs={0x2E45};r.proofPCs={0x2D0C,0x2D1D,0x2D2E,0x2DEE,0x2E1B,0x2E1C,0x2E1E,0x2E20,0x2E21,0x2E22,0x2E24,0x2E26,0x2E29,0x2E32,0x2E33,0x2E34,0x2E37,0x2E38,0x2E3A,0x2E3B,0x2E42,0x2E45};
        r.originDefinitionIds=defsAt(defUseResult_,r.proofPCs);r.exact=false;r.bounded=true;r.note="finite selector 0..7 + stride 8 + exact LDIR width 8; static local proof may be trace-seeded but no dynamic value bound is promoted";fixedRecordSemantics_.push_back(r);
    }

    // Apply bounded source-window and fixed-record proofs. The overlay is additive and never rewrites indirect-address analysis.
    for(const auto& b:boundedBlockSemantics_)if(b.staticProof){
        HighRomClosureProvenanceRecord q;q.blockIds.insert(b.id);q.readPCs=b.readPCs;q.proofPCs=b.proofPCs;q.originDefinitionIds=b.originDefinitionIds;q.note=b.note;
        for(auto a:b.coveredAddresses)addByte(a,b.exact,b.bounded,q);
    }
    for(const auto& r:fixedRecordSemantics_)if(r.staticProof){
        HighRomClosureProvenanceRecord q;q.recordIds.insert(r.id);q.readPCs=r.readPCs;q.proofPCs=r.proofPCs;q.originDefinitionIds=r.originDefinitionIds;q.note=r.note;
        for(auto a:r.coveredAddresses)addByte(a,r.exact,r.bounded,q);
    }
    for(const auto& kv:provenance)highRomClosureProvenance_.push_back(kv.second);

    // Semantic coverage deliberately separates indirect-address analysis's startup checksum sweep.
    SemanticCoverageStats sc;sc.romBytes=romSize;
    for(const auto& b:baseline)if(b.primary!=RomClosurePrimary::Unresolved)++sc.indirectAddressExplainedBytes;
    for(const auto& p:indirectAddressClosureProvenance_)if(p.accessPCs.size()==1&&p.accessPCs.count(0x300A))++sc.checksumOnlyBytes;
    std::vector<bool> before(romSize,false),after(romSize,false);
    for(std::size_t i=0;i<baseline.size()&&i<romSize;++i)before[i]=semanticallyTyped(baseline[i]);
    const auto& objs=!residualClosureRomObjects_.empty()?residualClosureRomObjects_:romObjects_;
    for(const auto& o:objs)if(!o.dynamicOnly&&(o.kind==RomObjectKind::ByteLookupTable||o.kind==RomObjectKind::WordPointerTable||o.kind==RomObjectKind::SequentialStream||o.kind==RomObjectKind::RecordTable))
        for(std::size_t a=o.start;a<o.end&&a<romSize;++a)before[a]=true;
    after=before;for(const auto& p:highRomClosureProvenance_)if(p.address<after.size())after[p.address]=true;
    for(bool b:before)if(b)++sc.semanticBytesBeforeHighRom;
    for(std::size_t i=0;i<after.size();++i){if(after[i])++sc.semanticBytesAfterHighRom;if(after[i]&&!before[i])++sc.highRomNewSemanticBytes;}
    stats_.highRom.semanticCoverage=sc;

    // Residual audit is diagnostic-only. It classifies remaining bytes by the
    // strongest nearby proven family without converting adjacency into proof.
    std::size_t rid=0;
    for(std::size_t i=0;i<highRomClosureBytes_.size();){
        if(highRomClosureBytes_[i].primary!=RomClosurePrimary::Unresolved){++i;continue;}
        std::size_t j=i+1;while(j<highRomClosureBytes_.size()&&highRomClosureBytes_[j].primary==RomClosurePrimary::Unresolved)++j;
        HighRomResidualAuditRecord a;a.id=rid++;a.start=static_cast<std::uint16_t>(i);a.end=static_cast<std::uint16_t>(j);a.length=j-i;
        if(overlaps(i,j,0x36A5,0x3703))a.categories.insert(HighRomAuditCategory::PointerTableGap);
        if(overlaps(i,j,0x3B08,0x3B30)||overlaps(i,j,0x32F9,0x3300))a.categories.insert(HighRomAuditCategory::RecordFieldGap);
        if(overlaps(i,j,0x3713,0x39D1))a.categories.insert(HighRomAuditCategory::DecoderUnreachedPayload);
        if(overlaps(i,j,0x3BC8,0x3E4F))a.categories.insert(HighRomAuditCategory::StreamTargetGap);
        if(a.categories.empty())a.categories.insert(HighRomAuditCategory::NoSemanticConsumer);
        bool same=true;for(std::size_t x=i+1;x<j;++x)if(program[x]!=program[i]){same=false;break;}
        if(same&&j-i>=8){a.constantRun=true;a.constantValue=program[i];a.categories.insert(HighRomAuditCategory::ConstantFillCandidate);}
        for(const auto& d:romDecoders_)if((d.routine>=i&&d.routine<j)||(d.routine<i&&i-d.routine<=16)||(d.routine>=j&&d.routine-j<=16))a.nearbyDecoderIds.insert(d.id);
        for(const auto& d:pointerTableDomains_)for(auto e:d.entryAddresses)if((e>=i&&e<j)||(e<i&&i-e<=16)||(e>=j&&e-j<=16)){a.nearbyTableDomainIds.insert(d.id);break;}
        for(const auto& s:streamSemantics_)if(s.accepted&&((s.start<j&&s.end>i)||(s.end<=i&&i-s.end<=16)||(s.start>=j&&s.start-j<=16)))a.nearbyStreamIds.insert(s.id);
        for(const auto& r:fixedRecordSemantics_)for(auto e:r.coveredAddresses)if((e>=i&&e<j)||(e<i&&i-e<=16)||(e>=j&&e-j<=16)){a.nearbyRecordIds.insert(r.id);break;}
        for(const auto& b:boundedBlockSemantics_)for(auto e:b.coveredAddresses)if((e>=i&&e<j)||(e<i&&i-e<=16)||(e>=j&&e-j<=16)){a.nearbyBlockIds.insert(b.id);break;}
        a.note="audit-only: category is a research hypothesis anchored to nearby proven consumers; no adjacency, fill pattern, or dynamic-only observation mutates closure";
        highRomResidualAudit_.push_back(a);i=j;
    }

    // Re-run the generic residual research priority on the high-ROM semantic analysis overlay.
    // This is intentionally research-order metadata only: it cannot create
    // closure, change an object extent, or promote dynamic evidence.
    std::vector<RomConsumerRecord> indirectAddressConsumers;
    (void)IndirectAddressAnalysis::synthesizeRomConsumers(indirectMemoryAccesses_,romSize,indirectAddressConsumers);
    std::vector<RomConsumerRecord> allConsumers=romConsumers_;
    allConsumers.insert(allConsumers.end(),defUseRomConsumers_.begin(),defUseRomConsumers_.end());
    allConsumers.insert(allConsumers.end(),indirectAddressConsumers.begin(),indirectAddressConsumers.end());
    const auto priorityAudit=ResidualResearch::auditResidualSpans(highRomClosureBytes_,objs,allConsumers,dormantCodeSeeds_,program);
    highRomResidualPriorityV2_=ResidualResearch::prioritizeV2(priorityAudit,highRomClosureBytes_,allConsumers,128);
    for(auto& pr:highRomResidualPriorityV2_){
        auto it=std::find_if(highRomResidualAudit_.begin(),highRomResidualAudit_.end(),[&](const HighRomResidualAuditRecord& a){return a.start==pr.start&&a.end==pr.end;});
        if(it==highRomResidualAudit_.end())continue;
        const std::size_t semanticNear=it->nearbyDecoderIds.size()+it->nearbyTableDomainIds.size()+it->nearbyStreamIds.size()+it->nearbyRecordIds.size()+it->nearbyBlockIds.size();
        if(semanticNear){
            pr.score+=static_cast<int>(std::min<std::size_t>(semanticNear,8)*3);
            pr.reason+="; high-ROM semantic analysis nearby decoder/table/stream/record/block evidence="+std::to_string(semanticNear)+" (priority only)";
        }
        int categoryBonus=0;
        if(it->categories.count(HighRomAuditCategory::PointerTableGap))categoryBonus+=4;
        if(it->categories.count(HighRomAuditCategory::RecordFieldGap))categoryBonus+=4;
        if(it->categories.count(HighRomAuditCategory::DecoderUnreachedPayload))categoryBonus+=3;
        if(it->categories.count(HighRomAuditCategory::StreamTargetGap))categoryBonus+=3;
        if(categoryBonus){pr.score+=categoryBonus;pr.reason+="; high-ROM semantic analysis residual-category bonus="+std::to_string(categoryBonus)+" (priority only)";}
    }
    std::stable_sort(highRomResidualPriorityV2_.begin(),highRomResidualPriorityV2_.end(),[](const ResidualPriorityV2Record& a,const ResidualPriorityV2Record& b){
        if(a.score!=b.score)return a.score>b.score;
        if(a.length!=b.length)return a.length<b.length;
        return a.start<b.start;
    });

    std::size_t unresolved=0,newExact=0,newBounded=0;
    for(std::size_t i=0;i<highRomClosureBytes_.size();++i){
        if(highRomClosureBytes_[i].primary==RomClosurePrimary::Unresolved)++unresolved;
        if(i<baseline.size()&&baseline[i].primary==RomClosurePrimary::Unresolved&&highRomClosureBytes_[i].primary!=RomClosurePrimary::Unresolved){
            if(highRomClosureBytes_[i].staticExactDataUse)++newExact;else if(highRomClosureBytes_[i].boundedConsumer)++newBounded;
        }
    }
    stats_.highRom.decoders=romDecoders_.size();stats_.highRom.pointerTableDomains=pointerTableDomains_.size();
    for(const auto& d:pointerTableDomains_)if(d.sparse)++stats_.highRom.sparsePointerTableDomains;
    stats_.highRom.streamFamilies=streamFamilies_.size();for(const auto& s:streamSemantics_)if(s.accepted)++stats_.highRom.acceptedStreams;
    for(const auto& r:fixedRecordSemantics_)if(r.staticProof)++stats_.highRom.fixedRecordProofs;
    for(const auto& b:boundedBlockSemantics_)if(b.staticProof)++stats_.highRom.boundedBlockProofs;
    stats_.highRom.closureProvenanceRecords=highRomClosureProvenance_.size();
    stats_.highRom.residualAuditSpans=highRomResidualAudit_.size();for(const auto& a:highRomResidualAudit_)stats_.highRom.auditedResidualBytes+=a.length;
    stats_.highRom.newlyExactExplainedBytes=newExact;stats_.highRom.newlyBoundedExplainedBytes=newBounded;stats_.highRom.newlyExplainedBytes=newExact+newBounded;
    stats_.highRom.unresolvedAfterHighRom=unresolved;stats_.highRom.semanticCoverage.unresolvedAfterHighRom=unresolved;
}

std::vector<std::string> Decompiler::romDecoderLines() const{
    std::vector<std::string> o;if(!ready_)return{"Decompiler model not built."};
    o.push_back("PacRipper high-ROM semantic analysis ROM decoder grammars");o.push_back("Static consuming code defines grammar; dynamic-only observations never create semantic rules.");o.push_back("");
    for(const auto& d:romDecoders_){
        o.push_back("decoder#"+std::to_string(d.id)+" $"+h16(d.routine)+" "+HighRomSemantics::decoderKindText(d.grammar)+" static="+(d.staticGrammarProof?"yes":"no")+" pointer-continuity="+(d.pointerContinuityProven?"yes":"no")+" trace-discovered="+(d.dynamicSeededCode?"yes":"no")+" dynamic-only="+(d.dynamicOnly?"yes":"no"));
        o.push_back("  reads="+pcs(d.readPCs)+" command-tests="+pcs(d.commandTestPCs)+" proof="+pcs(d.sourcePCs));
        for(const auto& r:d.rules){std::ostringstream x;x<<"  rule $"<<std::uppercase<<std::hex<<std::setw(2)<<std::setfill('0')<<(unsigned)r.opcodeLo;if(r.opcodeHi!=r.opcodeLo)x<<"-$"<<std::setw(2)<<(unsigned)r.opcodeHi;x<<std::dec<<" payload="<<r.payloadBytes<<(r.littleEndianJump?" LE16-jump":"")<<(r.terminates?" terminates":"")<<" :: "<<r.note;o.push_back(x.str());}
        o.push_back("  "+d.note);
    }
    return o;
}
std::vector<std::string> Decompiler::streamFamilyLines() const{
    std::vector<std::string> o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper high-ROM semantic analysis stream families");
    for(const auto& f:streamFamilies_)o.push_back("family#"+std::to_string(f.id)+" "+f.name+" decoder#"+std::to_string(f.decoderId)+" domains="+ids(f.tableDomainIds,"domain#")+" streams="+ids(f.streamIds,"stream#"));
    o.push_back("");for(const auto& s:streamSemantics_)o.push_back("stream#"+std::to_string(s.id)+" $"+h16(s.start)+"-$"+h16(s.end)+" "+(s.accepted?(s.cyclic?"ACCEPTED-CYCLE":"ACCEPTED"):"REJECTED")+" "+(s.exact?"exact":s.bounded?"bounded":"diagnostic")+" static="+(s.staticProof?"yes":"no")+" dynamic-only="+(s.dynamicOnly?"yes":"no")+" table-indexes="+pcs(s.tableIndices)+" :: "+s.terminationReason);
    return o;
}
std::vector<std::string> Decompiler::highRomObjectLines() const{
    std::vector<std::string> o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper high-ROM semantic analysis high-ROM semantic objects / residual audit");
    for(const auto& d:pointerTableDomains_)o.push_back("pointer-domain#"+std::to_string(d.id)+" decoder#"+std::to_string(d.decoderId)+" base=$"+h16(d.base)+" indexes="+pcs(d.indices)+(d.sparse?" SPARSE":"")+" static="+(d.staticProof?"yes":"no")+" proof="+pcs(d.proofPCs));
    for(const auto& r:fixedRecordSemantics_)o.push_back("record#"+std::to_string(r.id)+" base=$"+h16(r.base)+" stride="+std::to_string(r.stride)+" addresses="+std::to_string(r.coveredAddresses.size())+" static="+(r.staticProof?"yes":"no")+" "+(r.exact?"exact":r.bounded?"bounded":"diagnostic"));
    for(const auto& b:boundedBlockSemantics_)o.push_back("block#"+std::to_string(b.id)+" base=$"+h16(b.base)+" start-offsets=$"+h16(b.startOffsetLo)+"-$"+h16(b.startOffsetHi)+" width="+std::to_string(b.width)+" addresses="+std::to_string(b.coveredAddresses.size())+" static="+(b.staticProof?"yes":"no")+" "+(b.exact?"exact":b.bounded?"bounded":"diagnostic"));
    o.push_back("");for(const auto& a:highRomResidualAudit_){std::ostringstream s;s<<"residual#"<<a.id<<" $"<<h16(a.start)<<"-$"<<h16(a.end)<<" len="<<a.length<<" categories={";std::size_t n=0;for(auto c:a.categories){if(n++)s<<",";s<<HighRomSemantics::auditCategoryText(c);}s<<"}";o.push_back(s.str());}
    return o;
}
std::vector<std::string> Decompiler::semanticCoverageLines() const{
    std::vector<std::string> o;if(!ready_)return{"Decompiler model not built."};const auto& s=stats_.highRom.semanticCoverage;
    o.push_back("PacRipper high-ROM semantic analysis semantic coverage");o.push_back("indirect-address analysis consumer-covered bytes: "+std::to_string(s.indirectAddressExplainedBytes));
    o.push_back("indirect-address analysis startup-checksum-only bytes (consumer coverage, NOT semantic typing): "+std::to_string(s.checksumOnlyBytes));
    o.push_back("Static semantic bytes before high-ROM semantic analysis: "+std::to_string(s.semanticBytesBeforeHighRom));o.push_back("New semantic bytes from high-ROM semantic analysis decoder/table/record/block-window proof: "+std::to_string(s.highRomNewSemanticBytes));
    o.push_back("Static semantic bytes after high-ROM semantic analysis: "+std::to_string(s.semanticBytesAfterHighRom));o.push_back("Raw closure residual after high-ROM semantic analysis: "+std::to_string(s.unresolvedAfterHighRom));return o;
}
std::vector<std::string> Decompiler::highRomClosureLines() const{
    std::vector<std::string> o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper high-ROM semantic analysis semantic closure delta / provenance");
    o.push_back("new="+std::to_string(stats_.highRom.newlyExplainedBytes)+" exact="+std::to_string(stats_.highRom.newlyExactExplainedBytes)+" bounded="+std::to_string(stats_.highRom.newlyBoundedExplainedBytes)+" residual="+std::to_string(stats_.highRom.unresolvedAfterHighRom));
    for(const auto& p:highRomClosureProvenance_){const bool wasUnresolved=p.address<indirectAddressClosureBytes_.size()&&indirectAddressClosureBytes_[p.address].primary==RomClosurePrimary::Unresolved;if(wasUnresolved)o.push_back("$"+h16(p.address)+" "+(p.exact?"exact":"bounded")+" decoders="+ids(p.decoderIds,"decoder#")+" domains="+ids(p.tableDomainIds,"domain#")+" streams="+ids(p.streamIds,"stream#")+" records="+ids(p.recordIds,"record#")+" blocks="+ids(p.blockIds,"block#")+" reads="+pcs(p.readPCs)+" proof="+pcs(p.proofPCs));}
    return o;
}
std::vector<std::string> Decompiler::highRomResidualPriorityV2Lines() const{
    std::vector<std::string> o;if(!ready_)return{"Decompiler model not built."};
    o.push_back("PacRipper high-ROM semantic analysis residual priority v2");
    o.push_back("Research-order score only, recomputed after the high-ROM semantic analysis overlay. It never changes closure or proof status.");o.push_back("");
    for(const auto& r:highRomResidualPriorityV2_)o.push_back("audit#"+std::to_string(r.auditId)+" $"+h16(r.start)+"-$"+h16(static_cast<std::uint16_t>(r.end-1))+" len="+std::to_string(r.length)+" score="+std::to_string(r.score)+"  "+r.reason);
    return o;
}

} // namespace pacripper
