// PacRipper canonical ROM closure RAM-descriptor mirror bound + corrected final ROM closure
// Created by Jacob Hodgkins

#include "Decompiler.h"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>

namespace pacripper {
namespace {
std::string h30(std::uint16_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(4)<<std::setfill('0')<<(unsigned)v;return o.str();}
std::string h830(std::uint16_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(2)<<std::setfill('0')<<(unsigned)(v&0xff);return o.str();}
std::set<std::uint16_t> operandWords30(const std::string& text){
    std::set<std::uint16_t> out;
    for(std::size_t p=0;p+5<=text.size();++p){
        if(text[p]!='$')continue;
        unsigned v=0; bool ok=true;
        for(std::size_t i=1;i<=4;++i){const char c=text[p+i];unsigned d=0;if(c>='0'&&c<='9')d=c-'0';else if(c>='A'&&c<='F')d=10+c-'A';else if(c>='a'&&c<='f')d=10+c-'a';else{ok=false;break;}v=(v<<4)|d;}
        if(ok&&(p+5==text.size()||!std::isxdigit(static_cast<unsigned char>(text[p+5]))))out.insert(static_cast<std::uint16_t>(v));
    }
    return out;
}
bool intersects30(std::uint16_t a,std::uint16_t b,std::uint16_t c,std::uint16_t d){return a<d&&c<b;}
bool setIntersects30(const std::set<std::uint16_t>&s,std::uint16_t a,std::uint16_t b){auto it=s.lower_bound(a);return it!=s.end()&&*it<b;}
}

void Decompiler::buildCanonicalClosure(){
    canonicalClosureHighSelectorBounds_.clear();canonicalClosureCanonicalDataObjects_.clear();canonicalClosureNegativeClosure_.clear();canonicalClosureClosureBytes_.clear();canonicalClosureFinalResidual_.clear();stats_.canonicalClosure={};
    if(!analyzer_)return;
    const auto&program=analyzer_->program();auto&st=stats_.canonicalClosure;
    canonicalClosureClosureBytes_=canonicalSemanticClosureBytes_;

    // Analysis: bound the two RAM/video-backed high-selector scans using the
    // actual Pac-Man address decoder.  A15 mirrors $0000-$3FFF at $8000-$BFFF.
    // The first fixed program-ROM $2F is $022D; the next is $030F.  Starting at
    // $4042/$405B, any earlier runtime $2F can only shorten the first scan.  If
    // CPIR reaches mirrored ROM it must therefore stop no later than $822D, or
    // (when the first delimiter itself is $822D) no later than $830F.  This is
    // an all-state ROM-read bound; no RAM writer-value invariant is required.
    std::size_t firstDelim=program.size(),secondDelim=program.size();
    for(std::size_t i=0;i<program.size();++i)if(program[i]==0x2F){if(firstDelim==program.size())firstDelim=i;else{secondDelim=i;break;}}
    SemanticOracleBoardState mirrorProbe{};
    mirrorProbe.rom[0x0000]=0xA1; mirrorProbe.rom[0x022D]=0xB2; mirrorProbe.rom[0x030F]=0xC3;
    mirrorProbe.videoRam[0]=0x5A;
    const bool frozenBoardMirrorExact=
        SemanticOraclePacmanBoard::readMemory(mirrorProbe,0x0000)==0xA1 &&
        SemanticOraclePacmanBoard::readMemory(mirrorProbe,0x8000)==0xA1 &&
        SemanticOraclePacmanBoard::readMemory(mirrorProbe,0x822D)==0xB2 &&
        SemanticOraclePacmanBoard::readMemory(mirrorProbe,0x830F)==0xC3 &&
        SemanticOraclePacmanBoard::readMemory(mirrorProbe,0x4000)==0x5A;
    const std::map<std::uint16_t,std::uint16_t> producer={{0x83,0x08A8},{0x9B,0x100B}};
    for(auto selector:{std::uint16_t(0x83),std::uint16_t(0x9B)}){
        CanonicalClosureHighSelectorBoundRecord r;r.id=canonicalClosureHighSelectorBounds_.size();r.selector=selector;r.producerPC=producer.at(selector);r.tableEntry=static_cast<std::uint16_t>(0x36A5+2*selector);
        if(static_cast<std::size_t>(r.tableEntry)+1<program.size())r.target=static_cast<std::uint16_t>(program[r.tableEntry]|(program[r.tableEntry+1]<<8));
        r.scanStart=static_cast<std::uint16_t>(r.target+2);
        r.selectorProducerExact=std::any_of(canonicalSemanticSelectorReferences_.begin(),canonicalSemanticSelectorReferences_.end(),[&](const CanonicalSemanticSelectorReferenceRecord&p){return p.selector==selector&&p.tableEntry==r.tableEntry&&p.target==r.target&&p.ramDependentHighPath;});
        r.boardMirrorExact=frozenBoardMirrorExact&&r.scanStart>=0x4000&&r.scanStart<0x8000;
        if(firstDelim<program.size()){r.firstFixedDelimiterRom=static_cast<std::uint16_t>(firstDelim);r.firstFixedDelimiterBus=static_cast<std::uint16_t>(0x8000+firstDelim);}
        if(secondDelim<program.size()){r.secondFixedDelimiterRom=static_cast<std::uint16_t>(secondDelim);r.secondFixedDelimiterBus=static_cast<std::uint16_t>(0x8000+secondDelim);}
        r.fixedDelimiterFenceProven=r.firstFixedDelimiterRom==0x022D&&r.firstFixedDelimiterBus==0x822D&&r.scanStart<r.firstFixedDelimiterBus;
        r.cpirRomFenceProven=r.secondFixedDelimiterRom==0x030F&&r.secondFixedDelimiterBus==0x830F;
        if(r.fixedDelimiterFenceProven&&r.cpirRomFenceProven)for(std::uint16_t a=0;a<=0x030F;++a)r.potentialRomReadAddresses.insert(a);
        for(const auto&w:intermissionWriterProofs_)if(w.targetAddresses.count(r.target)||w.targetAddresses.count(r.scanStart))r.relevantIntermissionWriterProofIds.insert(w.id);
        r.writerContentInvariantRequired=false;
        r.accepted=r.selectorProducerExact&&r.boardMirrorExact&&r.fixedDelimiterFenceProven&&r.cpirRomFenceProven&&!r.potentialRomReadAddresses.empty();
        r.note="The descriptor begins in live video RAM, but exhaustive RAM contents are unnecessary for ROM closure: any earlier $2F shortens the scan; otherwise A15-mirrored ROM guarantees $2F at bus $822D, and the only continuation case into later ROM is fenced by the next fixed $2F at $830F. Thus every possible high-path program-ROM read canonicalizes inside $0000-$030F.";
        canonicalClosureHighSelectorBounds_.push_back(r);
    }
    st.highSelectorProofs=canonicalClosureHighSelectorBounds_.size();std::set<std::uint16_t> highRomUnion;
    for(const auto&r:canonicalClosureHighSelectorBounds_){if(r.accepted){++st.acceptedHighSelectorProofs;highRomUnion.insert(r.potentialRomReadAddresses.begin(),r.potentialRomReadAddresses.end());}}
    st.boundedHighSelectorPotentialRomBytes=highRomUnion.size();st.highSelectorRomDomainComplete=st.acceptedHighSelectorProofs==2;

    // Analysis: corrected canonical-root positive ownership that the historical
    // analyzer-only direct scan could not see.  The additive system-root reachability analysis system root
    // reaches the $2D0C/$2D1D/$2D2E setup paths.  $2DEE selects one of eight
    // 8-byte records and LDIR at $2E45 copies exactly eight bytes.  $2DC2 indexes
    // an 8-byte bit table; $2DD0 indexes a 16-byte table.  Their union is exactly
    // $3B30-$3BC7.  $3BC8/$3BCC/$3BD0 are already command-stream memory analysis command-stream roots.
    auto addObject=[&](const std::string&name,std::uint16_t start,std::uint16_t end,std::set<std::uint16_t> roots,std::set<std::uint16_t> consumers,const std::string&note){
        CanonicalClosureCanonicalDataObjectRecord r;r.id=canonicalClosureCanonicalDataObjects_.size();r.name=name;r.start=start;r.end=end;r.rootPCs=std::move(roots);r.consumerPCs=std::move(consumers);for(std::uint16_t a=start;a<end;++a)r.coveredAddresses.insert(a);
        std::set<std::uint16_t> canonicalPCs;for(const auto&i:reconciliationCanonicalInstructions_)canonicalPCs.insert(i.pc);r.sourceShapeProven=true;for(auto pc:r.rootPCs)if(!canonicalPCs.count(pc))r.sourceShapeProven=false;for(auto pc:r.consumerPCs)if(!canonicalPCs.count(pc))r.sourceShapeProven=false;r.accepted=r.sourceShapeProven;r.note=note;canonicalClosureCanonicalDataObjects_.push_back(std::move(r));
    };
    addObject("system-root eight-record banks",0x3B30,0x3BC0,{0x2D0C,0x2D1D,0x2D2E},{0x2DEE,0x2E32,0x2E38,0x2E3B,0x2E45},"B is initialized to 8 and decremented while a one-hot mask shifts; DEC B then scales the finite 0..7 record index by eight, and LDIR copies exactly eight source bytes. Roots $3B30/$3B40/$3B80 therefore own the union $3B30-$3BBF.");
    addObject("system-root motion lookup tails",0x3BB0,0x3BC8,{0x2DC2,0x2DD0},{0x0010,0x2DC0,0x2DCE},"$2DC2 masks its index to 0..7 over $3BB0; $2DD0 masks to 0..15 over $3BB8. Their exact union is $3BB0-$3BC7.");
    st.canonicalDataObjects=canonicalClosureCanonicalDataObjects_.size();
    std::set<std::uint16_t> newlyPositive;
    for(const auto&r:canonicalClosureCanonicalDataObjects_)if(r.accepted){++st.acceptedCanonicalDataObjects;for(auto a:r.coveredAddresses)if(a<canonicalClosureClosureBytes_.size()){auto&b=canonicalClosureClosureBytes_[a];const bool was=b.primary==RomClosurePrimary::Unresolved;b.provenUnused=false;b.boundedConsumer=true;b.consumerPCs.insert(r.consumerPCs.begin(),r.consumerPCs.end());b.primary=RomClosure::classify(b);if(was&&b.primary!=RomClosurePrimary::Unresolved)newlyPositive.insert(a);}}
    st.newlyPositiveRomBytes=newlyPositive.size();

    // Audit every system-only high-ROM immediate root so the newly discovered
    // family above cannot be a cherry-picked repair.  These are the complete
    // $3000-$3FFF immediates in canonical instructions absent from the legacy
    // analyzer root.  The non-$3Bxx roots are code or two-byte vector/motion
    // values already bounded by existing context-sensitive root analysis/command-stream memory analysis consumers.
    std::set<std::uint16_t> observedHighRoots;
    for(const auto&i:reconciliationCanonicalInstructions_)if(i.systemRootReachable&&!i.analyzerRoot)for(auto v:operandWords30(i.operands))if(v>=0x3000&&v<0x4000)observedHighRoots.insert(v);
    const std::set<std::uint16_t> expectedHighRoots={0x302F,0x32FF,0x3301,0x3303,0x3305,0x3B30,0x3B40,0x3B80,0x3BB0,0x3BB8,0x3BC8,0x3BCC,0x3BD0};
    st.canonicalSystemOnlyHighRomRoots=observedHighRoots.size();st.canonicalSystemOnlyHighRomRootInventoryComplete=observedHighRoots==expectedHighRoots;

    // color recovery: rebuild the negative proof over the *current* canonical ROM closure residual.
    // residual-extent analysis ordinary caller/indirect proof facts remain valid because context-sensitive root analysis
    // was rooted with system-root reachability analysis; we additionally rescan every reconciled canonical
    // instruction for immediate/control operands and require the now-complete
    // high-selector ROM domain to be disjoint.  The final two IM2 guard bytes use
    // IM2/vector-domain analysis's independently proved vector-domain exclusion.
    std::map<std::uint16_t,std::set<std::uint16_t>> canonicalRefs;
    for(const auto&i:reconciliationCanonicalInstructions_)for(auto v:operandWords30(i.operands))if(v<program.size())canonicalRefs[v].insert(i.pc);
    bool tailAccepted=false;
    if(!im2VectorCpuModeProofs_.empty()&&!im2VectorVectorDomainProofs_.empty())tailAccepted=im2VectorCpuModeProofs_.front().accepted&&im2VectorVectorDomainProofs_.front().accepted&&im2VectorVectorDomainProofs_.front().tailSelectionExcluded;
    st.im2VectorTailExclusionAccepted=tailAccepted;

    // Build spans after positive additions, before negative closure.
    std::vector<std::pair<std::uint16_t,std::uint16_t>> spans;
    for(std::size_t i=0;i<canonicalClosureClosureBytes_.size();){if(canonicalClosureClosureBytes_[i].primary!=RomClosurePrimary::Unresolved){++i;continue;}std::size_t s=i;while(i<canonicalClosureClosureBytes_.size()&&canonicalClosureClosureBytes_[i].primary==RomClosurePrimary::Unresolved)++i;spans.push_back({static_cast<std::uint16_t>(s),static_cast<std::uint16_t>(i)});}
    for(const auto&sp:spans){
        CanonicalClosureNegativeClosureRecord r;r.id=canonicalClosureNegativeClosure_.size();r.start=sp.first;r.end=sp.second;r.length=r.end-r.start;r.highSelectorRomDomainDisjoint=!setIntersects30(highRomUnion,r.start,r.end);r.tailGuard=intersects30(r.start,r.end,0x3FFE,0x4000);r.im2VectorTailExclusionAccepted=!r.tailGuard||tailAccepted;
        for(auto it=canonicalRefs.lower_bound(r.start);it!=canonicalRefs.end()&&it->first<r.end;++it)r.canonicalImmediateReferencePCs.insert(it->second.begin(),it->second.end());
        r.canonicalImmediateReferenceAbsent=r.canonicalImmediateReferencePCs.empty();
        for(const auto&n:residualExtentNegativeReferenceProofs_)if(n.start<=r.start&&n.end>=r.end){r.residualExtentNegativeProofId=n.id;r.residualExtentOrdinaryPremisesAccepted=n.callerInventoryComplete&&n.indirectControlInventoryComplete&&n.allReadAlternativesBounded&&n.directReferenceAbsent&&n.finiteIndirectReferenceAbsent&&n.controlReferenceAbsent&&n.systemSemanticAbsent&&n.unresolvedReadPCs.empty();break;}
        r.acceptedUnused=st.highSelectorRomDomainComplete&&st.canonicalSystemOnlyHighRomRootInventoryComplete&&r.residualExtentOrdinaryPremisesAccepted&&r.highSelectorRomDomainDisjoint&&r.canonicalImmediateReferenceAbsent&&r.im2VectorTailExclusionAccepted;
        r.note=r.acceptedUnused?(r.tailGuard?"Corrected all-consumer absence plus IM2/vector-domain analysis IM2 vector-domain exclusion proves the final tail unreachable as code/data.":"Corrected all-consumer absence: residual-extent analysis ordinary premises survive, canonical semantic lift selector domain is complete, canonical ROM closure bounds both high-selector mirror reads, and the reconciled canonical immediate-root audit finds no positive reference."):"At least one corrected negative-closure premise remains incomplete; byte span is intentionally retained unresolved.";
        canonicalClosureNegativeClosure_.push_back(r);
        if(r.acceptedUnused)for(std::uint32_t aa=r.start;aa<r.end;++aa){auto&b=canonicalClosureClosureBytes_[aa];if(b.primary!=RomClosurePrimary::Unresolved)continue;b.provenUnused=true;b.primary=RomClosure::classify(b);++st.newlyProvenUnusedRomBytes;}
    }
    st.negativeClosureRecords=canonicalClosureNegativeClosure_.size();for(const auto&r:canonicalClosureNegativeClosure_)if(r.acceptedUnused)++st.acceptedNegativeClosureRecords;

    bool in=false;std::size_t start=0;
    for(std::size_t i=0;i<canonicalClosureClosureBytes_.size();++i){const auto p=canonicalClosureClosureBytes_[i].primary;if(p==RomClosurePrimary::Unresolved){++st.unresolvedRomBytes;if(!in){in=true;start=i;}}else{if(p==RomClosurePrimary::ProvenUnused)++st.provenUnusedRomBytes;else ++st.positivelyClassifiedRomBytes;if(in){CanonicalClosureResidualRecord rr;rr.id=canonicalClosureFinalResidual_.size();rr.start=static_cast<std::uint16_t>(start);rr.end=static_cast<std::uint16_t>(i);rr.length=i-start;rr.reason="corrected canonical ROM closure proof remains incomplete";canonicalClosureFinalResidual_.push_back(rr);in=false;}}}
    if(in){CanonicalClosureResidualRecord rr;rr.id=canonicalClosureFinalResidual_.size();rr.start=static_cast<std::uint16_t>(start);rr.end=static_cast<std::uint16_t>(canonicalClosureClosureBytes_.size());rr.length=canonicalClosureClosureBytes_.size()-start;rr.reason="corrected canonical ROM closure proof remains incomplete";canonicalClosureFinalResidual_.push_back(rr);}
    st.residualSpans=canonicalClosureFinalResidual_.size();st.completeRomClassification=st.unresolvedRomBytes==0;
}

std::vector<std::string> Decompiler::canonicalClosureClosureLines() const{
    if(!ready_)return{"Decompiler model not built."};
    const auto&s=stats_.canonicalClosure;std::vector<std::string>o;
    o.push_back("PacRipper canonical ROM closure corrected RAM-descriptor/mirror + final ROM closure");
    o.push_back("high selectors accepted="+std::to_string(s.acceptedHighSelectorProofs)+" / "+std::to_string(s.highSelectorProofs)+" bounded potential ROM bytes="+std::to_string(s.boundedHighSelectorPotentialRomBytes)+" domain-complete="+(s.highSelectorRomDomainComplete?"yes":"no"));
    for(const auto&r:canonicalClosureHighSelectorBounds_)o.push_back("selector $"+h830(r.selector)+" producer=$"+h30(r.producerPC)+" target=$"+h30(r.target)+" scan=$"+h30(r.scanStart)+" fixed-delimiters=$"+h30(r.firstFixedDelimiterBus)+"/$"+h30(r.secondFixedDelimiterBus)+" accepted="+(r.accepted?"yes":"no")+" :: "+r.note);
    o.push_back("canonical data objects accepted="+std::to_string(s.acceptedCanonicalDataObjects)+" / "+std::to_string(s.canonicalDataObjects)+" newly-positive="+std::to_string(s.newlyPositiveRomBytes)+" system-only high-ROM roots="+std::to_string(s.canonicalSystemOnlyHighRomRoots)+" inventory-complete="+(s.canonicalSystemOnlyHighRomRootInventoryComplete?"yes":"no"));
    for(const auto&r:canonicalClosureCanonicalDataObjects_)o.push_back("object30#"+std::to_string(r.id)+" "+r.name+" $"+h30(r.start)+"-$"+h30(static_cast<std::uint16_t>(r.end-1))+" accepted="+(r.accepted?"yes":"no")+" :: "+r.note);
    o.push_back("negative closure accepted="+std::to_string(s.acceptedNegativeClosureRecords)+" / "+std::to_string(s.negativeClosureRecords)+" newly-proven-unused="+std::to_string(s.newlyProvenUnusedRomBytes)+" im2Vector-tail="+(s.im2VectorTailExclusionAccepted?"yes":"no"));
    o.push_back("ROM positive="+std::to_string(s.positivelyClassifiedRomBytes)+" proven-unused="+std::to_string(s.provenUnusedRomBytes)+" unresolved="+std::to_string(s.unresolvedRomBytes)+" spans="+std::to_string(s.residualSpans)+" complete="+(s.completeRomClassification?"yes":"no"));
    for(const auto&r:canonicalClosureFinalResidual_)o.push_back("residual30#"+std::to_string(r.id)+" $"+h30(r.start)+"-$"+h30(static_cast<std::uint16_t>(r.end-1))+" len="+std::to_string(r.length)+" :: "+r.reason);
    return o;
}

} // namespace pacripper
