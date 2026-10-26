// PacRipper canonical semantic lift canonical semantic rebase + selector closure
// Created by Jacob Hodgkins

#include "Decompiler.h"

#include <iomanip>
#include <set>
#include <sstream>

namespace pacripper {
namespace {
void addRange(std::set<std::uint16_t>&s,std::uint16_t a,std::uint16_t b){for(unsigned v=a;v<=b;++v)s.insert(static_cast<std::uint16_t>(v));}
}

void Decompiler::buildCanonicalSemantic(){
    canonicalSemanticLiftedOperations_.clear();canonicalSemanticLiftedBlocks_.clear();canonicalSemanticOracleRecords_.clear();canonicalSemanticSelectorDomains_.clear();canonicalSemanticSelectorReferences_.clear();canonicalSemanticClosureBytes_.clear();canonicalSemanticFinalResidual_.clear();stats_.canonicalSemantic={};
    if(!analyzer_)return;
    const auto&program=analyzer_->program();auto&st=stats_.canonicalSemantic;
    CanonicalSemanticLift::buildCanonicalLift(program,reconciliationCanonicalInstructions_,canonicalSemanticLiftedOperations_,canonicalSemanticLiftedBlocks_,st);
    canonicalSemanticOracleRecords_=CanonicalSemanticLift::verifyWithIndependentOracle(program,canonicalSemanticLiftedOperations_,canonicalSemanticLiftedBlocks_,st,3);

    CanonicalSemanticSelectorDomainRecord d;d.id=0;
    addRange(d.selectors,0x00,0x17);addRange(d.selectors,0x1B,0x36);d.selectors.insert(0x83);d.selectors.insert(0x86);d.selectors.insert(0x9B);d.selectors.insert(0xA2);
    d.directSelectors={0x00,0x01,0x02,0x08,0x09,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E};
    // Inline task-$1C records are derived directly from the ROM encoding
    // RST $28 ; DB $1C,selector rather than trusted from a handwritten list.
    for(std::size_t pc=0;pc+2<program.size();++pc)if(program[pc]==0xEF&&program[pc+1]==0x1C){d.producerPCs.insert(static_cast<std::uint16_t>(pc));d.inlineTaskSelectors.insert(program[pc+2]);}
    d.wrapperSelectors={0x0C,0x0D,0x0E,0x0F,0x10,0x12,0x13,0x14,0x15,0x16,0x17,0x2F,0x30,0x31,0x32,0x33,0x34,0x35,0x36};
    d.playerSelectors={0x03,0x04};d.levelSelectors={0x1B,0x1C,0x1D,0x1E,0x1F,0x20,0x21,0x22};
    const std::set<std::uint16_t> expectedProducerPCs={0x0263,0x04D8,0x05FC,0x05FF,0x0614,0x0683,0x0686,0x08A8,0x0936,0x0955,0x09A6,0x09B0,0x100B,0x1013};
    const std::set<std::uint16_t> expectedInlineSelectors={0x03,0x05,0x06,0x07,0x0A,0x0B,0x11,0x83,0x86,0x9B,0xA2};
    std::set<std::uint16_t> canonicalPCs;for(const auto&r:reconciliationCanonicalInstructions_)canonicalPCs.insert(r.pc);
    d.callInventoryComplete=d.producerPCs==expectedProducerPCs;for(auto pc:d.producerPCs)if(!canonicalPCs.count(pc))d.callInventoryComplete=false;
    d.inlineInventoryComplete=d.inlineTaskSelectors==expectedInlineSelectors;
    std::set<std::uint16_t> unionDomain=d.directSelectors;unionDomain.insert(d.inlineTaskSelectors.begin(),d.inlineTaskSelectors.end());unionDomain.insert(d.wrapperSelectors.begin(),d.wrapperSelectors.end());unionDomain.insert(d.playerSelectors.begin(),d.playerSelectors.end());unionDomain.insert(d.levelSelectors.begin(),d.levelSelectors.end());
    d.finiteDomainComplete=d.callInventoryComplete&&d.inlineInventoryComplete&&d.selectors.size()==56&&unionDomain==d.selectors;
    d.note="complete static task-$1C/$2C5E selector union; direct/wrapper/player/level and RST-$28 inline task producers retained explicitly";
    canonicalSemanticSelectorDomains_.push_back(d);st.selectorDomainValues=d.selectors.size();st.selectorDomainComplete=d.finiteDomainComplete;

    canonicalSemanticClosureBytes_=reconciliationClosureBytes_;
    std::set<std::uint16_t> newlyPositive;
    for(auto selector:d.selectors){
        CanonicalSemanticSelectorReferenceRecord r;r.id=canonicalSemanticSelectorReferences_.size();r.selector=selector;r.tableEntry=static_cast<std::uint16_t>(0x36A5u+2u*selector);r.lowPath=selector<0x80;r.targetInRom=false;
        if(static_cast<std::size_t>(r.tableEntry)+1>=program.size()){r.note="selector table entry outside program ROM";canonicalSemanticSelectorReferences_.push_back(r);continue;}
        r.target=static_cast<std::uint16_t>(program[r.tableEntry]|(program[r.tableEntry+1]<<8));r.targetInRom=r.target<program.size();r.romReadAddresses.insert(r.tableEntry);r.romReadAddresses.insert(static_cast<std::uint16_t>(r.tableEntry+1));
        if(r.lowPath&&r.targetInRom){
            // $2C5E low-B grammar: BIT descriptor byte, then scan to first $2F;
            // the byte following that delimiter is read once, and if nonnegative
            // a counted copy reads B bytes where B is the first-stream length.
            std::size_t p=r.target;r.romReadAddresses.insert(static_cast<std::uint16_t>(p));++p;std::size_t count=0;bool found=false;
            while(p<program.size()){r.romReadAddresses.insert(static_cast<std::uint16_t>(p));if(program[p]==0x2F){found=true;++p;break;}++count;++p;if(count>255)break;}
            if(found&&p<program.size()){
                r.romReadAddresses.insert(static_cast<std::uint16_t>(p));
                if((program[p]&0x80)==0){for(std::size_t n=0;n<count&&p+n<program.size();++n)r.romReadAddresses.insert(static_cast<std::uint16_t>(p+n));}
                r.streamExtentProven=true;
            }
            r.note=r.streamExtentProven?"exact finite selector + source-proven low-B $2F stream grammar":"low-B ROM target but stream grammar did not terminate inside ROM";
        }else if(!r.lowPath&&!r.targetInRom){r.ramDependentHighPath=true;r.note="high-B selector reaches RAM-backed descriptor; downstream CPIR/search contents are runtime-dependent and block exhaustive negative ROM proof";++st.ramDependentHighSelectors;}
        else if(!r.lowPath&&r.targetInRom)r.note="high-B path target is ROM; selector/table fetch is exact but the CPIR continuation grammar is not promoted to negative closure in this analysis";
        for(auto a:r.romReadAddresses)if(a<canonicalSemanticClosureBytes_.size()){
            auto&b=canonicalSemanticClosureBytes_[a];const bool wasUnresolved=b.primary==RomClosurePrimary::Unresolved;b.provenUnused=false;b.staticExactDataUse=true;b.consumerPCs.insert(0x2C5E);b.primary=RomClosure::classify(b);if(wasUnresolved&&b.primary!=RomClosurePrimary::Unresolved)newlyPositive.insert(a);
        }
        canonicalSemanticSelectorReferences_.push_back(std::move(r));
    }
    st.selectorReferences=canonicalSemanticSelectorReferences_.size();st.newlyPositiveRomBytes=newlyPositive.size();
    bool in=false;std::size_t start=0;for(std::size_t i=0;i<canonicalSemanticClosureBytes_.size();++i){if(canonicalSemanticClosureBytes_[i].primary==RomClosurePrimary::Unresolved){++st.unresolvedRomBytes;if(!in){in=true;start=i;}}else{++st.positivelyClassifiedRomBytes;if(in){CanonicalSemanticResidualRecord r;r.id=canonicalSemanticFinalResidual_.size();r.start=static_cast<std::uint16_t>(start);r.end=static_cast<std::uint16_t>(i);r.length=i-start;r.reason="remaining unresolved ROM after exact selector-domain reconstruction; negative closure blocked by RAM-dependent high-B descriptor path";canonicalSemanticFinalResidual_.push_back(r);in=false;}}}
    if(in){CanonicalSemanticResidualRecord r;r.id=canonicalSemanticFinalResidual_.size();r.start=static_cast<std::uint16_t>(start);r.end=static_cast<std::uint16_t>(canonicalSemanticClosureBytes_.size());r.length=canonicalSemanticClosureBytes_.size()-start;r.reason="remaining unresolved ROM after exact selector-domain reconstruction; negative closure blocked by RAM-dependent high-B descriptor path";canonicalSemanticFinalResidual_.push_back(r);}
    st.residualSpans=canonicalSemanticFinalResidual_.size();
}

std::vector<std::string> Decompiler::canonicalSemanticRebaseLines() const{
    if(!ready_)return{"Decompiler model not built."};
    const auto&s=stats_.canonicalSemantic;std::vector<std::string>o;
    o.push_back("PacRipper canonical semantic lift corrected canonical semantic rebase");
    o.push_back("canonical semantic lift="+std::to_string(s.mechanicallyLiftedInstructions)+" / "+std::to_string(s.canonicalInstructionStarts)+" unsupported="+std::to_string(s.unsupportedInstructionSemantics));
    o.push_back("canonical blocks="+std::to_string(s.canonicalBlocks)+" supported="+std::to_string(s.fullySupportedBlocks)+" independent-oracle verified="+std::to_string(s.independentlyVerifiedBlocks)+" mismatches="+std::to_string(s.independentOracleMismatches));
    o.push_back("semantic sources: SemanticLift="+std::to_string(s.semanticLiftPrimitiveOperations)+" SemanticOracle-extension="+std::to_string(s.semanticOracleExtensionOperations)+" CanonicalSemantic-extension="+std::to_string(s.canonicalSemanticExtensionOperations));
    o.push_back("selector domain values="+std::to_string(s.selectorDomainValues)+" complete="+(s.selectorDomainComplete?"yes":"no")+" RAM-dependent-high="+std::to_string(s.ramDependentHighSelectors));
    o.push_back("ROM positive="+std::to_string(s.positivelyClassifiedRomBytes)+" unresolved="+std::to_string(s.unresolvedRomBytes)+" newly-positive="+std::to_string(s.newlyPositiveRomBytes)+" residual-spans="+std::to_string(s.residualSpans));
    return o;
}

} // namespace pacripper
