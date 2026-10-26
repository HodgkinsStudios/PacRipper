// PacRipper exact ROM reconstruction deterministic bit-exact ROM reconstruction proof
// Created by Jacob Hodgkins

#include "ExactRomReconstruction.h"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace pacripper {
namespace {
std::string h16(std::uint16_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(4)<<std::setfill('0')<<(unsigned)v;return o.str();}
std::string instructionText(const ReconciliationCanonicalInstructionRecord&r){return r.operands.empty()?r.mnemonic:r.mnemonic+" "+r.operands;}
std::string inlineKindText(SystemRootInlineDataKind kind){
    switch(kind){
        case SystemRootInlineDataKind::Rst20DispatchTable:return "RST $20 inline dispatch table";
        case SystemRootInlineDataKind::Rst28InlineArgs:return "RST $28 inline arguments";
        case SystemRootInlineDataKind::Rst30InlinePayload:return "RST $30 inline payload";
        case SystemRootInlineDataKind::CallInlineFiveBytes:return "CALL $2BCD inline five-byte payload";
    }
    return "inline payload";
}
}

std::string ExactRomReconstruction::ownerKindText(RomReconstructionOwnerKind k){
    switch(k){
        case RomReconstructionOwnerKind::CanonicalInstruction:return "CanonicalInstruction";
        case RomReconstructionOwnerKind::InlinePayload:return "InlinePayload";
        case RomReconstructionOwnerKind::CanonicalDataObject:return "CanonicalDataObject";
        case RomReconstructionOwnerKind::ClassifiedData:return "ClassifiedData";
        case RomReconstructionOwnerKind::ProvenUnused:return "ProvenUnused";
        default:return "Unowned";
    }
}

RomReconstructionReconstructionResult ExactRomReconstruction::build(
    const std::vector<std::uint8_t>& program,
    const std::vector<ReconciliationCanonicalInstructionRecord>& canonicalInstructions,
    const std::vector<SystemRootInlineDataRecord>& inlineData,
    const std::vector<CanonicalClosureCanonicalDataObjectRecord>& canonicalDataObjects,
    const std::vector<CanonicalClosureNegativeClosureRecord>& negativeClosure,
    const std::vector<RomByteClosureRecord>& closureBytes){

    RomReconstructionReconstructionResult out;auto&st=out.stats;st.romBytes=program.size();
    out.ledger.resize(program.size());out.rebuiltBytes.assign(program.size(),0);
    for(std::size_t a=0;a<program.size();++a){
        auto&r=out.ledger[a];r.address=static_cast<std::uint16_t>(a);r.expectedByte=program[a];
        if(a<closureBytes.size())r.closurePrimary=closureBytes[a].primary;
    }

    auto claim=[&](std::size_t address,std::uint8_t emitted,RomReconstructionOwnerKind kind,std::size_t sourceId,
                   std::uint16_t sourceStart,std::uint16_t sourceEnd,int sourcePc,std::size_t sourceOffset,
                   const std::string&sourceText,const std::string&provenance,bool allowSameKindOverlap=false){
        if(address>=out.ledger.size())return;
        auto&r=out.ledger[address];
        if(r.owned){
            if(allowSameKindOverlap&&r.ownerKind==kind&&r.emittedByte==emitted)return;
            ++st.ownershipConflicts;return;
        }
        r.owned=true;r.ownerKind=kind;r.sourceId=sourceId;r.sourceStart=sourceStart;r.sourceEnd=sourceEnd;
        r.sourcePc=sourcePc;r.sourceOffset=sourceOffset;r.sourceText=sourceText;r.provenance=provenance;r.emittedByte=emitted;
        out.rebuiltBytes[address]=emitted;
        if(emitted!=r.expectedByte)++st.sourceByteMismatches;
    };

    // Strongest ownership first: exact canonical instructions.
    for(const auto&r:canonicalInstructions){
        for(std::size_t n=0;n<r.bytes.size();++n){
            const std::size_t a=static_cast<std::size_t>(r.pc)+n;if(a>=program.size())continue;
            std::ostringstream p;p<<"Reconciliation canonical instruction #"<<r.id<<" byte "<<n<<"/"<<r.bytes.size();
            claim(a,r.bytes[n],RomReconstructionOwnerKind::CanonicalInstruction,r.id,r.pc,
                  static_cast<std::uint16_t>(r.pc+r.bytes.size()),r.pc,n,instructionText(r),p.str());
        }
    }

    // Exact inline call/restart payloads are data ownership, never executable fallthrough.
    for(const auto&r:inlineData){
        for(std::uint16_t a=r.start;a<r.end&&a<program.size();++a){
            std::ostringstream p;p<<"SystemRoot inline-data #"<<r.id<<" sourcePC=$"<<h16(r.sourcePC);
            claim(a,program[a],RomReconstructionOwnerKind::InlinePayload,r.id,r.start,r.end,r.sourcePC,
                  static_cast<std::size_t>(a-r.start),inlineKindText(r.kind),p.str());
        }
    }

    // canonical ROM closure objects may overlap each other by construction; their union has one address owner.
    for(const auto&r:canonicalDataObjects)if(r.accepted){
        for(auto a:r.coveredAddresses)if(a<program.size()){
            std::ostringstream p;p<<"CanonicalClosure canonical data object #"<<r.id<<" "<<r.name;
            claim(a,program[a],RomReconstructionOwnerKind::CanonicalDataObject,r.id,r.start,r.end,-1,
                  static_cast<std::size_t>(a-r.start),r.name,p.str(),true);
        }
    }

    // Exhaustively proven unused bytes are still emitted exactly to reproduce the original image.
    for(const auto&r:negativeClosure)if(r.acceptedUnused){
        for(std::uint16_t a=r.start;a<r.end&&a<program.size();++a){
            std::ostringstream p;p<<"CanonicalClosure negative-closure #"<<r.id;
            claim(a,program[a],RomReconstructionOwnerKind::ProvenUnused,r.id,r.start,r.end,-1,
                  static_cast<std::size_t>(a-r.start),"exact preserved unused byte",p.str());
        }
    }

    // Every remaining positively classified address is emitted through its canonical ROM closure byte classification.
    for(std::size_t a=0;a<program.size();++a){
        if(out.ledger[a].owned)continue;
        const auto primary=a<closureBytes.size()?closureBytes[a].primary:RomClosurePrimary::Unresolved;
        if(primary==RomClosurePrimary::Unresolved)continue;
        const auto kind=primary==RomClosurePrimary::ProvenUnused?RomReconstructionOwnerKind::ProvenUnused:RomReconstructionOwnerKind::ClassifiedData;
        const auto text=kind==RomReconstructionOwnerKind::ProvenUnused?std::string("exact preserved unused byte"):RomClosure::primaryText(primary);
        std::ostringstream p;p<<"CanonicalClosure closure address-local "<<RomClosure::primaryText(primary);
        claim(a,program[a],kind,static_cast<std::size_t>(-1),static_cast<std::uint16_t>(a),static_cast<std::uint16_t>(a+1),-1,0,text,p.str());
    }

    st.ledgerRecords=out.ledger.size();
    for(const auto&r:out.ledger){
        if(r.owned)++st.ownedAddresses;else ++st.unownedAddresses;
        switch(r.ownerKind){
            case RomReconstructionOwnerKind::CanonicalInstruction:++st.canonicalInstructionBytes;break;
            case RomReconstructionOwnerKind::InlinePayload:++st.inlinePayloadBytes;break;
            case RomReconstructionOwnerKind::CanonicalDataObject:++st.canonicalDataObjectBytes;break;
            case RomReconstructionOwnerKind::ClassifiedData:++st.classifiedDataBytes;break;
            case RomReconstructionOwnerKind::ProvenUnused:++st.provenUnusedBytes;break;
            default:break;
        }
        if(r.owned&&r.emittedByte!=r.expectedByte){RomReconstructionBinaryDiffRecord d;d.id=out.diffs.size();d.address=r.address;d.expectedByte=r.expectedByte;d.emittedByte=r.emittedByte;d.ownerKind=r.ownerKind;d.sourceId=r.sourceId;d.provenance=r.provenance;out.diffs.push_back(std::move(d));}
    }
    st.rebuiltByteMismatches=out.diffs.size();
    st.completeOwnership=!program.empty()&&st.ownedAddresses==program.size()&&st.unownedAddresses==0&&st.ownershipConflicts==0;
    st.exactRebuild=st.completeOwnership&&st.sourceByteMismatches==0&&st.rebuiltByteMismatches==0&&out.rebuiltBytes==program;

    // Compact map only where complete source ownership/provenance is identical.
    std::size_t i=0;
    while(i<out.ledger.size()){
        const auto&first=out.ledger[i];std::size_t j=i+1;
        while(j<out.ledger.size()){
            const auto&n=out.ledger[j];
            if(n.ownerKind!=first.ownerKind||n.sourceId!=first.sourceId||n.sourceText!=first.sourceText||n.provenance!=first.provenance)break;
            ++j;
        }
        RomReconstructionReconstructionMapRecord m;m.id=out.map.size();m.start=static_cast<std::uint16_t>(i);m.end=static_cast<std::uint16_t>(j);m.length=j-i;m.ownerKind=first.ownerKind;m.sourceId=first.sourceId;m.sourceText=first.sourceText;m.provenance=first.provenance;out.map.push_back(std::move(m));i=j;
    }
    return out;
}

} // namespace pacripper
