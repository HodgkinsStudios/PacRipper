// PacRipper exact ROM reconstruction deterministic bit-exact ROM reconstruction proof
// Created by Jacob Hodgkins

#include "Decompiler.h"

#include <sstream>
#include <utility>

namespace pacripper {

void Decompiler::buildRomReconstruction(){
    romReconstructionReconstructionLedger_.clear();
    romReconstructionReconstructionMap_.clear();
    romReconstructionBinaryDiff_.clear();
    romReconstructionRebuiltBytes_.clear();
    stats_.romReconstruction={};
    if(!analyzer_) return;

    auto result=ExactRomReconstruction::build(
        analyzer_->program(),reconciliationCanonicalInstructions_,systemRootInlineData_,
        canonicalClosureCanonicalDataObjects_,canonicalClosureNegativeClosure_,canonicalClosureClosureBytes_);
    romReconstructionReconstructionLedger_=std::move(result.ledger);
    romReconstructionReconstructionMap_=std::move(result.map);
    romReconstructionBinaryDiff_=std::move(result.diffs);
    romReconstructionRebuiltBytes_=std::move(result.rebuiltBytes);
    stats_.romReconstruction=result.stats;
}

std::vector<std::string> Decompiler::romReconstructionReconstructionLines() const{
    if(!ready_) return {"Decompiler model not built."};
    const auto& s=stats_.romReconstruction;
    std::vector<std::string> out;
    out.push_back("PacRipper exact ROM reconstruction bit-exact reconstruction proof");
    out.push_back("ledger ownership="+std::to_string(s.ownedAddresses)+" / "+std::to_string(s.romBytes)+
                  " unowned="+std::to_string(s.unownedAddresses)+" conflicts="+std::to_string(s.ownershipConflicts));
    out.push_back("owner bytes: code="+std::to_string(s.canonicalInstructionBytes)+
                  " inline="+std::to_string(s.inlinePayloadBytes)+
                  " canonical-data="+std::to_string(s.canonicalDataObjectBytes)+
                  " classified-data="+std::to_string(s.classifiedDataBytes)+
                  " proven-unused="+std::to_string(s.provenUnusedBytes));
    out.push_back("source-byte mismatches="+std::to_string(s.sourceByteMismatches)+
                  " rebuilt-byte mismatches="+std::to_string(s.rebuiltByteMismatches)+
                  " complete="+(s.completeOwnership?std::string("yes"):std::string("no"))+
                  " exact-rebuild="+(s.exactRebuild?std::string("yes"):std::string("no")));
    return out;
}

} // namespace pacripper
