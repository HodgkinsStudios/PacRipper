// PacRipper deterministic ROM rebuilder integrated deterministic ROM rebuilder dataflow
// Created by Jacob Hodgkins

#include "Decompiler.h"

namespace pacripper {

void Decompiler::buildRomRebuilder(){
    romRebuilderRebuildResult_={};
    stats_.romRebuilder={};
    if(!analyzer_)return;
    romRebuilderRebuildResult_=RomRebuilder::rebuildAndVerify(analyzer_->program(),romReconstructionReconstructionLedger_);
    stats_.romRebuilder=romRebuilderRebuildResult_.stats;
}

std::vector<std::string> Decompiler::romRebuilderRebuilderLines() const{
    if(!ready_)return {"Decompiler model not built."};
    return RomRebuilder::reportLines(romRebuilderRebuildResult_);
}

} // namespace pacripper
