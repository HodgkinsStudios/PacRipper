// PacRipper release-input export implementation.
// Created by Jacob Hodgkins
//
// This is intentionally limited to the exact Reconciliation/30/31 artifacts consumed by
// the certified complete-board release generator. It keeps PacRipper independent
// from PacRipper's later native-runtime research passes. The final readable
// program/pacman.asm is now the sole assembly/reconstruction source.
#include "Decompiler.h"

#include <algorithm>
#include <cerrno>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>

namespace pacripper {
namespace {
std::string hex8(std::uint8_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(2)<<std::setfill('0')<<(unsigned)v;return o.str();}
std::string hex16(std::uint16_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(4)<<std::setfill('0')<<(unsigned)v;return o.str();}
bool ensureDir(const std::string& p){struct stat st{};if(stat(p.c_str(),&st)==0)return S_ISDIR(st.st_mode);return mkdir(p.c_str(),0755)==0||errno==EEXIST;}
std::string jsonEscape(const std::string& s){std::ostringstream o;for(char c:s){switch(c){case '\\':o<<"\\\\";break;case '"':o<<"\\\"";break;case '\n':o<<"\\n";break;case '\r':o<<"\\r";break;case '\t':o<<"\\t";break;default:if(static_cast<unsigned char>(c)<32)o<<"?";else o<<c;}}return o.str();}
std::string csvBytes(const std::vector<std::uint8_t>&v){std::ostringstream o;for(std::size_t i=0;i<v.size();++i){if(i)o<<" ";o<<hex8(v[i]);}return o.str();}
std::string joinSizesCsv(const std::set<std::size_t>&v){std::ostringstream o;std::size_t n=0;for(auto x:v){if(n++)o<<"|";o<<x;}return o.str();}
}

bool Decompiler::exportAll(const std::string& dir,std::string& error) const {
    if(!ready_){error="Decompiler model not built.";return false;}
    if(!ensureDir(dir)){error="Unable to create/open export directory.";return false;}

    std::ofstream reconciledInstructionsCsv((dir+"/reconciled_instructions.csv").c_str());if(!reconciledInstructionsCsv){error="Failed writing reconciled_instructions.csv";return false;}
    reconciledInstructionsCsv<<"id,pc,length,bytes,mnemonic,operands,analyzer_root,system_root_reachable,semantic_oracle_verified,semantic_oracle_source_bytes_match,system_root_reachability_ids,semantic_oracle_operation_ids,note\n";
    for(const auto&r:reconciliationCanonicalInstructions_)reconciledInstructionsCsv<<r.id<<",$"<<hex16(r.pc)<<","<<r.length<<",\""<<csvBytes(r.bytes)<<"\",\""<<jsonEscape(r.mnemonic)<<"\",\""<<jsonEscape(r.operands)<<"\","<<(r.analyzerRoot?1:0)<<","<<(r.systemRootReachable?1:0)<<","<<(r.semanticOracleSemanticallyVerified?1:0)<<","<<(r.semanticOracleSourceBytesMatch?1:0)<<",\""<<joinSizesCsv(r.systemRootReachabilityIds)<<"\",\""<<joinSizesCsv(r.semanticOracleOperationIds)<<"\",\""<<jsonEscape(r.note)<<"\"\n";
    if(!reconciledInstructionsCsv){error="Failed while writing reconciled_instructions.csv";return false;}

    std::ofstream canonicalDataCsv((dir+"/canonical_data_objects.csv").c_str());if(!canonicalDataCsv){error="Failed writing canonical_data_objects.csv";return false;}
    canonicalDataCsv<<"id,name,start,end_exclusive,length,root_pcs,consumer_pcs,source_shape_proven,accepted,note\n";
    for(const auto&r:canonicalClosureCanonicalDataObjects_)canonicalDataCsv<<r.id<<",\""<<jsonEscape(r.name)<<"\",$"<<hex16(r.start)<<",$"<<hex16(r.end)<<","<<(r.end-r.start)<<",\""<<addressSetText(r.rootPCs)<<"\",\""<<addressSetText(r.consumerPCs)<<"\","<<(r.sourceShapeProven?1:0)<<","<<(r.accepted?1:0)<<",\""<<jsonEscape(r.note)<<"\"\n";
    if(!canonicalDataCsv){error="Failed while writing canonical_data_objects.csv";return false;}

    std::ofstream reconstructionLedgerCsv((dir+"/rom_reconstruction_ledger.csv").c_str());if(!reconstructionLedgerCsv){error="Failed writing rom_reconstruction_ledger.csv";return false;}
    reconstructionLedgerCsv<<"address,expected_byte,emitted_byte,owned,owner_kind,source_id,source_start,source_end_exclusive,source_pc,source_offset,closure_primary,source_text,provenance\n";
    for(const auto&r:romReconstructionReconstructionLedger_){
        reconstructionLedgerCsv<<"$"<<hex16(r.address)<<",$"<<hex8(r.expectedByte)<<",$"<<hex8(r.emittedByte)<<","<<(r.owned?1:0)<<",\""<<ExactRomReconstruction::ownerKindText(r.ownerKind)<<"\",";
        if(r.sourceId!=static_cast<std::size_t>(-1)){reconstructionLedgerCsv<<r.sourceId;}
        reconstructionLedgerCsv<<",$"<<hex16(r.sourceStart)<<",$"<<hex16(r.sourceEnd)<<",";
        if(r.sourcePc>=0)reconstructionLedgerCsv<<"$"<<hex16(static_cast<std::uint16_t>(r.sourcePc));
        reconstructionLedgerCsv<<","<<r.sourceOffset<<",\""<<jsonEscape(RomClosure::primaryText(r.closurePrimary))<<"\",\""<<jsonEscape(r.sourceText)<<"\",\""<<jsonEscape(r.provenance)<<"\"\n";
    }
    if(!reconstructionLedgerCsv){error="Failed while writing rom_reconstruction_ledger.csv";return false;}

    std::ofstream reconstructionMapCsv((dir+"/rom_reconstruction_map.csv").c_str());if(!reconstructionMapCsv){error="Failed writing rom_reconstruction_map.csv";return false;}
    reconstructionMapCsv<<"id,start,end_exclusive,length,owner_kind,source_id,source_text,provenance\n";
    for(const auto&r:romReconstructionReconstructionMap_){
        reconstructionMapCsv<<r.id<<",$"<<hex16(r.start)<<",$"<<hex16(r.end)<<","<<r.length<<",\""<<ExactRomReconstruction::ownerKindText(r.ownerKind)<<"\",";
        if(r.sourceId!=static_cast<std::size_t>(-1)){reconstructionMapCsv<<r.sourceId;}
        reconstructionMapCsv<<",\""<<jsonEscape(r.sourceText)<<"\",\""<<jsonEscape(r.provenance)<<"\"\n";
    }
    if(!reconstructionMapCsv){error="Failed while writing rom_reconstruction_map.csv";return false;}

    std::ofstream rebuildVerificationFile((dir+"/rom_rebuild_verification.txt").c_str());
    if(!rebuildVerificationFile){error="Failed writing rom_rebuild_verification.txt";return false;}
    rebuildVerificationFile<<"PacRipper exact ROM reconstruction internal deterministic reconstruction verification\n"
        <<"rom_bytes="<<stats_.romReconstruction.romBytes<<"\n"
        <<"ledger_records="<<stats_.romReconstruction.ledgerRecords<<"\n"
        <<"owned_addresses="<<stats_.romReconstruction.ownedAddresses<<"\n"
        <<"unowned_addresses="<<stats_.romReconstruction.unownedAddresses<<"\n"
        <<"ownership_conflicts="<<stats_.romReconstruction.ownershipConflicts<<"\n"
        <<"source_byte_mismatches="<<stats_.romReconstruction.sourceByteMismatches<<"\n"
        <<"rebuilt_byte_mismatches="<<stats_.romReconstruction.rebuiltByteMismatches<<"\n"
        <<"complete_ownership="<<(stats_.romReconstruction.completeOwnership?"yes":"no")<<"\n"
        <<"exact_rebuild="<<(stats_.romReconstruction.exactRebuild?"yes":"no")<<"\n"
        <<"note=SHA-256 equality is verified independently outside this export using the ledger-only rebuild script.\n";
    if(!rebuildVerificationFile){error="Failed while writing rom_rebuild_verification.txt";return false;}

    error.clear();
    return true;
}

} // namespace pacripper
