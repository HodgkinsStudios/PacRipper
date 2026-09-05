// PacRipper semantic-oracle analysis complete semantic lift/oracle/generated-source overlay
// Created by Jacob Hodgkins

#include "Decompiler.h"

#include <iomanip>
#include <sstream>

namespace pacripper {
namespace {
std::string hex16p27(std::uint16_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(4)<<std::setfill('0')<<(unsigned)v;return o.str();}
std::string bytes27(const std::vector<std::uint8_t>&v){std::ostringstream o;for(std::size_t i=0;i<v.size();++i){if(i)o<<' ';o<<std::uppercase<<std::hex<<std::setw(2)<<std::setfill('0')<<(unsigned)v[i];}return o.str();}
}

void Decompiler::buildSemanticOracle(){
    stats_.semanticOracle={};
    SemanticOracleEngine::liftFromSemanticLift(semanticLiftLiftedOperations_,semanticLiftLiftedBlocks_,semanticOracleLiftedOperations_,semanticOracleLiftedBlocks_,stats_.semanticOracle);
    semanticOracleOracleRecords_=SemanticOracleEngine::verifyWithIndependentOracle(analyzer_->program(),semanticOracleLiftedOperations_,semanticOracleLiftedBlocks_,stats_.semanticOracle,3);
    semanticOracleGeneratedSourceMap_=SemanticOracleEngine::buildGeneratedSourceMap(semanticOracleLiftedOperations_);
    stats_.semanticOracle.generatedBlocks=semanticOracleLiftedBlocks_.size();
    stats_.semanticOracle.generatedOperations=semanticOracleLiftedOperations_.size();
    stats_.semanticOracle.generatedSourceMapRecords=semanticOracleGeneratedSourceMap_.size();
    stats_.semanticOracle.generatedCorpusDeterministic=true;
}

std::vector<std::string> Decompiler::semanticOracleSemanticCoverageLines() const{
    std::vector<std::string> out;
    std::ostringstream s;s<<"semantic-oracle analysis semantic coverage: rooted="<<stats_.semanticOracle.rootedCodeInstructions
        <<" lifted="<<stats_.semanticOracle.mechanicallyLiftedInstructions
        <<" unsupported="<<stats_.semanticOracle.unsupportedInstructionSemantics
        <<" blocks="<<stats_.semanticOracle.liftedBlocks
        <<" fully_supported="<<stats_.semanticOracle.fullySupportedBlocks
        <<" complete="<<(stats_.semanticOracle.completeRootedSemanticCoverage?"yes":"no");out.push_back(s.str());
    for(const auto&o:semanticOracleLiftedOperations_)if(o.extension!=SemanticOracleExtensionKind::None||!o.supported){std::ostringstream r;r<<o.stableId<<" pc=$"<<hex16p27(o.sourcePC)<<" bytes=["<<bytes27(o.bytes)<<"] semantic="<<SemanticOracleEngine::semanticKindText(o)<<" supported="<<(o.supported?"yes":"no")<<" note="<<o.note;out.push_back(r.str());}
    return out;
}

std::vector<std::string> Decompiler::semanticOracleOracleLines() const{
    std::vector<std::string> out;std::ostringstream s;s<<"semantic-oracle analysis independent oracle: verified_blocks="<<stats_.semanticOracle.independentlyVerifiedBlocks<<" mismatches="<<stats_.semanticOracle.independentOracleMismatches<<" snapshots="<<stats_.semanticOracle.independentOracleSnapshots<<" operations="<<stats_.semanticOracle.independentOracleOperations;out.push_back(s.str());
    for(const auto&r:semanticOracleOracleRecords_){std::ostringstream q;q<<r.blockId<<" start=$"<<hex16p27(r.blockStart)<<" supported="<<(r.supported?"yes":"no")<<" accepted="<<(r.accepted?"yes":"no")<<" snapshots="<<r.snapshots<<" operations="<<r.operationsCompared;if(r.firstDivergencePC!=0xFFFF)q<<" first_divergence=$"<<hex16p27(r.firstDivergencePC)<<" bytes=["<<bytes27(r.firstDivergenceBytes)<<"]";q<<" diagnostic="<<r.diagnostic;out.push_back(q.str());}
    return out;
}

std::vector<std::string> Decompiler::semanticOracleGeneratedSourceMapLines() const{
    std::vector<std::string> out;std::ostringstream s;s<<"semantic-oracle analysis generated C++ source map: blocks="<<stats_.semanticOracle.generatedBlocks<<" operations="<<stats_.semanticOracle.generatedOperations<<" records="<<stats_.semanticOracle.generatedSourceMapRecords;out.push_back(s.str());
    for(const auto&r:semanticOracleGeneratedSourceMap_){std::ostringstream q;q<<r.operationId<<" block="<<r.blockId<<" pc=$"<<hex16p27(r.sourcePC)<<" fallthrough=$"<<hex16p27(r.fallthroughPC)<<" semantic="<<r.semanticKind<<" bytes=["<<bytes27(r.bytes)<<"] function="<<r.generatedFunction;out.push_back(q.str());}
    return out;
}

} // namespace pacripper
