// PacRipper def-use analysis integration: def-use, expressions, RAM objects and residual closure
// Created by Jacob Hodgkins

#include "Decompiler.h"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace pacripper {
namespace {
std::string defUseHex16(std::uint16_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(4)<<std::setfill('0')<<(unsigned)v;return o.str();}
std::string defUseAddressSet(const std::set<std::uint16_t>& s){std::ostringstream o;o<<"{";std::size_t n=0;for(auto a:s){if(n++)o<<",";o<<"$"<<defUseHex16(a);}o<<"}";return o.str();}
std::string defUseFactText(const ReachingDefinitionFact& f){std::ostringstream o;o<<"{";std::size_t n=0;if(f.includesEntryValue){o<<"entry";++n;}for(auto id:f.definitionIds){if(n++)o<<",";o<<"def#"<<id;}if(f.includesClobberedUnknown){if(n++)o<<",";o<<"clobbered";}o<<"}";if(!f.unknownSourceAddresses.empty())o<<" unknown-at="<<defUseAddressSet(f.unknownSourceAddresses);return o.str();}
}

void Decompiler::buildDefUse(){
    defUseResult_={};ramObjects_.clear();defUseRomConsumers_.clear();defUseClosureBytes_.clear();defUseUnresolvedPriority_.clear();stats_.defUse={};
    if(!analyzer_)return;

    std::map<std::uint16_t,FunctionEffectInput> effects;
    for(const auto& kv:functionRegisterSummaries_){FunctionEffectInput f;f.functionEntry=kv.first;f.preservedRegisters=kv.second.preserved;if(kv.second.stackBalanced)f.preservedRegisters.insert("SP");f.ramMayWrite=kv.second.transitiveRamMayWrite;f.unknownMemoryWrite=kv.second.transitiveUnknownMemoryWrite;effects[kv.first]=f;}

    std::vector<RomObjectView> objectViews;objectViews.reserve(romObjects_.size());for(const auto& o:romObjects_){RomObjectView v;v.id=o.id;v.start=o.start;v.end=o.end;v.entrySize=o.entrySize;v.dynamicOnly=o.dynamicOnly;objectViews.push_back(v);}

    std::vector<DefUseBlockInput> inputs;inputs.reserve(blocks_.size());
    for(const auto& bk:blocks_){const auto& b=bk.second;if(b.functionOwners.size()!=1)continue;DefUseBlockInput x;x.start=b.start;x.functionEntry=*b.functionOwners.begin();x.instructions=b.instructions;x.staticProof=true;for(auto pc:b.instructions)if(!analyzer_->hasStaticInstructionProof(pc)){x.staticProof=false;break;}for(const auto& e:b.outgoing)if(isStructuralEdge(e.kind)&&e.to>=0)x.successors.insert(static_cast<std::uint16_t>(e.to));inputs.push_back(x);}

    defUseResult_=DefUseAnalysis::analyze(analyzer_->instructions(),inputs,effects,objectViews,analyzer_->program().size());
    ramObjects_=RamObjects::reconstruct(analyzer_->ramUsage(),ramPairEvidence_);
    stats_.defUse.defUse=defUseResult_.stats;stats_.defUse.ramObjects=RamObjects::stats(ramObjects_);stats_.defUse.baselineUnresolvedBytes=stats_.romClosure.unresolvedBytes;

    // def-use analysis closure is a separate overlay so all ROM closure and object/pointer analysis consumer/object facts stay verified and auditable.
    defUseClosureBytes_=romClosureBytes_;
    auto alreadyKnown=[&](std::uint16_t pc,std::uint16_t start,std::uint16_t end){for(const auto& c:romConsumers_)if(!c.dynamic&&c.exact&&c.pc==pc&&c.start<=start&&c.end>=end)return true;for(const auto& c:defUseRomConsumers_)if(c.pc==pc&&c.start==start&&c.end==end)return true;return false;};
    for(const auto& e:defUseResult_.expressions){if(!e.exact||e.operation!=DefExpressionKind::IndirectMemoryRead||!e.memoryAddressKnown)continue;const std::size_t width=e.bits==16?2u:1u;const std::size_t start=e.memoryAddress,end=start+width;if(start>=analyzer_->program().size()||end>analyzer_->program().size())continue;if(alreadyKnown(e.instructionAddress,static_cast<std::uint16_t>(start),static_cast<std::uint16_t>(end)))continue;RomConsumerRecord c;c.pc=e.instructionAddress;c.start=static_cast<std::uint16_t>(start);c.end=static_cast<std::uint16_t>(end);c.kind=RomConsumerKind::IndirectRegisterRead;c.exact=true;c.note="def-use analysis exact def-use/expression chain proves this ROM dereference address; provenance retained in expressions export";defUseRomConsumers_.push_back(c);for(std::size_t a=start;a<end;++a){defUseClosureBytes_[a].staticExactDataUse=true;defUseClosureBytes_[a].consumerPCs.insert(e.instructionAddress);}}
    for(auto& b:defUseClosureBytes_)b.primary=RomClosure::classify(b);
    std::size_t unresolved=0;for(const auto& b:defUseClosureBytes_)if(b.primary==RomClosurePrimary::Unresolved)++unresolved;stats_.defUse.expressionRomConsumers=defUseRomConsumers_.size();stats_.defUse.unresolvedAfterDefUse=unresolved;stats_.defUse.newlyExplainedBytes=stats_.defUse.baselineUnresolvedBytes>unresolved?stats_.defUse.baselineUnresolvedBytes-unresolved:0;
    defUseUnresolvedPriority_=RomObjects::prioritizeUnresolved(defUseClosureBytes_,romObjects_);
}

std::vector<std::string> Decompiler::defUseLines() const{
    std::vector<std::string> o;if(!ready_){o.push_back("Decompiler model not built.");return o;}o.push_back("PacRipper def-use analysis reaching definitions / liveness");o.push_back("Only accepted static, uniquely-owned function CFG edges participate. Dynamic-only flow never proves a def-use edge.");{std::ostringstream s;s<<"Functions/blocks/instructions: "<<stats_.defUse.defUse.analyzedFunctions<<" / "<<stats_.defUse.defUse.analyzedBlocks<<" / "<<stats_.defUse.defUse.analyzedInstructions<<"  definitions="<<stats_.defUse.defUse.definitions<<" uses="<<stats_.defUse.defUse.uses<<" exact-uses="<<stats_.defUse.defUse.exactUses<<" ambiguous-uses="<<stats_.defUse.defUse.ambiguousUses;o.push_back(s.str());}o.push_back("");
    for(const auto& u:defUseResult_.uses){std::ostringstream s;s<<"$"<<defUseHex16(u.instructionAddress)<<" uses "<<u.entity<<" <- "<<defUseFactText(u.reaching);o.push_back(s.str());}
    o.push_back("");o.push_back("Liveness (tracked registers + exact RAM cells):");for(const auto& kv:defUseResult_.liveness){std::ostringstream s;s<<"$"<<defUseHex16(kv.first)<<" before={";std::size_t n=0;for(const auto& x:kv.second.liveBefore){if(n++)s<<",";s<<x;}s<<"} after={";n=0;for(const auto& x:kv.second.liveAfter){if(n++)s<<",";s<<x;}s<<"}";o.push_back(s.str());}return o;
}

std::vector<std::string> Decompiler::expressionLines() const{
    std::vector<std::string> o;if(!ready_){o.push_back("Decompiler model not built.");return o;}o.push_back("PacRipper def-use analysis provenance-backed expressions");o.push_back("Ambiguous merges and clobbers remain explicit; expression prettiness never overrides proof.");{std::ostringstream s;s<<"Expressions: "<<defUseResult_.expressions.size()<<"  exact="<<stats_.defUse.defUse.exactExpressions<<" ambiguous="<<stats_.defUse.defUse.ambiguousExpressions<<" object-aware="<<stats_.defUse.defUse.objectAwareExpressions;o.push_back(s.str());}o.push_back("");for(const auto& e:defUseResult_.expressions){std::ostringstream s;s<<"def#"<<e.definitionId<<" @$"<<defUseHex16(e.instructionAddress)<<" "<<e.entity<<" = "<<e.text<<"  ["<<(e.exact?"exact":e.ambiguous?"ambiguous":"fallback")<<"]";if(e.objectAware){s<<" objects={";std::size_t n=0;for(auto id:e.romObjectIds){if(n++)s<<",";s<<"obj#"<<id;}s<<"}";}o.push_back(s.str());std::ostringstream p;p<<"  op="<<DefUseAnalysis::expressionKindText(e.operation)<<" provenance="<<defUseAddressSet(e.provenance);if(e.memoryAddressKnown)p<<" deref=$"<<defUseHex16(e.memoryAddress);if(!e.note.empty())p<<"  "<<e.note;o.push_back(p.str());}return o;
}

std::vector<std::string> Decompiler::ramObjectLines() const{
    std::vector<std::string> o;if(!ready_){o.push_back("Decompiler model not built.");return o;}o.push_back("PacRipper def-use analysis RAM field/object evidence");o.push_back("Adjacency alone is never used as grouping proof. Direct 16-bit Z80 accesses prove word fields; isolated exact addresses remain byte fields.");{std::ostringstream s;s<<"Objects="<<stats_.defUse.ramObjects.objects<<" byte="<<stats_.defUse.ramObjects.byteFields<<" word="<<stats_.defUse.ramObjects.wordFields<<" static="<<stats_.defUse.ramObjects.staticObjects<<" dynamic-only="<<stats_.defUse.ramObjects.dynamicOnlyObjects;o.push_back(s.str());}o.push_back("");for(const auto& r:ramObjects_){std::ostringstream s;s<<"ramobj#"<<r.id<<" $"<<defUseHex16(r.start)<<"-$"<<defUseHex16(static_cast<std::uint16_t>(r.end-1))<<" "<<RamObjects::kindText(r.kind)<<" ["<<(r.dynamicOnly?"dynamic-only":r.staticProof?"static-proof":"observational")<<"]";if(r.pointerLike)s<<" pointer-like";o.push_back(s.str());std::ostringstream q;q<<"  access="<<(r.read?"R":"")<<(r.write?"W":"")<<" xrefs="<<defUseAddressSet(r.sourcePCs);if(!r.overlappingObjectIds.empty()){q<<" overlaps={";std::size_t n=0;for(auto id:r.overlappingObjectIds){if(n++)q<<",";q<<"ramobj#"<<id;}q<<"}";}o.push_back(q.str());o.push_back("  "+r.note);}return o;
}

std::vector<std::string> Decompiler::xrefLines() const{
    std::vector<std::string> o;if(!ready_){o.push_back("Decompiler model not built.");return o;}o.push_back("PacRipper def-use analysis def-use / ROM-object / RAM-object xrefs");o.push_back("");o.push_back("ROM object expression references:");for(const auto& e:defUseResult_.expressions)if(!e.romObjectIds.empty()){std::ostringstream s;s<<"$"<<defUseHex16(e.instructionAddress)<<" "<<e.entity<<" -> ";std::size_t n=0;for(auto id:e.romObjectIds){if(n++)s<<",";s<<"obj#"<<id;}s<<" via "<<e.text;o.push_back(s.str());}o.push_back("");o.push_back("New exact ROM consumers from def-use analysis expression chains:");for(const auto& c:defUseRomConsumers_){std::ostringstream s;s<<"$"<<defUseHex16(c.pc)<<" -> $"<<defUseHex16(c.start)<<"-$"<<defUseHex16(static_cast<std::uint16_t>(c.end-1))<<"  "<<c.note;o.push_back(s.str());}o.push_back("");o.push_back("RAM object xrefs:");for(const auto& r:ramObjects_){std::ostringstream s;s<<"ramobj#"<<r.id<<" $"<<defUseHex16(r.start)<<" xrefs="<<defUseAddressSet(r.sourcePCs);o.push_back(s.str());}o.push_back("");{std::ostringstream s;s<<"Residual closure: baseline unresolved="<<stats_.defUse.baselineUnresolvedBytes<<"  after def-use analysis="<<stats_.defUse.unresolvedAfterDefUse<<"  newly explained="<<stats_.defUse.newlyExplainedBytes;o.push_back(s.str());}o.push_back("Prioritized residual unresolved spans after def-use analysis:");std::size_t shown=0;for(const auto& r:defUseUnresolvedPriority_){if(shown++>=32)break;std::ostringstream s;s<<"$"<<defUseHex16(r.start)<<"-$"<<defUseHex16(static_cast<std::uint16_t>(r.end-1))<<" len="<<r.length<<" nearby-objects="<<r.nearbyObjectCount<<" nearby-consumers="<<r.nearbyConsumerCount<<"  "<<r.reason;o.push_back(s.str());}return o;
}

} // namespace pacripper
