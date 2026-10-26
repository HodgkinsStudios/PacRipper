// Created by Jacob Hodgkins
#include "Analyzer.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>

namespace pacripper {
namespace {

std::string hexByte(std::uint8_t v) {
    std::ostringstream o; o<<std::uppercase<<std::hex<<std::setw(2)<<std::setfill('0')<<(unsigned)v; return o.str();
}
std::string hexWord(std::uint16_t v) {
    std::ostringstream o; o<<std::uppercase<<std::hex<<std::setw(4)<<std::setfill('0')<<(unsigned)v; return o.str();
}
bool ensureDir(const std::string& path) {
    if (path.empty()) return false;
    std::error_code ec;
    const std::filesystem::path dir(path);
    if (std::filesystem::is_directory(dir, ec)) return true;
    ec.clear();
    return std::filesystem::create_directories(dir, ec) ||
           (!ec && std::filesystem::is_directory(dir));
}
std::string accessName(RefAccess a) {
    switch(a) { case RefAccess::Read:return "read"; case RefAccess::Write:return "write"; case RefAccess::ReadWrite:return "read/write"; default:return "address"; }
}
void pushUnique(std::vector<std::uint16_t>& v, std::uint16_t x) {
    if(std::find(v.begin(),v.end(),x)==v.end()) v.push_back(x);
}
std::uint16_t readWord(const std::vector<std::uint8_t>& p, std::size_t a) {
    return static_cast<std::uint16_t>(p[a] | (static_cast<std::uint16_t>(p[a+1])<<8));
}

} // namespace

void Analyzer::clear() {
    ready_=false; sourcePath_.clear(); program_.clear(); instructions_.clear(); codeBytes_.clear(); dataBytes_.clear();
    labels_.clear(); entries_.clear(); codeXrefs_.clear(); indirectCodeXrefs_.clear(); memoryXrefs_.clear();
    dispatchTables_.clear(); dataRegions_.clear(); instructionEvidence_.clear(); unresolvedIndirectSites_.clear();
    traceSources_.clear(); dynamicSeedAddresses_.clear(); traceDiscoveredInstructionAddresses_.clear(); romDataUsage_.clear(); ramUsage_.clear(); boardUsage_.clear(); dynamicFlowEdges_.clear(); bulkRomScanPCs_.clear(); dataCandidates_.clear();
    classificationConflictsCount_=0; dynamicNewInstructionsCount_=0; traceMemoryReadEvents_=0; traceMemoryWriteEvents_=0;
    attributedMemoryEvents_=0; stats_={}; validation_.clear(); irqEntry_=0xFFFF; symbols_.clear();
}


bool Analyzer::loadSymbols(const std::string& path, std::string& error) {
    if(!symbols_.load(path,error)) return false;
    if(ready_) rebuildDerivedState();
    return true;
}

bool Analyzer::saveSymbols(const std::string& path, std::string& error) const {
    return symbols_.save(path,error);
}

bool Analyzer::setSymbol(std::uint16_t address,const std::string& name,const std::string& comment,std::string& error) {
    if(!symbols_.set(address,name,comment,error)) return false;
    if(ready_) rebuildDerivedState();
    return true;
}

std::string Analyzer::symbolFor(std::uint16_t address) const {
    if(const auto* s=symbols_.find(address)) return s->name;
    if(address<0x4000) return labelFor(address);
    const auto it=ramUsage_.find(address);
    if(it!=ramUsage_.end()) return it->second.symbol;
    return defaultRamSymbol(address);
}

bool Analyzer::analyze(const RomSet& set, std::string& error) {
    clear();
    if (!set.loaded()) { error="No ROM set loaded."; return false; }
    RomVariant variant = RomVariant::Unknown;
    if (!set.validateSupportedPacmanFamily(error, &variant)) return false;
    program_=set.assembledProgramROM();
    if (program_.size()!=0x4000) { error="Failed to assemble the four 4 KB Pac-Man program ROMs."; return false; }
    sourcePath_=set.sourcePath();
    validation_=set.validationItems();
    codeBytes_.assign(program_.size(),false);
    dataBytes_.assign(program_.size(),DataKind::None);

    const std::uint16_t seeds[] = {0x0000,0x0008,0x0010,0x0018,0x0020,0x0028,0x0030,0x0038};
    std::vector<WorkItem> work;
    for (auto s:seeds) {
        entries_.insert(s); labels_.insert(s);
        work.push_back({s,static_cast<std::uint8_t>(EvidenceKind::VectorSeed)});
    }

    if(program_.size()>0x3FFB) {
        irqEntry_=readWord(program_,0x3FFA);
        if(irqEntry_<program_.size()) {
            entries_.insert(irqEntry_); labels_.insert(irqEntry_);
            work.push_back({irqEntry_,static_cast<std::uint8_t>(EvidenceKind::VectorSeed)});
        }
    }

    while(!work.empty()) {
        const WorkItem item=work.back(); work.pop_back();
        traceFrom(item.address,item.evidence,work);
    }

    rebuildDerivedState();
    ready_=true; error.clear(); return true;
}

bool Analyzer::isPhysicalRamAddress(std::uint16_t a) const {
    return (a>=0x4000 && a<=0x47FF) || (a>=0x4C00 && a<=0x4FFF);
}

std::string Analyzer::ramRegionName(std::uint16_t a) const {
    if(a>=0x4000 && a<=0x43FF) return "video RAM";
    if(a>=0x4400 && a<=0x47FF) return "color RAM";
    if(a>=0x4C00 && a<=0x4FEF) return "work RAM";
    if(a>=0x4FF0 && a<=0x4FFF) return "sprite RAM";
    return "";
}

std::string Analyzer::defaultRamSymbol(std::uint16_t a) const {
    if(const auto* user=symbols_.find(a)) return user->name;
    if(a>=0x4000 && a<=0x43FF) return "vram_"+hexWord(a);
    if(a>=0x4400 && a<=0x47FF) return "cram_"+hexWord(a);
    if(a>=0x4FF0 && a<=0x4FFF) return "sprite_ram_"+hexWord(a);
    if(a>=0x4C00 && a<=0x4FEF) return "ram_"+hexWord(a);
    return "mem_"+hexWord(a);
}

std::string Analyzer::observedAccessClass(const RamAddressUsage& u) const {
    const bool read=(u.dynamicReads!=0) || !u.staticReaders.empty();
    const bool write=(u.dynamicWrites!=0) || !u.staticWriters.empty();
    if(read && write) return "read/write";
    if(read) return "read-only observed";
    if(write) return "write-only observed";
    if(!u.staticAddressRefs.empty()) return "address-reference only";
    return "unclassified access";
}

std::string Analyzer::observedValueProfile(const RamAddressUsage& u) const {
    std::set<std::uint8_t> values=u.readValues;
    values.insert(u.writeValues.begin(),u.writeValues.end());
    if(values.empty()) return "no dynamic values";
    if(values.size()==1) return "constant in observed trace";
    bool boolLike=true;
    for(const auto v:values) if(v!=0x00 && v!=0x01) { boolLike=false; break; }
    if(boolLike) return "flag-like observed values";
    const unsigned lo=*values.begin(), hi=*values.rbegin();
    if(values.size()<=16 && hi-lo<=0x0F) return "small-range observed values";
    if(values.size()<=8) return "small state-set observed values";
    return "general byte-state observed values";
}

void Analyzer::rebuildStaticRamUsage() {
    for(auto& kv:ramUsage_) {
        kv.second.symbol=defaultRamSymbol(kv.first);
        kv.second.staticReaders.clear();
        kv.second.staticWriters.clear();
        kv.second.staticAddressRefs.clear();
    }
    for(const auto& kv:instructions_) {
        const Instruction& in=kv.second;
        for(const auto& mr:in.memoryRefs) {
            if(!isPhysicalRamAddress(mr.address)) continue;
            RamAddressUsage& u=ramUsage_[mr.address];
            u.address=mr.address; u.region=ramRegionName(mr.address); u.symbol=defaultRamSymbol(mr.address);
            switch(mr.access) {
                case RefAccess::Read: u.staticReaders.insert(in.address); break;
                case RefAccess::Write: u.staticWriters.insert(in.address); break;
                case RefAccess::ReadWrite: u.staticReaders.insert(in.address); u.staticWriters.insert(in.address); break;
                case RefAccess::Address: u.staticAddressRefs.insert(in.address); break;
            }
        }
    }
}

void Analyzer::rebuildDataCandidates() {
    dataCandidates_.clear();
    bulkRomScanPCs_.clear();
    if(program_.empty()) return;

    auto collectImmediatePointerRefs=[&](std::uint16_t start,std::uint16_t end,bool exactStartOnly) {
        std::set<std::uint16_t> refs;
        for(const auto& kv:instructions_) {
            const Instruction& in=kv.second;
            std::uint16_t imm=0; bool has=false;
            // LD BC/DE/HL,nn
            if(in.bytes.size()>=3 && (in.bytes[0]==0x01 || in.bytes[0]==0x11 || in.bytes[0]==0x21)) {
                imm=static_cast<std::uint16_t>(in.bytes[1] | (static_cast<std::uint16_t>(in.bytes[2])<<8)); has=true;
            }
            // LD IX/IY,nn
            else if(in.bytes.size()>=4 && (in.bytes[0]==0xDD || in.bytes[0]==0xFD) && in.bytes[1]==0x21) {
                imm=static_cast<std::uint16_t>(in.bytes[2] | (static_cast<std::uint16_t>(in.bytes[3])<<8)); has=true;
            }
            if(!has) continue;
            if(exactStartOnly ? (imm==start) : (imm>=start && imm<end)) refs.insert(in.address);
        }
        return refs;
    };

    // ROM self-test/checksum loops can deliberately scan huge portions of the
    // program ROM as raw data. Preserve those observations, but do not let a
    // bulk scan manufacture thousands of false lookup-table candidates.
    std::map<std::uint16_t,std::size_t> perReaderAddresses;
    for(const auto& kv:romDataUsage_) for(auto pc:kv.second.sourcePCs) ++perReaderAddresses[pc];
    for(const auto& kv:perReaderAddresses) if(kv.second>=512) bulkRomScanPCs_.insert(kv.first);

    // Strong static candidate: three or more consecutive little-endian words
    // that all point to already-proven control-flow labels/entries. This is kept
    // as a candidate rather than hard data so a later execution trace can still
    // prove dual-use bytes without a classification conflict.
    std::size_t a=0;
    while(a+5<program_.size()) {
        if(codeBytes_[a] || dataBytes_[a]!=DataKind::None) { ++a; continue; }
        std::size_t count=0;
        std::set<std::uint16_t> uniqueTargets;
        while(a+(count+1)*2<=program_.size()) {
            const std::size_t p=a+count*2;
            if(p+1>=program_.size() || codeBytes_[p] || codeBytes_[p+1] ||
               dataBytes_[p]!=DataKind::None || dataBytes_[p+1]!=DataKind::None) break;
            const std::uint16_t t=readWord(program_,p);
            if(t<0x0040 || t>=program_.size() || instructions_.find(t)==instructions_.end()) break;
            if(labels_.count(t)==0 && codeXrefs_.count(t)==0 && entries_.count(t)==0) break;
            uniqueTargets.insert(t); ++count;
        }
        if(count>=3 && uniqueTargets.size()>=3 && uniqueTargets.size()*4>=count) {
            DataCandidate c;
            c.start=static_cast<std::uint16_t>(a);
            c.end=static_cast<std::uint16_t>(a+count*2);
            c.kind=CandidateKind::GeneralPointerTable;
            c.confidence=static_cast<unsigned>(std::min<std::size_t>(82,66+count*2));
            c.staticRefPCs=collectImmediatePointerRefs(c.start,c.end,true);
            for(std::size_t p=a;p<a+count*2;++p) {
                const auto r=romDataUsage_.find(static_cast<std::uint16_t>(p));
                if(r!=romDataUsage_.end()) {
                    bool semantic=false;
                    for(const auto pc:r->second.sourcePCs) if(!bulkRomScanPCs_.count(pc)) { c.sourcePCs.insert(pc); semantic=true; }
                    if(semantic) c.observedReadEvents+=r->second.readEvents;
                }
            }
            if(!c.staticRefPCs.empty()) c.confidence=std::min(96u,c.confidence+8u);
            if(c.observedReadEvents) c.confidence=std::min(96u,c.confidence+10u);
            c.reason="consecutive little-endian pointers to proven code labels";
            if(!c.staticRefPCs.empty()) c.reason+="; code loads this exact table start into a pointer register";
            if(c.observedReadEvents) c.reason+="; also observed as ROM data";
            dataCandidates_.push_back(c);
            a+=count*2;
            continue;
        }
        ++a;
    }

    // Dynamic ROM data regions are factual observations. Candidate *type* is
    // heuristic and deliberately separate from the hard code/data map.
    std::vector<std::uint16_t> observed;
    for(const auto& kv:romDataUsage_) {
        const std::uint16_t p=kv.first;
        bool semanticReader=false;
        for(auto pc:kv.second.sourcePCs) if(!bulkRomScanPCs_.count(pc)) { semanticReader=true; break; }
        if(semanticReader && p<program_.size() && !codeBytes_[p] && dataBytes_[p]==DataKind::None) observed.push_back(p);
    }
    std::size_t i=0;
    while(i<observed.size()) {
        std::size_t j=i+1;
        while(j<observed.size() && observed[j]==static_cast<std::uint16_t>(observed[j-1]+1)) ++j;
        const std::uint16_t start=observed[i];
        const std::uint16_t end=static_cast<std::uint16_t>(observed[j-1]+1);
        const std::size_t len=static_cast<std::size_t>(end-start);
        bool overlapsPointer=false;
        for(const auto& c:dataCandidates_) if(c.kind==CandidateKind::GeneralPointerTable && start<c.end && end>c.start) { overlapsPointer=true; break; }
        if(len>=2 && !overlapsPointer) {
            DataCandidate c; c.start=start; c.end=end; c.kind=CandidateKind::ByteLookupTable; c.confidence=60;
            c.staticRefPCs=collectImmediatePointerRefs(start,end,false);
            std::size_t textish=0, low5Even=0, low5Odd=0, pairShared=0, pairs=0;
            std::uint8_t evenMin=0xFF,evenMax=0,oddMin=0xFF,oddMax=0;
            std::set<std::uint8_t> unique;
            for(std::uint16_t p=start;p<end;++p) {
                const std::uint8_t v=program_[p]; unique.insert(v);
                if((v>=0x40 && v<=0x5A) || v==0x2F || v==0x3A || v==0x8F || v==0x00) ++textish;
                const auto r=romDataUsage_.find(p);
                if(r!=romDataUsage_.end()) {
                    bool semantic=false;
                    for(auto pc:r->second.sourcePCs) if(!bulkRomScanPCs_.count(pc)) { c.sourcePCs.insert(pc); semantic=true; }
                    if(semantic) c.observedReadEvents+=r->second.readEvents;
                }
            }
            if((len%2)==0) {
                for(std::size_t n=0;n<len;n+=2) {
                    ++pairs;
                    const std::uint8_t even=program_[start+n], odd=program_[start+n+1];
                    if(even<=0x3F) ++low5Even;
                    if(odd<=0x3F) ++low5Odd;
                    evenMin=std::min(evenMin,even); evenMax=std::max(evenMax,even);
                    oddMin=std::min(oddMin,odd); oddMax=std::max(oddMax,odd);
                    const auto r0=romDataUsage_.find(static_cast<std::uint16_t>(start+n));
                    const auto r1=romDataUsage_.find(static_cast<std::uint16_t>(start+n+1));
                    if(r0!=romDataUsage_.end() && r1!=romDataUsage_.end()) {
                        bool shared=false;
                        for(auto pc:r0->second.sourcePCs) if(!bulkRomScanPCs_.count(pc) && r1->second.sourcePCs.count(pc)){shared=true;break;}
                        if(shared) ++pairShared;
                    }
                }
            }
            if(len>=6 && unique.size()>=3 && textish*100>=len*70) {
                c.kind=CandidateKind::TileTextStream; c.confidence=78;
                c.reason="dynamically read ROM stream dominated by Pac-Man-like tile/character codes and separators/terminators (heuristic)";
            } else if(pairs>=3 && pairShared*100>=pairs*70 &&
                      ((low5Even*100>=pairs*70 && low5Odd*100>=pairs*70) ||
                       (static_cast<unsigned>(evenMax)-evenMin<=0x3F && static_cast<unsigned>(oddMax)-oddMin<=0x3F))) {
                c.kind=CandidateKind::CoordinatePairTable; c.confidence=45;
                c.reason="dynamically read even-length byte pairs with shared readers and coordinate-scale axis ranges (heuristic)";
            } else if(pairs>=2 && pairShared*100>=pairs*70) {
                c.kind=CandidateKind::WordLookupTable; c.confidence=65;
                c.reason="dynamically read adjacent byte pairs are commonly consumed by the same PCs";
            } else {
                c.kind=CandidateKind::ByteLookupTable; c.confidence=62;
                c.reason="contiguous ROM bytes observed as data reads outside the executing instruction stream";
            }
            if(!c.staticRefPCs.empty()) {
                c.confidence=std::min(95u,c.confidence+5u);
                c.reason+="; code also loads an address inside this span into a pointer register";
            }
            dataCandidates_.push_back(c);
        }
        i=j;
    }

    std::sort(dataCandidates_.begin(),dataCandidates_.end(),[](const DataCandidate& x,const DataCandidate& y){
        if(x.start!=y.start) return x.start<y.start;
        if(x.confidence!=y.confidence) return x.confidence>y.confidence;
        return static_cast<int>(x.kind)<static_cast<int>(y.kind);
    });
}

void Analyzer::rebuildDerivedState() {
    memoryXrefs_.clear();
    stats_={};
    for (const auto& kv:instructions_) {
        const Instruction& in=kv.second;
        for (const auto& mr:in.memoryRefs) memoryXrefs_[mr.address].push_back(in.address);
        if (in.flow==FlowKind::Call) ++stats_.calls;
        if (in.flow==FlowKind::Jump || in.flow==FlowKind::RelativeJump) ++stats_.jumps;
    }
    for(auto& kv:memoryXrefs_) { auto& v=kv.second; std::sort(v.begin(),v.end()); v.erase(std::unique(v.begin(),v.end()),v.end()); }
    for(auto& kv:codeXrefs_) { auto& v=kv.second; std::sort(v.begin(),v.end()); v.erase(std::unique(v.begin(),v.end()),v.end()); }
    for(auto& kv:indirectCodeXrefs_) { auto& v=kv.second; std::sort(v.begin(),v.end()); v.erase(std::unique(v.begin(),v.end()),v.end()); }

    rebuildStaticRamUsage();
    rebuildDataCandidates();

    stats_.romBytes=program_.size();
    stats_.codeInstructions=instructions_.size();
    stats_.codeBytes=std::count(codeBytes_.begin(),codeBytes_.end(),true);
    stats_.classifiedDataBytes=std::count_if(dataBytes_.begin(),dataBytes_.end(),[](DataKind k){return k!=DataKind::None;});
    stats_.dataBytes=stats_.romBytes-stats_.codeBytes;
    stats_.unclassifiedBytes=stats_.romBytes-stats_.codeBytes-stats_.classifiedDataBytes;
    stats_.labels=labels_.size();
    std::size_t refs=0; for(const auto& kv:memoryXrefs_) refs+=kv.second.size(); stats_.memoryReferences=refs;
    stats_.dispatchTables=dispatchTables_.size();
    std::set<std::uint16_t> dispatchTargets;
    for(const auto& kv:dispatchTables_) { stats_.dispatchEntries+=kv.second.entries.size(); for(const auto& e:kv.second.entries) dispatchTargets.insert(e.target); }
    stats_.dispatchTargets=dispatchTargets.size();
    for(const auto& kv:dataRegions_) {
        if(kv.second.kind==DataKind::Rst28InlineArgs) ++stats_.rst28InlineRegions;
        if(kv.second.kind==DataKind::Rst30InlinePayload) ++stats_.rst30InlineRegions;
        if(kv.second.kind==DataKind::CallInlineFiveBytes) ++stats_.callInlineFiveByteRegions;
    }
    stats_.unresolvedIndirectJumps=unresolvedIndirectSites_.size();
    stats_.classificationConflicts=classificationConflictsCount_;
    stats_.traceFilesImported=traceSources_.size();
    stats_.dynamicSeedPCs=dynamicSeedAddresses_.size();
    stats_.dynamicNewInstructions=dynamicNewInstructionsCount_;
    stats_.dynamicFlowEdgePairs=0; stats_.dynamicFlowTransitions=0;
    for(const auto& from:dynamicFlowEdges_) for(const auto& to:from.second){++stats_.dynamicFlowEdgePairs;stats_.dynamicFlowTransitions+=to.second;}
    stats_.traceMemoryReads=traceMemoryReadEvents_;
    stats_.traceMemoryWrites=traceMemoryWriteEvents_;
    stats_.attributedMemoryEvents=attributedMemoryEvents_;
    stats_.observedRomDataAddresses=romDataUsage_.size();
    for(const auto& kv:romDataUsage_) stats_.observedRomDataReads+=kv.second.readEvents;
    stats_.bulkRomScanPCs=bulkRomScanPCs_.size();
    stats_.observedRamAddresses=0; for(const auto& kv:ramUsage_) if(kv.second.dynamicReads || kv.second.dynamicWrites) ++stats_.observedRamAddresses;
    stats_.dataCandidates=dataCandidates_.size();
    for(const auto& c:dataCandidates_) {
        if(c.kind==CandidateKind::GeneralPointerTable) ++stats_.pointerTableCandidates;
        else if(c.kind==CandidateKind::CoordinatePairTable) ++stats_.coordinateCandidates;
        else if(c.kind==CandidateKind::TileTextStream) ++stats_.tileTextCandidates;
        else ++stats_.lookupTableCandidates;
    }
}

void Analyzer::recordTraceMemoryEvent(const PendingMemoryEvent& event, int sourcePC, bool sourceReliable) {
    if(event.write) ++traceMemoryWriteEvents_; else ++traceMemoryReadEvents_;
    if(sourceReliable && sourcePC>=0 && sourcePC<0x4000) ++attributedMemoryEvents_;

    // hardware-semantics analysis keeps a separate board-bus observation database. This does not
    // alter RAM hard classification or static proof; it only preserves exact
    // dynamic read/write evidence for the mapped Pac-Man board window.
    if(event.address>=0x4000 && event.address<=0x50FF) {
        BoardAddressUsage& b=boardUsage_[event.address];b.address=event.address;
        if(b.firstObservedCycle==0 || event.machineCycle<b.firstObservedCycle)b.firstObservedCycle=event.machineCycle;
        if(event.machineCycle>b.lastObservedCycle)b.lastObservedCycle=event.machineCycle;
        if(event.write){++b.dynamicWrites;b.writeValues.insert(event.value);if(sourceReliable&&sourcePC>=0)b.dynamicWriters.insert(static_cast<std::uint16_t>(sourcePC));}
        else{++b.dynamicReads;b.readValues.insert(event.value);if(sourceReliable&&sourcePC>=0)b.dynamicReaders.insert(static_cast<std::uint16_t>(sourcePC));}
    }

    if(isPhysicalRamAddress(event.address)) {
        RamAddressUsage& u=ramUsage_[event.address];
        u.address=event.address; u.region=ramRegionName(event.address); u.symbol=defaultRamSymbol(event.address);
        if(u.firstObservedCycle==0 || event.machineCycle<u.firstObservedCycle) u.firstObservedCycle=event.machineCycle;
        if(event.machineCycle>u.lastObservedCycle) u.lastObservedCycle=event.machineCycle;
        if(event.write) {
            ++u.dynamicWrites; u.writeValues.insert(event.value);
            if(sourceReliable && sourcePC>=0) u.dynamicWriters.insert(static_cast<std::uint16_t>(sourcePC));
        } else {
            ++u.dynamicReads; u.readValues.insert(event.value);
            if(sourceReliable && sourcePC>=0) u.dynamicReaders.insert(static_cast<std::uint16_t>(sourcePC));
        }
    }

    if(!event.write && event.address<program_.size() && sourceReliable && sourcePC>=0) {
        const auto it=instructions_.find(static_cast<std::uint16_t>(sourcePC));
        if(it!=instructions_.end()) {
            const std::uint32_t lo=it->second.address;
            const std::uint32_t hi=lo+it->second.length();
            // Memory fetches for the currently executing instruction are not data
            // observations. Reads elsewhere in ROM are strong dynamic evidence.
            if(event.address<lo || event.address>=hi) {
                RomDataUsage& r=romDataUsage_[event.address];
                r.address=event.address; ++r.readEvents; r.sourcePCs.insert(static_cast<std::uint16_t>(sourcePC));
            }
        }
    }
}

bool Analyzer::importPacmanArcadeTrace(const std::string& tracePath, std::string& error) {
    if(!ready_) { error="Analyze a ROM set before importing a Pacman Arcade trace."; return false; }
    if(std::find(traceSources_.begin(),traceSources_.end(),tracePath)!=traceSources_.end()) {
        error="This trace has already been imported into the current analysis."; return false;
    }
    std::ifstream f(tracePath.c_str());
    if(!f) { error="Unable to open trace file: "+tracePath; return false; }

    std::set<std::uint16_t> pcs;
    std::string line;
    std::size_t lineNo=0, instructionEvents=0, opcodeMatches=0, haltRefreshEvents=0;
    bool schemaSeen=false;
    auto parseHexField=[](const std::string& text,const std::string& field,unsigned long& out)->bool {
        std::size_t p=text.find("\""+field+"\""); if(p==std::string::npos) return false;
        p=text.find(':',p); if(p==std::string::npos) return false;
        p=text.find('"',p); if(p==std::string::npos) return false;
        const std::size_t q=text.find('"',p+1); if(q==std::string::npos) return false;
        const std::string value=text.substr(p+1,q-p-1); if(value.empty() || value.size()>16) return false;
        char* e=nullptr; out=std::strtoul(value.c_str(),&e,16); return e && *e=='\0';
    };
    auto expectedTraceOpcode=[&](std::uint16_t pc)->std::uint8_t {
        std::size_t p=pc; std::uint8_t op=program_[p];
        while((op==0xDD || op==0xFD) && p+1<program_.size()) op=program_[++p];
        return op;
    };

    while(std::getline(f,line)) {
        ++lineNo;
        if(line.find("pacemu.trace")!=std::string::npos) schemaSeen=true;
        if(line.find("\"type\":\"instruction\"")==std::string::npos && line.find("\"type\": \"instruction\"")==std::string::npos) continue;
        unsigned long address=0, opcode=0;
        if(!parseHexField(line,"address",address) || !parseHexField(line,"value",opcode)) {
            error="Malformed instruction event in trace near line "+std::to_string(lineNo)+"."; return false;
        }
        if(address>=program_.size()) continue;
        if(opcode>0xFF) { error="Invalid opcode value in trace near line "+std::to_string(lineNo)+"."; return false; }
        const auto pc=static_cast<std::uint16_t>(address); ++instructionEvents;
        const auto op=static_cast<std::uint8_t>(opcode);
        if(op==program_[pc] || op==expectedTraceOpcode(pc)) { ++opcodeMatches; pcs.insert(pc); }
        else if(op==0x76 && pc>0 && program_[pc-1]==0x76) {
            // Z80 HALT refresh cycles leave PC on the following byte while
            // Pacman Arcade correctly reports lastOpcode() as the HALT opcode.
            // These are not executions of program_[PC] and must not seed code.
            ++haltRefreshEvents;
        }
    }
    if(f.bad()) { error="Failed while reading trace file near line "+std::to_string(lineNo)+"."; return false; }
    if(!schemaSeen) { error="This does not appear to be a pacemu.trace JSON export from Pacman Arcade."; return false; }
    if(pcs.empty() || instructionEvents==0) { error="No Pacman Arcade instruction events were found in the trace."; return false; }
    const std::size_t comparableEvents=instructionEvents-haltRefreshEvents;
    const double agreement=comparableEvents?static_cast<double>(opcodeMatches)/static_cast<double>(comparableEvents):0.0;
    if(opcodeMatches==0 || agreement<0.90) {
        std::ostringstream o; o<<"Trace does not match the loaded canonical ROM (opcode agreement "<<std::fixed<<std::setprecision(2)<<(agreement*100.0)
                               <<"% after excluding "<<haltRefreshEvents<<" HALT refresh events).";
        error=o.str(); return false;
    }
    for(const auto pc:pcs) {
        if(dataBytes_[pc]!=DataKind::None) {
            error="Trace proves an instruction boundary at $"+hexWord(pc)+" but static analysis currently classifies that byte as "+dataKindText(dataBytes_[pc])+". Import was rejected so the conflict can be investigated.";
            return false;
        }
    }

    const std::size_t before=instructions_.size();
    std::set<std::uint16_t> instructionsBeforeTrace;
    for(const auto& kv:instructions_) instructionsBeforeTrace.insert(kv.first);
    std::vector<WorkItem> work;
    for(const auto pc:pcs) { dynamicSeedAddresses_.insert(pc); work.push_back({pc,static_cast<std::uint8_t>(EvidenceKind::DynamicTrace)}); }
    while(!work.empty()) { const WorkItem item=work.back(); work.pop_back(); traceFrom(item.address,item.evidence,work); }
    for(const auto& kv:instructions_)
        if(!instructionsBeforeTrace.count(kv.first)) traceDiscoveredInstructionAddresses_.insert(kv.first);

    // Second streaming scan attributes read/write events to the instruction event
    // emitted immediately after CPU::step(). IRQ-acknowledge windows are kept but
    // intentionally not attributed to the pre-step PC.
    std::ifstream mf(tracePath.c_str());
    if(!mf) { error="Unable to reopen validated trace for memory-evidence import."; return false; }
    std::vector<PendingMemoryEvent> pending;
    bool ambiguousInstruction=false;
    int previousFlowPC=-1;
    bool previousFlowReliable=false;
    auto parseDecField=[](const std::string& text,const std::string& field,std::uint64_t& out)->bool {
        std::size_t p=text.find("\""+field+"\""); if(p==std::string::npos) return false;
        p=text.find(':',p); if(p==std::string::npos) return false; ++p;
        while(p<text.size() && (text[p]==' '||text[p]=='\t')) ++p;
        std::size_t q=p; while(q<text.size() && text[q]>='0' && text[q]<='9') ++q;
        if(q==p) return false;
        const std::string value=text.substr(p,q-p);
        char* e=nullptr;
        out=std::strtoull(value.c_str(),&e,10);
        return e && *e=='\0';
    };
    while(std::getline(mf,line)) {
        const bool isRead=line.find("\"type\":\"memory_read\"")!=std::string::npos || line.find("\"type\": \"memory_read\"")!=std::string::npos;
        const bool isWrite=line.find("\"type\":\"memory_write\"")!=std::string::npos || line.find("\"type\": \"memory_write\"")!=std::string::npos;
        if(isRead || isWrite) {
            unsigned long address=0,value=0; std::uint64_t cycle=0;
            if(parseHexField(line,"address",address) && parseHexField(line,"value",value) && address<=0xFFFF && value<=0xFF) {
                parseDecField(line,"machine_cycle",cycle);
                pending.push_back({isWrite,static_cast<std::uint16_t>(address),static_cast<std::uint8_t>(value),cycle});
            }
            continue;
        }
        if(line.find("\"type\":\"interrupt_acknowledge\"")!=std::string::npos || line.find("\"type\": \"interrupt_acknowledge\"")!=std::string::npos) {
            ambiguousInstruction=true; continue;
        }
        if(line.find("\"type\":\"instruction\"")!=std::string::npos || line.find("\"type\": \"instruction\"")!=std::string::npos) {
            unsigned long address=0, opcode=0; int pc=-1; bool opcodeReliable=false;
            if(parseHexField(line,"address",address) && parseHexField(line,"value",opcode) && address<program_.size() && opcode<=0xFF) {
                pc=static_cast<int>(address);
                const auto pcu=static_cast<std::uint16_t>(address);
                const auto op=static_cast<std::uint8_t>(opcode);
                opcodeReliable=(op==program_[pcu] || op==expectedTraceOpcode(pcu));
            }
            const bool reliable=!ambiguousInstruction && pc>=0 && opcodeReliable;
            for(const auto& ev:pending) recordTraceMemoryEvent(ev,pc,reliable);
            if(previousFlowReliable && reliable && previousFlowPC>=0 && pc>=0) {
                ++dynamicFlowEdges_[static_cast<std::uint16_t>(previousFlowPC)][static_cast<std::uint16_t>(pc)];
            }
            previousFlowPC=pc;
            previousFlowReliable=reliable;
            pending.clear(); ambiguousInstruction=false;
        }
    }
    for(const auto& ev:pending) recordTraceMemoryEvent(ev,-1,false);

    traceSources_.push_back(tracePath);
    dynamicNewInstructionsCount_+=instructions_.size()-before;
    rebuildDerivedState();
    error.clear(); return true;
}

void Analyzer::addCodeXref(std::uint16_t target, std::uint16_t source, bool indirect) {
    pushUnique(codeXrefs_[target],source);
    if(indirect) pushUnique(indirectCodeXrefs_[target],source);
}

void Analyzer::queueTarget(std::uint16_t target, std::uint16_t source, std::uint8_t evidence,
                           bool indirect, std::vector<WorkItem>& work) {
    if(target>=program_.size()) return;
    labels_.insert(target);
    addCodeXref(target,source,indirect);
    work.push_back({target,evidence});
}

bool Analyzer::markDataRange(std::uint16_t sourceAddress, std::uint16_t start, std::size_t length, DataKind kind) {
    if(length==0 || static_cast<std::size_t>(start)+length>program_.size()) return false;
    for(std::size_t i=0;i<length;++i) {
        const std::size_t a=static_cast<std::size_t>(start)+i;
        if(codeBytes_[a]) { ++classificationConflictsCount_; return false; }
        if(dataBytes_[a]!=DataKind::None && dataBytes_[a]!=kind) { ++classificationConflictsCount_; return false; }
    }
    for(std::size_t i=0;i<length;++i) dataBytes_[static_cast<std::size_t>(start)+i]=kind;
    DataRegion r; r.sourceAddress=sourceAddress; r.start=start; r.end=static_cast<std::uint16_t>(start+length); r.kind=kind;
    const auto it=dataRegions_.find(start);
    if(it==dataRegions_.end()) dataRegions_[start]=r;
    return true;
}

bool Analyzer::markInlineData(std::uint16_t rstAddress, std::uint16_t start, std::size_t length, DataKind kind) {
    return markDataRange(rstAddress,start,length,kind);
}

std::uint16_t Analyzer::pushedContinuationBefore(std::uint16_t rstAddress) const {
    // Pac-Man sometimes prepares an explicit post-dispatch return with:
    //   LD HL,$xxxx / PUSH HL / ... / RST $20
    // Search a short contiguous instruction window rather than assuming adjacency.
    std::vector<const Instruction*> prior;
    std::uint16_t cursor=rstAddress;
    for(int n=0;n<7;++n) {
        const Instruction* found=nullptr;
        auto it=instructions_.lower_bound(cursor);
        while(it!=instructions_.begin()) {
            --it;
            const auto end=static_cast<std::uint32_t>(it->first)+it->second.length();
            if(end==cursor) { found=&it->second; break; }
            if(end<cursor) break;
        }
        if(!found) break;
        prior.push_back(found);
        cursor=found->address;
    }
    for(std::size_t i=0;i+1<prior.size();++i) {
        const Instruction& push=*prior[i];
        const Instruction& load=*prior[i+1];
        if(push.mnemonic=="PUSH" && push.operands=="HL" && load.bytes.size()==3 && load.bytes[0]==0x21) {
            return static_cast<std::uint16_t>(load.bytes[1] | (static_cast<std::uint16_t>(load.bytes[2])<<8));
        }
    }
    return 0xFFFF;
}

bool Analyzer::resolveRst20Table(std::uint16_t rstAddress, std::vector<WorkItem>& work) {
    if(dispatchTables_.count(rstAddress)) return true;
    const std::uint32_t base32=static_cast<std::uint32_t>(rstAddress)+1;
    if(base32+1>=program_.size()) return false;
    const std::uint16_t base=static_cast<std::uint16_t>(base32);
    constexpr std::size_t kMaxEntries=256;

    std::vector<std::uint16_t> words;
    bool sawInvalid=false;
    std::size_t invalidIndex=0;
    for(std::size_t i=0;i<kMaxEntries;++i) {
        const std::size_t p=static_cast<std::size_t>(base)+i*2;
        if(p+1>=program_.size()) { sawInvalid=true; invalidIndex=i; break; }
        if(dataBytes_[p]!=DataKind::None || dataBytes_[p+1]!=DataKind::None) { sawInvalid=true; invalidIndex=i; break; }
        const std::uint16_t target=readWord(program_,p);
        if(target>=program_.size()) { sawInvalid=true; invalidIndex=i; break; }
        words.push_back(target);
    }

    struct Choice { std::size_t count=std::numeric_limits<std::size_t>::max(); int priority=99; std::string reason; } choice;
    auto consider=[&](std::size_t count,int priority,const std::string& reason){
        if(count==0 || count>words.size()) return;
        if(count<choice.count || (count==choice.count && priority<choice.priority)) choice={count,priority,reason};
    };

    // Strongest generic boundary: a pointer in the table lands exactly at an
    // aligned address after the table. A valid dispatch table cannot target its
    // own pointer bytes, so the earliest such local target is a natural end.
    for(const std::uint16_t target:words) {
        if(target>=base) {
            const std::uint32_t diff=static_cast<std::uint32_t>(target)-base;
            if((diff&1u)==0) consider(diff/2,1,"first aligned local handler target");
        }
    }

    // Explicit continuation prepared by caller code is equally useful when it
    // points immediately after the inline table.
    const std::uint16_t continuation=pushedContinuationBefore(rstAddress);
    if(continuation!=0xFFFF && continuation>=base) {
        const std::uint32_t diff=static_cast<std::uint32_t>(continuation)-base;
        if((diff&1u)==0) consider(diff/2,0,"caller-pushed continuation");
    }

    // If another trusted path has already decoded code after this RST, do not
    // let a pointer table consume it.
    auto codeIt=instructions_.upper_bound(base);
    if(codeIt!=instructions_.end()) {
        const std::uint32_t diff=static_cast<std::uint32_t>(codeIt->first)-base;
        if((diff&1u)==0) consider(diff/2,0,"previously proven code boundary");
    }

    // Pac-Man tables are ROM pointers. The first little-endian word that is not
    // a ROM address is a conservative fallback boundary.
    if(sawInvalid && invalidIndex>0) consider(invalidIndex,3,"first non-ROM pointer word");

    if(choice.count==std::numeric_limits<std::size_t>::max()) return false;
    const std::uint32_t end32=base32+choice.count*2;
    if(end32>program_.size()) return false;
    const std::uint16_t end=static_cast<std::uint16_t>(end32);

    // Final self-reference guard. A handler may begin exactly at end, never
    // inside the table body.
    for(std::size_t i=0;i<choice.count;++i) {
        const std::uint16_t t=words[i];
        if(t>=base && t<end) return false;
    }
    if(!markDataRange(rstAddress,base,choice.count*2,DataKind::Rst20DispatchTable)) return false;

    DispatchTable table; table.rstAddress=rstAddress; table.start=base; table.end=end; table.boundaryReason=choice.reason;
    for(std::size_t i=0;i<choice.count;++i) {
        const std::uint16_t target=words[i];
        const std::uint16_t entryAddress=static_cast<std::uint16_t>(base+i*2);
        table.entries.push_back({i,entryAddress,target});
        queueTarget(target,rstAddress,static_cast<std::uint8_t>(EvidenceKind::Rst20Dispatch),true,work);
    }
    dispatchTables_[rstAddress]=table;
    unresolvedIndirectSites_.erase(rstAddress);
    return true;
}

void Analyzer::traceFrom(std::uint16_t entry, std::uint8_t evidence, std::vector<WorkItem>& work) {
    std::uint32_t pc=entry;
    while(pc<program_.size()) {
        const auto a=static_cast<std::uint16_t>(pc);
        const auto existing=instructions_.find(a);
        if(existing!=instructions_.end()) { instructionEvidence_[a]|=evidence; return; }
        if(dataBytes_[pc]!=DataKind::None) return;
        if(codeBytes_[pc]) return; // landed inside an instruction already decoded from another path.

        Instruction in=dis_.decode(program_,a);
        if (in.bytes.empty() || pc+in.length()>program_.size()) return;
        bool overlaps=false;
        for(std::size_t n=0;n<in.length();++n) {
            if(codeBytes_[pc+n] || dataBytes_[pc+n]!=DataKind::None) { overlaps=true; break; }
        }
        if(overlaps) { ++classificationConflictsCount_; return; }
        instructions_[in.address]=in;
        instructionEvidence_[in.address]|=evidence;
        for(std::size_t n=0;n<in.length();++n) codeBytes_[pc+n]=true;

        if(in.target>=0 && in.target < static_cast<int>(program_.size())) {
            const auto t=static_cast<std::uint16_t>(in.target);
            queueTarget(t,in.address,static_cast<std::uint8_t>(EvidenceKind::DirectFlow),false,work);
        }

        const std::uint32_t next=pc+in.length();

        // Pac-Man has one statically proven custom inline-call convention at
        // $2B70: CALL $2BCD pushes the physical return $2B73, while the callee
        // POPs that address, consumes exactly five bytes, PUSHes $2B78 and RETs.
        // Those five bytes are data, not executable CALL fallthrough.
        if(in.flow==FlowKind::Call && in.target==0x2BCD) {
            if(next+5>program_.size() || !markInlineData(in.address,static_cast<std::uint16_t>(next),5,DataKind::CallInlineFiveBytes)) return;
            pc=next+5;
            evidence=static_cast<std::uint8_t>(EvidenceKind::DirectFlow);
            continue;
        }

        // Pac-Man-specific inline restart conventions.
        if(in.flow==FlowKind::Restart && in.target==0x20) {
            if(!resolveRst20Table(in.address,work)) unresolvedIndirectSites_.insert(in.address);
            return; // RST $20 pops the caller return and dispatches with JP (HL).
        }
        if(in.flow==FlowKind::Restart && in.target==0x28) {
            if(next+2>program_.size() || !markInlineData(in.address,static_cast<std::uint16_t>(next),2,DataKind::Rst28InlineArgs)) return;
            pc=next+2;
            evidence=static_cast<std::uint8_t>(EvidenceKind::DirectFlow);
            continue;
        }
        if(in.flow==FlowKind::Restart && in.target==0x30) {
            if(next+3>program_.size() || !markInlineData(in.address,static_cast<std::uint16_t>(next),3,DataKind::Rst30InlinePayload)) return;
            pc=next+3;
            evidence=static_cast<std::uint8_t>(EvidenceKind::DirectFlow);
            continue;
        }

        if(in.flow==FlowKind::Return && !in.conditional) return;
        // An indirect JP terminates the linear path. $0027 is the known JP (HL)
        // inside Pac-Man's RST $20 dispatcher; other sites remain unresolved.
        if(in.indirect && in.flow==FlowKind::Jump) {
            // $0027 is RST $20's table dispatcher. $0064 is RST $30's
            // inline-payload continuation after it advances HL by three bytes.
            if(in.address!=0x0027 && in.address!=0x0064) unresolvedIndirectSites_.insert(in.address);
            return;
        }
        // HALT resumes at the following instruction when an enabled interrupt is accepted.
        if((in.flow==FlowKind::Jump || in.flow==FlowKind::RelativeJump) && !in.conditional) return;
        pc=next;
        evidence=static_cast<std::uint8_t>(EvidenceKind::DirectFlow);
    }
}

std::string Analyzer::labelFor(std::uint16_t address) const {
    if(const auto* user=symbols_.find(address)) return user->name;
    if(address==irqEntry_) return "irq_"+hexWord(address);
    if(entries_.count(address)) {
        if(address==0x0000) return "reset_0000";
        return "vector_"+hexWord(address);
    }
    const auto xr=codeXrefs_.find(address);
    if(xr!=codeXrefs_.end()) {
        for(const auto source:xr->second) {
            const auto it=instructions_.find(source);
            if(it!=instructions_.end() && it->second.flow==FlowKind::Call) return "sub_"+hexWord(address);
        }
    }
    if(indirectCodeXrefs_.count(address)) return "handler_"+hexWord(address);
    return "loc_"+hexWord(address);
}

std::string Analyzer::hardwareAnnotation(std::uint16_t a, RefAccess access) const {
    const bool read=access==RefAccess::Read||access==RefAccess::ReadWrite;
    const bool write=access==RefAccess::Write||access==RefAccess::ReadWrite;
    if(a>=0x4000 && a<=0x43FF) return "video RAM";
    if(a>=0x4400 && a<=0x47FF) return "color RAM";
    if(a>=0x4800 && a<=0x4BFF) return read&&!write?"unconnected/open bus read":"unconnected write region";
    if(a>=0x4C00 && a<=0x4FEF) return "work RAM";
    if(a>=0x4FF0 && a<=0x4FFF) return "sprite RAM";
    if(a>=0x5000 && a<=0x5007) {
        if(read&&!write) return "IN0 read decode";
        if(write&&!read){static const char* latch[8]={"IRQ enable output latch","sound enable output latch","aux output latch","flip screen output latch","lamp 1 output latch","lamp 2 output latch","coin lockout output latch","coin counter output latch"};return latch[a-0x5000];}
        return "IN0 read decode / output latch write";
    }
    if(a>=0x5040 && a<=0x505F) return read&&!write?"IN1 read decode":write&&!read?"Namco WSG sound register write":"IN1 read decode / Namco WSG write";
    if(a>=0x5060 && a<=0x506F) return "sprite coordinate register";
    if(a>=0x5070 && a<=0x507F) return write?"NOP write region":"unmapped read region";
    if(a>=0x5080 && a<=0x50BF) return read&&!write?"DSW1 input decode":write&&!read?"NOP write region":"DSW1 input decode / NOP writes";
    if(a>=0x50C0 && a<=0x50FF) return read&&!write?"DSW2 input decode":write&&!read?"watchdog write":"DSW2 input decode / watchdog writes";
    return "";
}

std::string Analyzer::evidenceText(std::uint16_t address) const {
    const auto it=instructionEvidence_.find(address);
    if(it==instructionEvidence_.end()) return "unknown";
    const std::uint8_t f=it->second;
    std::vector<std::string> parts;
    if(f&static_cast<std::uint8_t>(EvidenceKind::VectorSeed)) parts.push_back("vector-seed");
    if(f&static_cast<std::uint8_t>(EvidenceKind::DirectFlow)) parts.push_back("direct-flow");
    if(f&static_cast<std::uint8_t>(EvidenceKind::Rst20Dispatch)) parts.push_back("rst20-dispatch");
    if(f&static_cast<std::uint8_t>(EvidenceKind::DynamicTrace)) parts.push_back("dynamic-trace");
    std::ostringstream o; for(std::size_t i=0;i<parts.size();++i){if(i)o<<",";o<<parts[i];} return o.str();
}

std::string Analyzer::dataKindText(DataKind kind) const {
    switch(kind) {
        case DataKind::Rst20DispatchTable:return "RST $20 dispatch pointer table";
        case DataKind::Rst28InlineArgs:return "RST $28 inline B/C arguments";
        case DataKind::Rst30InlinePayload:return "RST $30 inline 3-byte payload";
        case DataKind::CallInlineFiveBytes:return "CALL $2BCD inline 5-byte payload";
        default:return "unclassified";
    }
}

std::string Analyzer::candidateKindText(CandidateKind kind) const {
    switch(kind) {
        case CandidateKind::GeneralPointerTable:return "general pointer table";
        case CandidateKind::ByteLookupTable:return "byte lookup table";
        case CandidateKind::WordLookupTable:return "word lookup table";
        case CandidateKind::CoordinatePairTable:return "coordinate-pair table";
        case CandidateKind::TileTextStream:return "tile/text stream";
    }
    return "unknown candidate";
}

std::string Analyzer::formatInstruction(const Instruction& in, bool useLabels) const {
    std::ostringstream o;
    o<<hexWord(in.address)<<"  ";
    std::ostringstream bytes;
    for(auto b:in.bytes) bytes<<hexByte(b)<<" ";
    o<<std::left<<std::setw(15)<<bytes.str();
    std::string operand=in.operands;
    if(useLabels && in.target>=0 && in.target<0x4000) {
        const std::string h=Z80Disassembler::hex16(static_cast<std::uint16_t>(in.target));
        const auto p=operand.find(h);
        if(p!=std::string::npos) operand.replace(p,h.size(),labelFor(static_cast<std::uint16_t>(in.target)));
    }
    // Researcher symbols are stronger than generated names and may describe
    // RAM/hardware as well as code. Replace exact $XXXX operands when named.
    for(const auto& kv:symbols_.entries()) {
        const std::string h=Z80Disassembler::hex16(kv.first);
        std::size_t p=0;
        while((p=operand.find(h,p))!=std::string::npos) { operand.replace(p,h.size(),kv.second.name); p+=kv.second.name.size(); }
    }
    o<<std::left<<std::setw(7)<<in.mnemonic<<operand;
    std::vector<std::string> comments;
    if(!in.comment.empty()) comments.push_back(in.comment);
    for(const auto& mr:in.memoryRefs) {
        std::string hw=hardwareAnnotation(mr.address,mr.access);
        std::ostringstream c; c<<accessName(mr.access)<<" "<<Z80Disassembler::hex16(mr.address);
        if(!hw.empty()) c<<" "<<hw;
        comments.push_back(c.str());
    }
    if(!comments.empty()) {
        o<<"  ; ";
        for(std::size_t i=0;i<comments.size();++i) { if(i) o<<" | "; o<<comments[i]; }
    }
    return o.str();
}

std::vector<std::string> Analyzer::annotatedLines() const {
    std::vector<std::string> out;
    if(!ready_) return out;
    out.push_back("; PacRipper RST-aware analyzed assembly");
    out.push_back("; Source: "+sourcePath_);
    out.push_back("; Proven code is decoded; recognized inline data is typed; all remaining bytes stay DB.");
    out.push_back("");
    std::size_t pc=0;
    while(pc<program_.size()) {
        const auto it=instructions_.find(static_cast<std::uint16_t>(pc));
        if(it!=instructions_.end()) {
            if(labels_.count(static_cast<std::uint16_t>(pc))) {
                out.push_back(""); out.push_back(labelFor(static_cast<std::uint16_t>(pc))+":");
                const auto xr=codeXrefs_.find(static_cast<std::uint16_t>(pc));
                if(xr!=codeXrefs_.end() && !xr->second.empty()) {
                    std::ostringstream x; x<<"; XREF from ";
                    for(std::size_t n=0;n<xr->second.size();++n) { if(n) x<<", "; x<<"$"<<hexWord(xr->second[n]); }
                    const auto ix=indirectCodeXrefs_.find(static_cast<std::uint16_t>(pc));
                    if(ix!=indirectCodeXrefs_.end()) x<<"  [includes RST $20 dispatch]";
                    out.push_back(x.str());
                }
                out.push_back("; Evidence: "+evidenceText(static_cast<std::uint16_t>(pc)));
            }
            out.push_back(formatInstruction(it->second,true));
            pc+=it->second.length();
            continue;
        }

        const auto dr=dataRegions_.find(static_cast<std::uint16_t>(pc));
        if(dr!=dataRegions_.end()) {
            const DataRegion& r=dr->second;
            out.push_back("");
            if(r.kind==DataKind::Rst20DispatchTable) {
                const auto dt=dispatchTables_.find(r.sourceAddress);
                std::ostringstream h; h<<"; RST $20 dispatch table at $"<<hexWord(r.start)<<" from $"<<hexWord(r.sourceAddress);
                if(dt!=dispatchTables_.end()) h<<" - "<<dt->second.entries.size()<<" entries; boundary: "<<dt->second.boundaryReason;
                out.push_back(h.str());
                if(dt!=dispatchTables_.end()) {
                    for(const auto& e:dt->second.entries) {
                        std::ostringstream l;
                        l<<hexWord(e.entryAddress)<<"  "<<hexByte(program_[e.entryAddress])<<" "<<hexByte(program_[e.entryAddress+1])<<"           ";
                        l<<std::left<<std::setw(7)<<"DW"<<labelFor(e.target)<<"  ; dispatch["<<e.index<<"] -> $"<<hexWord(e.target);
                        out.push_back(l.str());
                    }
                }
            } else {
                std::ostringstream l;
                l<<hexWord(r.start)<<"  ";
                std::ostringstream b,ops;
                for(std::uint16_t a=r.start;a<r.end;++a) { b<<hexByte(program_[a])<<" "; if(a!=r.start)ops<<",";ops<<Z80Disassembler::hex8(program_[a]); }
                l<<std::left<<std::setw(15)<<b.str()<<std::setw(7)<<"DB"<<ops.str();
                l<<"  ; "<<dataKindText(r.kind)<<" consumed by RST at $"<<hexWord(r.sourceAddress);
                out.push_back(l.str());
            }
            pc=r.end;
            continue;
        }

        const std::size_t start=pc;
        std::ostringstream o; o<<hexWord(static_cast<std::uint16_t>(start))<<"  ";
        o<<std::left<<std::setw(15)<<""<<std::setw(7)<<"DB";
        std::size_t n=0;
        while(pc<program_.size() && instructions_.find(static_cast<std::uint16_t>(pc))==instructions_.end()
              && dataBytes_[pc]==DataKind::None && n<8) {
            if(n) o<<",";
            o<<Z80Disassembler::hex8(program_[pc]);
            ++pc; ++n;
        }
        if(n==0) { ++pc; continue; }
        o<<"  ; unclassified data";
        for(const auto& c:dataCandidates_) {
            if(c.start==start) { o<<" | candidate "<<candidateKindText(c.kind)<<" ("<<c.confidence<<"%)"; break; }
        }
        out.push_back(o.str());
    }
    return out;
}

std::vector<std::string> Analyzer::linearLines() const {
    std::vector<std::string> out;
    if(!ready_) return out;
    out.push_back("; PacRipper raw linear Z80 decode");
    out.push_back("; WARNING: this intentionally decodes data bytes as instructions too.");
    out.push_back("");
    std::size_t pc=0;
    while(pc<program_.size()) {
        Instruction in=dis_.decode(program_,static_cast<std::uint16_t>(pc));
        out.push_back(formatInstruction(in,false));
        pc+=std::max<std::size_t>(1,in.length());
    }
    return out;
}

std::vector<std::string> Analyzer::summaryLines() const {
    std::vector<std::string> out;
    if(!ready_) { out.push_back("No analysis loaded."); return out; }
    out.push_back("PacRipper analysis complete");
    out.push_back("Source: "+sourcePath_);
    out.push_back("Program image: 16,384 bytes ($0000-$3FFF)");
    if(irqEntry_!=0xFFFF) out.push_back("Derived IM2 IRQ entry: $"+hexWord(irqEntry_)+" via vector $3FFA");
    out.push_back("Reachable instructions: "+std::to_string(stats_.codeInstructions));
    out.push_back("Proven code bytes: "+std::to_string(stats_.codeBytes));
    out.push_back("Hard-typed inline/table data: "+std::to_string(stats_.classifiedDataBytes));
    out.push_back("Still unclassified bytes: "+std::to_string(stats_.unclassifiedBytes));
    out.push_back("RST $20 dispatch tables: "+std::to_string(stats_.dispatchTables)+" ("+std::to_string(stats_.dispatchEntries)+" entries)");
    out.push_back("Unique dispatch handlers: "+std::to_string(stats_.dispatchTargets));
    out.push_back("RST $28 inline argument sites: "+std::to_string(stats_.rst28InlineRegions));
    out.push_back("RST $30 inline payload sites: "+std::to_string(stats_.rst30InlineRegions));
    out.push_back("Data/table candidates: "+std::to_string(stats_.dataCandidates)+" (pointer="+std::to_string(stats_.pointerTableCandidates)+", lookup="+std::to_string(stats_.lookupTableCandidates)+", coordinate="+std::to_string(stats_.coordinateCandidates)+", tile/text="+std::to_string(stats_.tileTextCandidates)+")");
    out.push_back("Control-flow labels: "+std::to_string(stats_.labels));
    out.push_back("Direct CALLs: "+std::to_string(stats_.calls));
    out.push_back("Direct/relative jumps: "+std::to_string(stats_.jumps));
    out.push_back("Absolute memory references: "+std::to_string(stats_.memoryReferences));
    out.push_back("Unresolved generic indirect jumps: "+std::to_string(stats_.unresolvedIndirectJumps));
    out.push_back("Classification conflicts: "+std::to_string(stats_.classificationConflicts));
    out.push_back("Researcher symbols: "+std::to_string(symbols_.entries().size()));
    if(stats_.traceFilesImported) {
        out.push_back("Pacman Arcade traces imported: "+std::to_string(stats_.traceFilesImported));
        out.push_back("Dynamic trace PC seeds: "+std::to_string(stats_.dynamicSeedPCs));
        out.push_back("Instructions added by traces: "+std::to_string(stats_.dynamicNewInstructions));
        out.push_back("Observed control-flow edge pairs/transitions: "+std::to_string(stats_.dynamicFlowEdgePairs)+" / "+std::to_string(stats_.dynamicFlowTransitions));
        out.push_back("Trace memory reads/writes: "+std::to_string(stats_.traceMemoryReads)+" / "+std::to_string(stats_.traceMemoryWrites));
        out.push_back("Memory events attributed to instruction PCs: "+std::to_string(stats_.attributedMemoryEvents));
        out.push_back("Observed ROM data addresses/reads: "+std::to_string(stats_.observedRomDataAddresses)+" / "+std::to_string(stats_.observedRomDataReads));
        out.push_back("Bulk ROM scan/checksum reader PCs excluded from table heuristics: "+std::to_string(stats_.bulkRomScanPCs));
        out.push_back("Dynamically observed RAM addresses: "+std::to_string(stats_.observedRamAddresses));
    }
    return out;
}

std::vector<std::string> Analyzer::dispatchLines() const {
    std::vector<std::string> out;
    if(!ready_) { out.push_back("No analysis loaded."); return out; }
    out.push_back("PacRipper recovered RST $20 dispatch tables");
    out.push_back("Source: "+sourcePath_);
    out.push_back("");
    for(const auto& kv:dispatchTables_) {
        const DispatchTable& t=kv.second;
        std::ostringstream h; h<<"RST $20 at $"<<hexWord(t.rstAddress)<<"  table $"<<hexWord(t.start)<<"-$"<<hexWord(static_cast<std::uint16_t>(t.end-1))
                               <<"  entries="<<t.entries.size()<<"  boundary="<<t.boundaryReason;
        out.push_back(h.str());
        for(const auto& e:t.entries) {
            std::ostringstream l; l<<"  ["<<std::setw(3)<<e.index<<"] $"<<hexWord(e.entryAddress)<<" -> $"<<hexWord(e.target)<<"  "<<labelFor(e.target);
            out.push_back(l.str());
        }
        out.push_back("");
    }
    if(dispatchTables_.empty()) out.push_back("No RST $20 dispatch tables were recovered.");
    return out;
}

std::vector<std::string> Analyzer::dataRegionLines() const {
    std::vector<std::string> out;
    if(!ready_) { out.push_back("No analysis loaded."); return out; }
    out.push_back("PacRipper typed inline data regions"); out.push_back("");
    for(const auto& kv:dataRegions_) {
        const DataRegion& r=kv.second;
        std::ostringstream l; l<<"$"<<hexWord(r.start)<<"-$"<<hexWord(static_cast<std::uint16_t>(r.end-1))<<"  "<<dataKindText(r.kind)<<"  source RST $"<<hexWord(r.sourceAddress);
        out.push_back(l.str());
    }
    return out;
}

std::vector<std::string> Analyzer::dataCandidateLines() const {
    std::vector<std::string> out;
    if(!ready_) { out.push_back("No analysis loaded."); return out; }
    out.push_back("PacRipper ROM data/table candidates");
    out.push_back("IMPORTANT: these are heuristic candidates, not hard code/data classifications.");
    out.push_back("Dynamic ROM data reads are factual; the inferred table/stream type remains a hypothesis.");
    if(!bulkRomScanPCs_.empty()) { std::ostringstream b; b<<"Bulk ROM scan/checksum PCs excluded from type heuristics: "; std::size_t n=0; for(auto pc:bulkRomScanPCs_){if(n++)b<<", ";b<<"$"<<hexWord(pc);} out.push_back(b.str()); }
    out.push_back("");
    if(dataCandidates_.empty()) { out.push_back("No general data candidates detected yet. Import a read-enabled trace for stronger evidence."); return out; }
    for(const auto& c:dataCandidates_) {
        std::ostringstream l;
        l<<"$"<<hexWord(c.start)<<"-$"<<hexWord(static_cast<std::uint16_t>(c.end-1))
         <<"  "<<candidateKindText(c.kind)<<"  confidence="<<c.confidence<<"%";
        if(c.observedReadEvents) l<<"  observed_reads="<<c.observedReadEvents;
        out.push_back(l.str());
        out.push_back("    evidence: "+c.reason);
        if(!c.sourcePCs.empty()) {
            std::ostringstream p; p<<"    reader PCs: "; std::size_t n=0;
            for(auto pc:c.sourcePCs) { if(n++) p<<", "; p<<"$"<<hexWord(pc); if(n>=16 && c.sourcePCs.size()>n){p<<", ...";break;} }
            out.push_back(p.str());
        }
        if(!c.staticRefPCs.empty()) {
            std::ostringstream p; p<<"    static pointer refs: "; std::size_t n=0;
            for(auto pc:c.staticRefPCs) { if(n++) p<<", "; p<<"$"<<hexWord(pc); if(n>=16 && c.staticRefPCs.size()>n){p<<", ...";break;} }
            out.push_back(p.str());
        }
    }
    return out;
}

std::vector<std::string> Analyzer::ramUsageLines() const {
    std::vector<std::string> out;
    if(!ready_) { out.push_back("No analysis loaded."); return out; }
    out.push_back("PacRipper typed Pac-Man RAM usage database");
    out.push_back("Static = absolute references decoded from ROM. Dynamic = read/write events attributed from Pacman Arcade traces.");
    out.push_back("");

    out.push_back("Observed / referenced contiguous ranges:");
    bool anyRange=false;
    auto it=ramUsage_.begin();
    while(it!=ramUsage_.end()) {
        const std::uint16_t start=it->first; const std::string region=it->second.region;
        std::uint16_t end=start; std::size_t reads=0,writes=0,entries=0;
        std::set<std::uint16_t> readers,writers,staticRefs;
        auto jt=it;
        while(jt!=ramUsage_.end() && jt->first==static_cast<std::uint16_t>(end) && jt->second.region==region) {
            const RamAddressUsage& u=jt->second;
            reads+=u.dynamicReads; writes+=u.dynamicWrites; ++entries;
            readers.insert(u.dynamicReaders.begin(),u.dynamicReaders.end());
            readers.insert(u.staticReaders.begin(),u.staticReaders.end());
            writers.insert(u.dynamicWriters.begin(),u.dynamicWriters.end());
            writers.insert(u.staticWriters.begin(),u.staticWriters.end());
            staticRefs.insert(u.staticAddressRefs.begin(),u.staticAddressRefs.end());
            ++end; ++jt;
        }
        std::ostringstream r; r<<"  $"<<hexWord(start)<<"-$"<<hexWord(static_cast<std::uint16_t>(end-1))<<"  "<<region<<"  bytes="<<entries;
        if(reads||writes) r<<"  dynamic R/W="<<reads<<"/"<<writes;
        if(!readers.empty()||!writers.empty()) r<<"  access-PCs R/W="<<readers.size()<<"/"<<writers.size();
        if(!staticRefs.empty()) r<<"  address-refs="<<staticRefs.size();
        out.push_back(r.str()); anyRange=true; it=jt;
    }
    if(!anyRange) out.push_back("  No RAM references discovered.");

    out.push_back(""); out.push_back("Per-address evidence:");
    for(const auto& kv:ramUsage_) {
        const RamAddressUsage& u=kv.second;
        std::ostringstream h; h<<"$"<<hexWord(u.address)<<"  "<<u.symbol<<"  "<<u.region
          <<"  dyn R/W="<<u.dynamicReads<<"/"<<u.dynamicWrites
          <<"  static readers/writers="<<u.staticReaders.size()<<"/"<<u.staticWriters.size()
          <<"  access="<<observedAccessClass(u);
        out.push_back(h.str());
        if(!u.readValues.empty() || !u.writeValues.empty()) {
            auto valueSummary=[](const std::set<std::uint8_t>& vals)->std::string {
                if(vals.empty()) return "-";
                std::ostringstream o;
                o<<"$"<<hexByte(*vals.begin()); if(vals.size()>1) o<<"-$"<<hexByte(*vals.rbegin()); o<<" ("<<vals.size()<<" distinct)"; return o.str();
            };
            out.push_back("    observed values: read "+valueSummary(u.readValues)+"  write "+valueSummary(u.writeValues));
            out.push_back("    observed value profile: "+observedValueProfile(u));
        }
        auto pcList=[](const std::set<std::uint16_t>& pcs)->std::string {
            std::ostringstream o; std::size_t n=0; for(auto pc:pcs){if(n++)o<<",";o<<"$"<<hexWord(pc);if(n>=20&&pcs.size()>n){o<<",...";break;}} return o.str();
        };
        if(!u.dynamicReaders.empty()) out.push_back("    dynamic reader PCs: "+pcList(u.dynamicReaders));
        if(!u.dynamicWriters.empty()) out.push_back("    dynamic writer PCs: "+pcList(u.dynamicWriters));
        if(!u.staticReaders.empty()) out.push_back("    static reader PCs: "+pcList(u.staticReaders));
        if(!u.staticWriters.empty()) out.push_back("    static writer PCs: "+pcList(u.staticWriters));
        if(!u.staticAddressRefs.empty()) out.push_back("    static address refs: "+pcList(u.staticAddressRefs));
        if(u.firstObservedCycle||u.lastObservedCycle) {
            out.push_back("    observed cycle span: "+std::to_string(u.firstObservedCycle)+".."+std::to_string(u.lastObservedCycle));
        }
    }
    return out;
}

std::vector<std::string> Analyzer::symbolLines() const {
    std::vector<std::string> out;
    out.push_back("PacRipper researcher symbols");
    out.push_back("Persistent names are user/researcher assertions; they do not change code/data evidence.");
    out.push_back("");
    if(symbols_.entries().empty()) { out.push_back("No researcher symbols assigned."); return out; }
    for(const auto& kv:symbols_.entries()) {
        std::ostringstream l; l<<"$"<<hexWord(kv.first)<<"  "<<kv.second.name;
        if(kv.first<0x4000 && instructions_.count(kv.first)) l<<"  [code]";
        else if(isPhysicalRamAddress(kv.first)) l<<"  ["<<ramRegionName(kv.first)<<"]";
        else { const std::string hw=hardwareAnnotation(kv.first,RefAccess::Address); if(!hw.empty()) l<<"  ["<<hw<<"]"; }
        if(!kv.second.comment.empty()) l<<"  ; "<<kv.second.comment;
        out.push_back(l.str());
    }
    return out;
}

std::vector<std::string> Analyzer::provenanceLines() const {
    std::vector<std::string> out;
    if(!ready_) { out.push_back("No analysis loaded."); return out; }
    out.push_back("PacRipper instruction evidence / provenance");
    out.push_back("Evidence tags: vector-seed, direct-flow, rst20-dispatch, dynamic-trace");
    out.push_back("");
    for(const auto& kv:instructions_) {
        std::ostringstream l;
        l<<"$"<<hexWord(kv.first)<<"  ["<<evidenceText(kv.first)<<"]  "<<kv.second.mnemonic;
        if(!kv.second.operands.empty()) l<<" "<<kv.second.operands;
        out.push_back(l.str());
    }
    return out;
}

std::string Analyzer::jsonEscape(const std::string& s) const {
    std::ostringstream o;
    for(char c:s) {
        switch(c) { case '\\':o<<"\\\\";break; case '"':o<<"\\\"";break; case '\n':o<<"\\n";break; case '\r':o<<"\\r";break; case '\t':o<<"\\t";break; default: if(static_cast<unsigned char>(c)<32) o<<"?"; else o<<c; }
    }
    return o.str();
}

bool Analyzer::exportAll(const std::string& outputDir, std::string& error) const {
    if(!ready_) { error="Nothing has been analyzed yet."; return false; }
    if(!ensureDir(outputDir)) { error="Unable to create/open output directory: "+outputDir; return false; }
    auto writeLines=[&](const std::string& path,const std::vector<std::string>& lines)->bool {
        std::ofstream f(path.c_str()); if(!f) return false; for(const auto& l:lines) f<<l<<"\n"; return !!f;
    };
    if(!writeLines(outputDir+"/pacman_analyzed.asm",annotatedLines())) { error="Failed writing pacman_analyzed.asm"; return false; }
    if(!writeLines(outputDir+"/pacman_linear.asm",linearLines())) { error="Failed writing pacman_linear.asm"; return false; }
    if(!writeLines(outputDir+"/summary.txt",summaryLines())) { error="Failed writing summary.txt"; return false; }
    if(!writeLines(outputDir+"/dispatch_tables.txt",dispatchLines())) { error="Failed writing dispatch_tables.txt"; return false; }
    if(!writeLines(outputDir+"/data_regions.txt",dataRegionLines())) { error="Failed writing data_regions.txt"; return false; }
    if(!writeLines(outputDir+"/data_candidates.txt",dataCandidateLines())) { error="Failed writing data_candidates.txt"; return false; }
    if(!writeLines(outputDir+"/ram_database.txt",ramUsageLines())) { error="Failed writing ram_database.txt"; return false; }

    std::ofstream rcsv((outputDir+"/ram_database.csv").c_str());
    if(!rcsv) { error="Failed writing ram_database.csv"; return false; }
    rcsv<<"address,symbol,region,access_class,value_profile,dynamic_reads,dynamic_writes,static_reader_count,static_writer_count,address_ref_count,dynamic_reader_count,dynamic_writer_count,first_cycle,last_cycle\n";
    for(const auto& kv:ramUsage_) {
        const auto& u=kv.second;
        rcsv<<"$"<<hexWord(u.address)<<","<<u.symbol<<",\""<<jsonEscape(u.region)<<"\",\""<<jsonEscape(observedAccessClass(u))<<"\",\""<<jsonEscape(observedValueProfile(u))<<"\",";
        rcsv<<u.dynamicReads<<","<<u.dynamicWrites<<","<<u.staticReaders.size()<<","<<u.staticWriters.size()<<","<<u.staticAddressRefs.size()<<","<<u.dynamicReaders.size()<<","<<u.dynamicWriters.size()<<","<<u.firstObservedCycle<<","<<u.lastObservedCycle<<"\n";
    }
    if(!rcsv) { error="Failed while writing ram_database.csv"; return false; }

    std::ofstream rd((outputDir+"/rom_data_reads.txt").c_str());
    if(!rd) { error="Failed writing rom_data_reads.txt"; return false; }
    rd<<"PacRipper dynamically observed ROM data reads\n\n";
    rd<<"Instruction-fetch bytes are excluded. Bulk checksum/self-test readers remain listed here but are excluded from table-type heuristics.\n";
    if(!bulkRomScanPCs_.empty()) {
        rd<<"Bulk scan PCs: "; std::size_t n=0; for(auto pc:bulkRomScanPCs_){if(n++)rd<<", ";rd<<"$"<<hexWord(pc);} rd<<"\n\n";
    }
    for(const auto& kv:romDataUsage_) {
        rd<<"$"<<hexWord(kv.first)<<" value=$"<<hexByte(program_[kv.first])<<" reads="<<kv.second.readEvents<<" reader_pcs=";
        std::size_t n=0; for(auto pc:kv.second.sourcePCs){if(n++)rd<<",";rd<<"$"<<hexWord(pc);} rd<<"\n";
    }

    std::ofstream xr((outputDir+"/xrefs.txt").c_str());
    if(!xr) { error="Failed writing xrefs.txt"; return false; }
    xr<<"PacRipper control-flow cross references\n\n";
    for(const auto& kv:codeXrefs_) {
        xr<<labelFor(kv.first)<<" ($"<<hexWord(kv.first)<<") <- ";
        for(std::size_t i=0;i<kv.second.size();++i){ if(i)xr<<", "; xr<<"$"<<hexWord(kv.second[i]); }
        if(indirectCodeXrefs_.count(kv.first)) xr<<"  [RST $20 dispatch target]";
        xr<<"\n";
    }
    xr<<"\nAbsolute memory cross references\n\n";
    for(const auto& kv:memoryXrefs_) {
        xr<<"$"<<hexWord(kv.first);
        const auto hw=hardwareAnnotation(kv.first,RefAccess::Address); if(!hw.empty()) xr<<" ("<<hw<<")";
        xr<<" <- "; for(std::size_t i=0;i<kv.second.size();++i){if(i)xr<<", ";xr<<"$"<<hexWord(kv.second[i]);} xr<<"\n";
    }

    std::ofstream fn((outputDir+"/functions.txt").c_str());
    if(!fn) { error="Failed writing functions.txt"; return false; }
    fn<<"PacRipper function / dispatch-handler catalog\n\n";
    std::set<std::uint16_t> functionTargets;
    for(const auto& kv:instructions_) if(kv.second.flow==FlowKind::Call && kv.second.target>=0 && kv.second.target<0x4000) functionTargets.insert(static_cast<std::uint16_t>(kv.second.target));
    for(const auto& kv:indirectCodeXrefs_) functionTargets.insert(kv.first);
    for(const auto a:functionTargets) {
        fn<<labelFor(a)<<" ($"<<hexWord(a)<<")  evidence="<<evidenceText(a)<<"\n";
        const auto cx=codeXrefs_.find(a);
        if(cx!=codeXrefs_.end()) { fn<<"  xrefs: "; for(std::size_t i=0;i<cx->second.size();++i){if(i)fn<<", ";fn<<"$"<<hexWord(cx->second[i]);} fn<<"\n"; }
    }

    { std::ofstream df((outputDir+"/dynamic_flow.txt").c_str()); if(!df){error="Failed writing dynamic_flow.txt";return false;} df<<"PacRipper observed control-flow transitions from imported traces\n\n"; if(dynamicFlowEdges_.empty())df<<"No dynamic control-flow transitions imported.\n"; else for(const auto& f:dynamicFlowEdges_)for(const auto& t:f.second)df<<"$"<<hexWord(f.first)<<" -> $"<<hexWord(t.first)<<"  count="<<t.second<<"\n"; }
    if(!writeLines(outputDir+"/provenance.txt",provenanceLines())) { error="Failed writing provenance.txt"; return false; }
    { std::string se; if(!symbols_.save(outputDir+"/researcher_symbols.sym",se)) { error=se; return false; } }

    std::ofstream ts((outputDir+"/trace_sources.txt").c_str());
    if(!ts) { error="Failed writing trace_sources.txt"; return false; }
    ts<<"PacRipper imported Pacman Arcade traces\n\n";
    if(traceSources_.empty()) ts<<"No dynamic traces imported.\n"; else for(const auto& path:traceSources_) ts<<path<<"\n";

    std::ofstream mm((outputDir+"/memory_map.txt").c_str());
    if(!mm) { error="Failed writing memory_map.txt"; return false; }
    mm<<"PacRipper canonical Pac-Man board map\n\n"
      <<"$0000-$3FFF  Program ROM (6e+6f+6h+6j)\n"
      <<"$4000-$43FF  Video RAM\n"
      <<"$4400-$47FF  Color RAM\n"
      <<"$4800-$4BFF  Unconnected/open-bus region\n"
      <<"$4C00-$4FEF  Work RAM\n"
      <<"$4FF0-$4FFF  Sprite RAM\n"
      <<"$5000-$5007  Output latch / IN0 read decode\n"
      <<"$5040-$505F  Namco WSG registers / IN1 read decode\n"
      <<"$5060-$506F  Sprite coordinate registers\n"
      <<"$5070-$507F  NOP write region\n"
      <<"$5080-$50BF  DSW1 input decode / NOP writes\n"
      <<"$50C0-$50FF  DSW2 input decode / watchdog writes\n";

    std::ofstream mf((outputDir+"/rom_manifest.txt").c_str());
    if(!mf) { error="Failed writing rom_manifest.txt"; return false; }
    mf<<"PacRipper canonical ROM validation manifest\n\n";
    for(const auto& v:validation_) {
        mf<<(v.valid?"PASS ":"FAIL ")<<v.name<<"  size="<<v.actualSize<<"  CRC32="<<std::uppercase<<std::hex<<std::setw(8)<<std::setfill('0')<<v.actualCrc<<std::dec<<std::setfill(' ')<<"\n";
    }

    std::ofstream bin((outputDir+"/pacman_program.bin").c_str(),std::ios::binary);
    if(!bin) { error="Failed writing pacman_program.bin"; return false; }
    bin.write(reinterpret_cast<const char*>(program_.data()),static_cast<std::streamsize>(program_.size()));
    if(!bin) { error="Failed writing complete pacman_program.bin"; return false; }

    std::ofstream j((outputDir+"/analysis.json").c_str());
    if(!j) { error="Failed writing analysis.json"; return false; }
    auto writePcSet=[&](const std::set<std::uint16_t>& pcs) {
        j<<"["; std::size_t n=0; for(auto pc:pcs){if(n++)j<<",";j<<"\"$"<<hexWord(pc)<<"\"";} j<<"]";
    };
    j<<"{\n  \"tool\": \"PacRipper\",\n  \"source\": \""<<jsonEscape(sourcePath_)<<"\",\n";
    j<<"  \"program_size\": "<<stats_.romBytes<<",\n  \"code_bytes\": "<<stats_.codeBytes<<",\n  \"classified_data_bytes\": "<<stats_.classifiedDataBytes<<",\n  \"unclassified_bytes\": "<<stats_.unclassifiedBytes<<",\n";
    j<<"  \"instructions\": "<<stats_.codeInstructions<<",\n  \"labels\": "<<stats_.labels<<",\n  \"calls\": "<<stats_.calls<<",\n  \"jumps\": "<<stats_.jumps<<",\n";
    j<<"  \"dispatch_table_count\": "<<stats_.dispatchTables<<",\n  \"dispatch_entry_count\": "<<stats_.dispatchEntries<<",\n";
    j<<"  \"trace_files_imported\": "<<stats_.traceFilesImported<<",\n  \"dynamic_seed_pcs\": "<<stats_.dynamicSeedPCs<<",\n  \"dynamic_new_instructions\": "<<stats_.dynamicNewInstructions<<",\n  \"dynamic_flow_edge_pairs\": "<<stats_.dynamicFlowEdgePairs<<",\n  \"dynamic_flow_transitions\": "<<stats_.dynamicFlowTransitions<<",\n";
    j<<"  \"trace_memory_reads\": "<<stats_.traceMemoryReads<<",\n  \"trace_memory_writes\": "<<stats_.traceMemoryWrites<<",\n  \"attributed_memory_events\": "<<stats_.attributedMemoryEvents<<",\n";
    j<<"  \"observed_rom_data_addresses\": "<<stats_.observedRomDataAddresses<<",\n  \"observed_rom_data_reads\": "<<stats_.observedRomDataReads<<",\n  \"observed_ram_addresses\": "<<stats_.observedRamAddresses<<",\n";
    j<<"  \"data_candidate_count\": "<<stats_.dataCandidates<<",\n  \"bulk_rom_scan_pc_count\": "<<stats_.bulkRomScanPCs<<",\n";
    j<<"  \"trace_sources\": ["; for(std::size_t i=0;i<traceSources_.size();++i){ if(i)j<<","; j<<"\""<<jsonEscape(traceSources_[i])<<"\""; } j<<"],\n";
    j<<"  \"bulk_rom_scan_pcs\": "; writePcSet(bulkRomScanPCs_); j<<",\n";
    j<<"  \"researcher_symbols\": ["; std::size_t syi=0; for(const auto& kv:symbols_.entries()){if(syi++)j<<",";j<<"{\"address\":\"$"<<hexWord(kv.first)<<"\",\"name\":\""<<jsonEscape(kv.second.name)<<"\",\"comment\":\""<<jsonEscape(kv.second.comment)<<"\"}";} j<<"],\n";
    j<<"  \"dynamic_flow_edges\": ["; std::size_t dfi=0; for(const auto& f:dynamicFlowEdges_)for(const auto& t:f.second){if(dfi++)j<<",";j<<"{\"from\":\"$"<<hexWord(f.first)<<"\",\"to\":\"$"<<hexWord(t.first)<<"\",\"count\":"<<t.second<<"}";} j<<"],\n";

    j<<"  \"dispatch_tables\": [\n";
    std::size_t ti=0;
    for(const auto& kv:dispatchTables_) {
        const auto& t=kv.second;
        j<<"    {\"rst_address\":\"$"<<hexWord(t.rstAddress)<<"\",\"start\":\"$"<<hexWord(t.start)<<"\",\"end_exclusive\":\"$"<<hexWord(t.end)<<"\",\"boundary_reason\":\""<<jsonEscape(t.boundaryReason)<<"\",\"entries\":[";
        for(std::size_t i=0;i<t.entries.size();++i) { const auto& e=t.entries[i]; if(i)j<<","; j<<"{\"index\":"<<e.index<<",\"entry\":\"$"<<hexWord(e.entryAddress)<<"\",\"target\":\"$"<<hexWord(e.target)<<"\"}"; }
        j<<"]}"<<(++ti<dispatchTables_.size()?",":"")<<"\n";
    }
    j<<"  ],\n  \"data_regions\": [\n";
    std::size_t di=0;
    for(const auto& kv:dataRegions_) { const auto& r=kv.second; j<<"    {\"source\":\"$"<<hexWord(r.sourceAddress)<<"\",\"start\":\"$"<<hexWord(r.start)<<"\",\"end_exclusive\":\"$"<<hexWord(r.end)<<"\",\"kind\":\""<<jsonEscape(dataKindText(r.kind))<<"\"}"<<(++di<dataRegions_.size()?",":"")<<"\n"; }
    j<<"  ],\n  \"data_candidates\": [\n";
    for(std::size_t i=0;i<dataCandidates_.size();++i) {
        const auto& c=dataCandidates_[i];
        j<<"    {\"start\":\"$"<<hexWord(c.start)<<"\",\"end_exclusive\":\"$"<<hexWord(c.end)<<"\",\"kind\":\""<<jsonEscape(candidateKindText(c.kind))<<"\",\"confidence\":"<<c.confidence<<",\"observed_read_events\":"<<c.observedReadEvents<<",\"reason\":\""<<jsonEscape(c.reason)<<"\",\"reader_pcs\":"; writePcSet(c.sourcePCs); j<<",\"static_pointer_refs\":"; writePcSet(c.staticRefPCs); j<<"}"<<(i+1<dataCandidates_.size()?",":"")<<"\n";
    }
    j<<"  ],\n  \"rom_data_usage\": [\n";
    std::size_t ri=0;
    for(const auto& kv:romDataUsage_) {
        j<<"    {\"address\":\"$"<<hexWord(kv.first)<<"\",\"value\":\"$"<<hexByte(program_[kv.first])<<"\",\"read_events\":"<<kv.second.readEvents<<",\"reader_pcs\":"; writePcSet(kv.second.sourcePCs); j<<"}"<<(++ri<romDataUsage_.size()?",":"")<<"\n";
    }
    j<<"  ],\n  \"ram_usage\": [\n";
    std::size_t rami=0;
    for(const auto& kv:ramUsage_) {
        const auto& u=kv.second;
        j<<"    {\"address\":\"$"<<hexWord(u.address)<<"\",\"symbol\":\""<<jsonEscape(u.symbol)<<"\",\"region\":\""<<jsonEscape(u.region)<<"\",\"access_class\":\""<<jsonEscape(observedAccessClass(u))<<"\",\"value_profile\":\""<<jsonEscape(observedValueProfile(u))<<"\",\"dynamic_reads\":"<<u.dynamicReads<<",\"dynamic_writes\":"<<u.dynamicWrites
         <<",\"read_distinct_values\":"<<u.readValues.size()<<",\"write_distinct_values\":"<<u.writeValues.size()<<",\"first_cycle\":"<<u.firstObservedCycle<<",\"last_cycle\":"<<u.lastObservedCycle<<",\"static_readers\":"; writePcSet(u.staticReaders);
        j<<",\"static_writers\":"; writePcSet(u.staticWriters); j<<",\"static_address_refs\":"; writePcSet(u.staticAddressRefs); j<<",\"dynamic_readers\":"; writePcSet(u.dynamicReaders); j<<",\"dynamic_writers\":"; writePcSet(u.dynamicWriters); j<<"}"<<(++rami<ramUsage_.size()?",":"")<<"\n";
    }
    j<<"  ],\n  \"instructions_detail\": [\n";
    std::size_t idx=0;
    for(const auto& kv:instructions_) {
        const auto& in=kv.second;
        j<<"    {\"address\":\"$"<<hexWord(in.address)<<"\",\"mnemonic\":\""<<jsonEscape(in.mnemonic)<<"\",\"operands\":\""<<jsonEscape(in.operands)<<"\",\"evidence\":\""<<jsonEscape(evidenceText(in.address))<<"\"";
        if(in.target>=0) j<<",\"target\":\"$"<<hexWord(static_cast<std::uint16_t>(in.target))<<"\"";
        j<<"}"<<(++idx<instructions_.size()?",":"")<<"\n";
    }
    j<<"  ]\n}\n";
    if(!j) { error="Failed while writing analysis.json"; return false; }
    error.clear(); return true;
}

} // namespace pacripper
