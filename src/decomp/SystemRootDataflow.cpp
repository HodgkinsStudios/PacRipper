// PacRipper system-root reachability analysis system-root reachability + unknown-indirect blocker reduction
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

std::string h18(std::uint16_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(4)<<std::setfill('0')<<(unsigned)v;return o.str();}
std::string pcs18(const std::set<std::uint16_t>& s){std::ostringstream o;o<<"{";std::size_t n=0;for(auto v:s){if(n++)o<<",";o<<"$"<<h18(v);}o<<"}";return o.str();}
std::string ids18(const std::set<std::size_t>& s,const char* p=""){std::ostringstream o;o<<"{";std::size_t n=0;for(auto v:s){if(n++)o<<",";o<<p<<v;}o<<"}";return o.str();}
bool readDir18(IndirectMemoryDirection d){return d==IndirectMemoryDirection::Read||d==IndirectMemoryDirection::ReadWrite;}
bool independent18(const Analyzer* a,std::uint16_t pc){return a&&a->hasStaticInstructionProof(pc)&&!a->isTraceDiscoveredInstruction(pc);}
std::vector<std::string> split18(const std::string& s){std::vector<std::string> out;std::string cur;int depth=0;for(char c:s){if(c=='(')++depth;else if(c==')')--depth;if(c==','&&depth==0){out.push_back(cur);cur.clear();}else cur+=c;}if(!cur.empty()||!s.empty())out.push_back(cur);for(auto& x:out){std::size_t a=0,b=x.size();while(a<b&&std::isspace(static_cast<unsigned char>(x[a])))++a;while(b>a&&std::isspace(static_cast<unsigned char>(x[b-1])))--b;x=x.substr(a,b-a);}return out;}

bool potentialIndirectRead18(const Instruction& in){
    if(in.flow==FlowKind::Jump&&in.indirect)return false;
    const auto ops=split18(in.operands);bool any=false;
    for(std::size_t i=0;i<ops.size();++i){std::string reg;int disp=0;if(!IndirectAddressAnalysis::parseIndirectOperand(ops[i],reg,disp))continue;any=true;
        if(in.mnemonic=="LD")return i>0; // indirect source is a read; indirect destination is write-only
        return true; // ALU, BIT/SET/RES, INC/DEC, compare, etc. read or read/modify/write
    }
    return any;
}

AddressLatticeValue range18(std::uint16_t lo,std::uint16_t hi,std::uint16_t stride=1){AddressLatticeValue v;v.kind=stride>1?AddressValueKind::StridedRange:AddressValueKind::ContiguousRange;v.rangeStart=lo;v.rangeEnd=hi;v.stride=stride;v.staticProof=true;v.hasUnknownAlternative=false;return v;}
AddressLatticeValue set18(const std::set<std::uint16_t>& values){auto v=IndirectAddressAnalysis::finiteSet(values,false);v.staticProof=true;v.dynamicOnly=false;v.hasUnknownAlternative=false;return v;}

bool completeRomDomain18(const AddressLatticeValue& v,std::size_t romSize,std::set<std::uint16_t>& out){
    out.clear();
    if(v.kind==AddressValueKind::Unknown||v.hasUnknownAlternative||v.dynamicOnly||!v.staticProof||v.wraparound||romSize==0)return false;
    if(v.kind==AddressValueKind::Exact||v.kind==AddressValueKind::FiniteSet||v.kind==AddressValueKind::AmbiguousAlternatives){
        if(v.values.empty())return false;
        for(auto a:v.values){if(static_cast<std::size_t>(a)>=romSize){out.clear();return false;}out.insert(a);}
        return !out.empty();
    }
    if(v.kind==AddressValueKind::ContiguousRange||v.kind==AddressValueKind::StridedRange){
        if(v.rangeStart>v.rangeEnd||static_cast<std::size_t>(v.rangeEnd)>=romSize)return false;
        const std::uint32_t stride=v.kind==AddressValueKind::StridedRange?(v.stride?v.stride:1):1;
        for(std::uint32_t a=v.rangeStart;a<=v.rangeEnd;a+=stride){out.insert(static_cast<std::uint16_t>(a));if(a+stride>a&&a+stride>v.rangeEnd)break;}
        return !out.empty();
    }
    return false;
}

} // namespace

void Decompiler::buildSystemRoot(){
    systemRoots_.clear();systemRootReachability_.clear();systemRootInlineData_.clear();indirectAddressRefinements_.clear();
    systemRootNegativeReferenceEvidence_.clear();systemRootUnusedRomRegions_.clear();systemRootClosureProvenance_.clear();systemRootClosureBytes_.clear();stats_.systemRoot={};
    if(!analyzer_)return;
    const auto& program=analyzer_->program();const auto& baseline=!residualReferenceClosureBytes_.empty()?residualReferenceClosureBytes_:highRomClosureBytes_;systemRootClosureBytes_=baseline;
    // The core has already validated the complete canonical ROM manifest. Keep
    // per-address raw-byte signatures out of the distributable analysis source.
    const bool canonicalManifestBound=(program.size()==0x4000u);

    const auto rooted=SystemRootAnalysis::discoverSystemRoots(*analyzer_,baseline,systemRomSemantics_);
    systemRoots_=rooted.roots;systemRootReachability_=rooted.reachability;systemRootInlineData_=rooted.inlineData;
    const auto& rootPCs=rooted.reachablePCs;

    std::set<std::uint16_t> originalBlockers;for(const auto& n:negativeReferenceEvidence_)originalBlockers.insert(n.unknownIndirectReadBlockerPCs.begin(),n.unknownIndirectReadBlockerPCs.end());
    std::map<std::uint16_t,const IndirectMemoryAccessRecord*> accessByPc;
    for(const auto& a:indirectMemoryAccesses_)if(readDir18(a.direction)&&(!accessByPc.count(a.pc)||a.id<accessByPc[a.pc]->id))accessByPc[a.pc]=&a;
    auto eligible=[&](std::uint16_t pc){return independent18(analyzer_,pc)||rootPCs.count(pc)!=0;};

    auto addRef=[&](std::uint16_t pc,IndirectAddressRefinementKind kind,AddressLatticeValue value,const std::set<std::uint16_t>& proof,const std::string& note,const std::set<std::size_t>& semanticIds=std::set<std::size_t>{},const std::set<std::size_t>& inlineIds=std::set<std::size_t>{}){
        if(!eligible(pc)||value.kind==AddressValueKind::Unknown||value.hasUnknownAlternative||!value.staticProof)return;
        IndirectAddressRefinementRecord r;r.id=indirectAddressRefinements_.size();r.pc=pc;r.kind=kind;r.refinedAddress=std::move(value);r.originalResidualReferenceBlocker=originalBlockers.count(pc)!=0;r.rootReachable=rootPCs.count(pc)!=0;r.accepted=true;r.removesUnknownAlternative=true;r.proofPCs=proof;r.semanticIds=semanticIds;r.inlineDataIds=inlineIds;r.note=note;
        const auto ai=accessByPc.find(pc);if(ai!=accessByPc.end()){r.accessId=ai->second->id;r.originalKind=ai->second->address.kind;}r.intersectsRom=SystemRootAnalysis::addressIntersectsSpan(r.refinedAddress,0,static_cast<std::uint16_t>(program.size()));r.nonRomOnly=!r.intersectsRom;indirectAddressRefinements_.push_back(r);
    };
    auto addRange=[&](std::uint16_t pc,std::uint16_t lo,std::uint16_t hi,IndirectAddressRefinementKind kind,const std::set<std::uint16_t>& proof,const std::string& note,std::uint16_t stride=1){addRef(pc,kind,range18(lo,hi,stride),proof,note);};
    auto addSet=[&](std::uint16_t pc,const std::set<std::uint16_t>& values,IndirectAddressRefinementKind kind,const std::set<std::uint16_t>& proof,const std::string& note,const std::set<std::size_t>& sem=std::set<std::size_t>{},const std::set<std::size_t>& inl=std::set<std::size_t>{}){if(!values.empty())addRef(pc,kind,set18(values),proof,note,sem,inl);};
    auto suppress=[&](std::uint16_t pc,const std::set<std::size_t>& inlineIds,const std::set<std::uint16_t>& proof,const std::string& note){
        if(!originalBlockers.count(pc))return;
        IndirectAddressRefinementRecord r;r.id=indirectAddressRefinements_.size();r.pc=pc;r.kind=IndirectAddressRefinementKind::InlineConvention;r.originalResidualReferenceBlocker=true;r.rootReachable=rootPCs.count(pc)!=0;r.accepted=true;r.removesUnknownAlternative=true;r.sourceInstructionSuppressed=true;r.proofPCs=proof;r.inlineDataIds=inlineIds;r.note=note;const auto ai=accessByPc.find(pc);if(ai!=accessByPc.end()){r.accessId=ai->second->id;r.originalKind=ai->second->address.kind;}indirectAddressRefinements_.push_back(r);
    };

    // RST $20/$28/$30 inline conventions. These are finite source-level domains,
    // not trace observations. The root traversal records each exact inline extent.
    std::set<std::uint16_t> rst20Bytes,rst28First,rst28Second,rst30Bytes;std::set<std::size_t> rst20Ids,rst28Ids,rst30Ids,call5Ids;
    for(const auto& d:systemRootInlineData_){
        if(d.kind==SystemRootInlineDataKind::Rst20DispatchTable){rst20Ids.insert(d.id);for(std::uint16_t a=d.start;a<d.end;++a)rst20Bytes.insert(a);}
        else if(d.kind==SystemRootInlineDataKind::Rst28InlineArgs){rst28Ids.insert(d.id);if(d.end-d.start==2){rst28First.insert(d.start);rst28Second.insert(static_cast<std::uint16_t>(d.start+1));}}
        else if(d.kind==SystemRootInlineDataKind::Rst30InlinePayload){rst30Ids.insert(d.id);for(std::uint16_t a=d.start;a<d.end;++a)rst30Bytes.insert(a);}
        else if(d.kind==SystemRootInlineDataKind::CallInlineFiveBytes)call5Ids.insert(d.id);
    }
    addSet(0x0025,rst20Bytes,IndirectAddressRefinementKind::InlineConvention,{0x0020,0x0023,0x0024,0x0025,0x0027},"RST $20 dispatch reads only bytes from exact inline dispatch tables proven by the restart convention",{},rst20Ids);
    addSet(0x0029,rst28First,IndirectAddressRefinementKind::InlineConvention,{0x0028,0x0029,0x002A,0x002B,0x002D},"RST $28 first read is exactly the first byte after each statically rooted RST $28 site",{},rst28Ids);
    addSet(0x002B,rst28Second,IndirectAddressRefinementKind::InlineConvention,{0x0028,0x0029,0x002A,0x002B,0x002D},"RST $28 second read is exactly the second inline byte",{},rst28Ids);
    addSet(0x005E,rst30Bytes,IndirectAddressRefinementKind::InlineConvention,{0x0030,0x0033,0x0035,0x005B,0x005C,0x005E,0x0064},"RST $30 loop reads exactly the three-byte payload at each statically rooted call site",{},rst30Ids);

    // $2BCD custom inline call: POP return; read five bytes; PUSH advanced return.
    // Require the exact routine shape and exact rooted call site before suppressing
    // the generic fall-through decode at $2B73-$2B77.
    std::set<std::uint16_t> call5Starts;for(const auto& d:systemRootInlineData_)if(d.kind==SystemRootInlineDataKind::CallInlineFiveBytes&&d.end-d.start==5)call5Starts.insert(d.start);
    if(call5Starts==std::set<std::uint16_t>({0x2B73})&&canonicalManifestBound){
        addSet(0x2BCE,{0x2B73},IndirectAddressRefinementKind::InlineConvention,{0x2B70,0x2BCD,0x2BCE,0x2BD8},"custom inline call first byte",{},call5Ids);
        addSet(0x2BD0,{0x2B74},IndirectAddressRefinementKind::InlineConvention,{0x2B70,0x2BCD,0x2BD0,0x2BD8},"custom inline call second byte",{},call5Ids);
        addSet(0x2BD2,{0x2B75},IndirectAddressRefinementKind::InlineConvention,{0x2B70,0x2BCD,0x2BD2,0x2BD8},"custom inline call third byte",{},call5Ids);
        addSet(0x2BD4,{0x2B76},IndirectAddressRefinementKind::InlineConvention,{0x2B70,0x2BCD,0x2BD4,0x2BD8},"custom inline call fourth byte",{},call5Ids);
        addSet(0x2BD6,{0x2B77},IndirectAddressRefinementKind::InlineConvention,{0x2B70,0x2BCD,0x2BD6,0x2BD8},"custom inline call fifth byte",{},call5Ids);
        suppress(0x2B76,call5Ids,{0x2B70,0x2BCD,0x2BD8},"$2B76 lies inside the exact five-byte $2BCD inline payload and is not an executable indirect-read site in the system-root reachability analysis rooted model");
    }

    // $070E table decoder: all address arithmetic is explicitly 8-bit in E with
    // D=0, so these table reads are bounded in low ROM independent of caller data.
    if(canonicalManifestBound&&canonicalManifestBound){
        for(auto pc:{0x0724u,0x073Au,0x0740u,0x0750u,0x0766u,0x077Cu})addRange(static_cast<std::uint16_t>(pc),0x0796,0x0898,IndirectAddressRefinementKind::ContiguousRange,{0x0716,0x071F,0x0720,0x0722},"IX=$0796 plus zero-extended 8-bit E; displacement stays in finite low-ROM window");
    }
    if(canonicalManifestBound&&canonicalManifestBound)for(auto pc:{0x075Du,0x0760u})addRange(static_cast<std::uint16_t>(pc),0x084F,0x094E,IndirectAddressRefinementKind::ContiguousRange,{0x0753,0x0754,0x0755,0x0757,0x075B},"IY=$084F plus an even zero-extended byte domain; +1 high-byte read remains below $094F");
    if(canonicalManifestBound)for(auto pc:{0x0773u,0x0776u})addRange(static_cast<std::uint16_t>(pc),0x0861,0x0960,IndirectAddressRefinementKind::ContiguousRange,{0x0766,0x0769,0x076A,0x076B,0x076D,0x0771},"IY=$0861 plus even zero-extended byte domain; finite low-ROM window");
    if(canonicalManifestBound)for(auto pc:{0x0789u,0x078Cu})addRange(static_cast<std::uint16_t>(pc),0x0873,0x0972,IndirectAddressRefinementKind::ContiguousRange,{0x077C,0x077F,0x0780,0x0781,0x0783,0x0787},"IY=$0873 plus even zero-extended byte domain; finite low-ROM window");

    // Existing high-ROM semantic analysis source-proven semantic extents can refine the address
    // domain of their own read instructions without reclassifying adjacent bytes.
    for(const auto& s:streamSemantics_)if(s.accepted&&s.staticProof){
        const auto dit=std::find_if(romDecoders_.begin(),romDecoders_.end(),[&](const RomDecoderRecord& d){return d.id==s.decoderId;});if(dit==romDecoders_.end())continue;
        if(dit->routine==0x2419){for(auto pc:{0x241Fu,0x242Bu})addSet(static_cast<std::uint16_t>(pc),s.coveredAddresses,IndirectAddressRefinementKind::ProvenSemanticUnion,s.proofPCs,"high-ROM semantic analysis exact $3435 signed-pair/zero stream is the complete consumer domain",{s.id});}
    }
    // Decoder $2C5E: pointer-table bytes versus decoded stream bytes are kept
    // distinct so the refinement cannot grow through pointer-looking holes.
    std::set<std::uint16_t> d0lo,d0hi,d0streams;std::set<std::size_t> d0sem;std::set<std::uint16_t> d0proof;
    std::set<std::size_t> d0decoderIds;for(const auto& d:romDecoders_)if(d.routine==0x2C5E&&d.staticGrammarProof)d0decoderIds.insert(d.id);
    for(const auto& pd:pointerTableDomains_)if(d0decoderIds.count(pd.decoderId)&&pd.staticProof){for(auto a:pd.entryAddresses){d0lo.insert(a);if(static_cast<std::size_t>(a)+1<program.size())d0hi.insert(static_cast<std::uint16_t>(a+1));}d0proof.insert(pd.proofPCs.begin(),pd.proofPCs.end());}
    for(const auto& s:streamSemantics_)if(d0decoderIds.count(s.decoderId)&&s.accepted&&s.staticProof){d0streams.insert(s.coveredAddresses.begin(),s.coveredAddresses.end());d0sem.insert(s.id);d0proof.insert(s.proofPCs.begin(),s.proofPCs.end());}
    addSet(0x2C62,d0lo,IndirectAddressRefinementKind::ProvenSemanticUnion,d0proof,"$2C5E low-byte pointer-table read is limited to proven sparse table entries",d0sem);
    addSet(0x2C64,d0hi,IndirectAddressRefinementKind::ProvenSemanticUnion,d0proof,"$2C5E high-byte pointer-table read is limited to proven sparse table entries",d0sem);
    for(auto pc:{0x2C75u,0x2C84u,0x2C95u,0x2C9Au,0x2CACu})addSet(static_cast<std::uint16_t>(pc),d0streams,IndirectAddressRefinementKind::ProvenSemanticUnion,d0proof,"$2C5E read is limited to the union of grammar-accepted high-ROM semantic analysis stream extents",d0sem);

    // high-ROM semantic analysis maze proof: exactly 30 records x 8 bytes at $35B5-$36A4.
    std::set<std::uint16_t> mazeSet;std::set<std::size_t> mazeIds;std::set<std::uint16_t> mazeProof;
    for(const auto& r:fixedRecordSemantics_)if(r.base==0x35B5&&r.staticProof){mazeSet.insert(r.coveredAddresses.begin(),r.coveredAddresses.end());mazeIds.insert(r.id);mazeProof.insert(r.proofPCs.begin(),r.proofPCs.end());}
    addSet(0x245C,mazeSet,IndirectAddressRefinementKind::ProvenSemanticUnion,mazeProof,"nested-loop IY read uses exactly the high-ROM semantic analysis 30x8 maze extent",mazeIds);
    addSet(0x2498,mazeSet,IndirectAddressRefinementKind::ProvenSemanticUnion,mazeProof,"nested-loop IY read uses exactly the high-ROM semantic analysis 30x8 maze extent",mazeIds);
    if(canonicalManifestBound&&canonicalManifestBound)addRange(0x2459,0x4E16,0x4E33,IndirectAddressRefinementKind::NonRomRange,{0x244B,0x2455,0x246A,0x246C,0x246D},"IX starts at work RAM $4E16 and increments once for exactly 30 outer iterations");
    if(canonicalManifestBound&&canonicalManifestBound)addRange(0x24A3,0x4E16,0x4E33,IndirectAddressRefinementKind::NonRomRange,{0x248A,0x2494,0x24AC,0x24AE,0x24AF},"read/modify/write IX domain is exactly 30 work-RAM bytes $4E16-$4E33");
    if(mazeSet.size()==240&&canonicalManifestBound){unsigned sum=0,maxSum=0;for(std::uint16_t a=0x35B5;a<=0x36A4;++a){sum+=program[a];maxSum=std::max(maxSum,sum);}if(maxSum<=0x03FF)addRange(0x249C,0x4000,static_cast<std::uint16_t>(0x4000+maxSum),IndirectAddressRefinementKind::NonRomRange,{0x2487,0x2498,0x249B,0x249C},"HL begins at $4000 and accumulates the complete proven maze-byte stream; exact maximum cumulative offset keeps every read in video RAM");}

    // Selector masked to 0..3, with record path consuming only three two-byte
    // entries from literal table $32F9 (high-ROM semantic analysis exact fixed-record proof).
    std::set<std::uint16_t> r32;std::set<std::size_t> r32ids;std::set<std::uint16_t> r32proof;for(const auto& r:fixedRecordSemantics_)if(r.base==0x32F9&&r.staticProof){r32.insert(r.coveredAddresses.begin(),r.coveredAddresses.end());r32ids.insert(r.id);r32proof.insert(r.proofPCs.begin(),r.proofPCs.end());}
    addSet(0x3213,r32,IndirectAddressRefinementKind::ProvenSemanticUnion,r32proof,"$32F9 selector record domain is already source-proven in high-ROM semantic analysis",r32ids);addSet(0x3218,r32,IndirectAddressRefinementKind::ProvenSemanticUnion,r32proof,"second field remains inside the same exact $32F9 fixed-record union",r32ids);

    // $2BEA record reads: source-level count/selector proof already captured by
    // high-ROM semantic analysis fixed-record semantics rooted at $3B08.
    std::set<std::uint16_t> b08;std::set<std::size_t> b08ids;std::set<std::uint16_t> b08proof;for(const auto& r:fixedRecordSemantics_)if(r.base==0x3B08&&r.staticProof){b08.insert(r.coveredAddresses.begin(),r.coveredAddresses.end());b08ids.insert(r.id);b08proof.insert(r.proofPCs.begin(),r.proofPCs.end());}
    addSet(0x2C02,b08,IndirectAddressRefinementKind::ProvenSemanticUnion,b08proof,"$2BEA low-byte read is limited to high-ROM semantic analysis's proven $3B08 record fields",b08ids);addSet(0x2C0B,b08,IndirectAddressRefinementKind::ProvenSemanticUnion,b08proof,"$2BEA high-byte read is limited to high-ROM semantic analysis's proven $3B08 record fields",b08ids);

    // RST $30 helper entry: the rooted direct entry loads DE=$4C90 and B=$10;
    // each nonzero record advances E by exactly three and DJNZ bounds the loop.
    // Thus the read at $0051 is confined to 16 strided work-RAM addresses.
    if(canonicalManifestBound
       &&canonicalManifestBound)
        addRange(0x0051,0x4C90,0x4CBD,IndirectAddressRefinementKind::NonRomRange,
            {0x0030,0x0033,0x0035,0x0051,0x0055,0x0056,0x0057,0x0058},
            "RST $30 helper starts DE=$4C90/B=$10 and advances E by three per bounded iteration; all possible reads are work RAM",3);

    // Local arithmetic proofs independent of callers.
    if(canonicalManifestBound)addRange(0x2A30,0x0000,0x1FFF,IndirectAddressRefinementKind::ContiguousRange,{0x2A2C,0x2A2D,0x2A2F,0x2A30},"H is masked with $1F immediately before LD A,(HL); every possible target is low ROM $0000-$1FFF");
    if(canonicalManifestBound&&canonicalManifestBound)addRange(0x2A3F,0x4040,0x43BF,IndirectAddressRefinementKind::NonRomRange,{0x2A35,0x2A38,0x2A3C,0x2A3E,0x2A3F,0x2A4F},"DE starts at $4040, is compared against $43C0 before each read, and increments by one; domain is video RAM only");
    if(canonicalManifestBound&&canonicalManifestBound)for(auto pc:{0x2A69u,0x2A6Eu,0x2A75u})addRange(static_cast<std::uint16_t>(pc),0x4E80,0x4E86,IndirectAddressRefinementKind::NonRomRange,{0x2A65,0x2B0B,0x2B13,0x2A69,0x2A6C,0x2A72},"sub_$2B0B returns HL=$4E80 or $4E84; at most two INC HL operations precede these BCD reads");
    if(canonicalManifestBound)addRange(0x2A92,0x4E88,0x4E8A,IndirectAddressRefinementKind::NonRomRange,{0x2A8C,0x2A8F,0x2A92,0x2A97,0x2A98},"HL starts at $4E8A and can decrement only twice in the B=3 compare loop");

    // $294D/$2950 intentionally remain blockers.  Although A is masked to 0..3
    // before the initial IX=$32FF+2*A construction, the loop at $2957 increments
    // IX by two before jumping back to $293D.  The source-level proof does not yet
    // bound every possible number of loop advances, so the initial mask cannot be
    // reused as a complete effective-address bound for these later reads.
    // $29E1/$29E4 intentionally remain blockers: the selector is reloaded from
    // $4D3B after multiple state paths. system-root reachability analysis does not borrow the nearby $2929
    // mask as proof for this later value.

    // Candidate caller-sensitive refinements for shared helpers such as RST $10/
    // RST $18 and sub_$2000 are intentionally not collapsed here.  The new $008D
    // root exposes additional statically reachable callers beyond the verified residual-reference analysis
    // set, so a global helper refinement would be unsound without context-sensitive
    // caller domains.  Those PCs remain explicit blockers for the next analysis.

    // $3AF4 source-proven sentinel stream. Every byte from $3A4F through the
    // first zero is read sequentially; the following byte is excluded.
    if(canonicalManifestBound&&canonicalManifestBound){std::uint16_t end=0x3A4F;while(end<program.size()&&program[end]!=0)++end;if(end<program.size())addRange(0x3AFC,0x3A4F,end,IndirectAddressRefinementKind::ProvenSemanticUnion,{0x3AF7,0x3AFC,0x3AFD,0x3AFE,0x3AFF,0x3B06},"literal DE=$3A4F advances exactly once per nonzero byte; first zero is a source-proven inclusive terminator");}


    // system-root reachability analysis deliberately does not promote a second whole-program address
    // interpreter over the new system-root graph.  A prototype of that bridge
    // exposed a context-merge hazard at multi-caller routines (for example, the
    // three independently rooted callers of sub_$2DEE carry different HL bases).
    // Accepting a narrowed result there could under-approximate a ROM read domain.
    //
    // Therefore every accepted system-root reachability analysis refinement above is backed by an explicit
    // source-level finite-domain proof or by already-verified high-ROM semantic analysis semantics.
    // Root-only address-flow generalization is deferred to context-sensitive root analysis, where caller
    // contexts must be represented and merged soundly before any result can remove
    // an unknown blocker or close a ROM byte.

    // Index accepted refinements by PC. A refinement removes an unknown blocker,
    // but if its finite domain intersects a residual span it becomes positive
    // evidence for that span rather than negative evidence.
    std::map<std::uint16_t,const IndirectAddressRefinementRecord*> refByPc;for(const auto& r:indirectAddressRefinements_)if(r.accepted)refByPc[r.pc]=&r;

    // Newly rooted instructions can expose unknown reads that residual-reference analysis was not
    // permitted to count as independent static. Existing indirect-address analysis address facts
    // are reused when available; otherwise the rooted instruction is conservatively
    // retained as an unknown blocker unless system-root reachability analysis has a source refinement.
    std::set<std::uint16_t> newlyRootedUnknown;
    Z80Disassembler dis;
    for(auto pc:rooted.newlyIndependentPCs){
        if(refByPc.count(pc))continue;
        // Do not borrow a indirect-address analysis address fact for code that was trace-rooted before
        // system-root reachability analysis.  The instruction is independently static only *because* of the
        // new system root, so its address domain must be re-proven in system-root reachability analysis (or
        // later) before it can stop blocking exhaustive negative-reference claims.
        // This keeps the blocker inventory invariant between ROM-only and traced
        // runs and prevents trace-to-static bootstrapping.
        const auto in=dis.decode(program,pc);
        if(potentialIndirectRead18(in))newlyRootedUnknown.insert(pc);
    }
    // PCs already in residual-reference analysis's original independent blocker set are not counted
    // a second time merely because the new root can also reach them.
    for(auto pc:originalBlockers)newlyRootedUnknown.erase(pc);

    for(const auto& old:negativeReferenceEvidence_){
        SystemRootNegativeReferenceRecord n;n.id=systemRootNegativeReferenceEvidence_.size();n.residualReferenceNegativeReferenceId=old.id;n.start=old.start;n.end=old.end;n.length=old.length;n.originalUnknownBlockerPCs=old.unknownIndirectReadBlockerPCs;n.dynamicReadEvents=old.dynamicReadEvents;
        n.inheritedPositiveReference=!old.directMemoryRefPCs.empty()||!old.immediateAddressPCs.empty()||!old.controlTargetPCs.empty()||!old.finiteIndirectAccessIds.empty()||!old.systemSemanticIds.empty();
        for(auto pc:old.unknownIndirectReadBlockerPCs){const auto ri=refByPc.find(pc);if(ri==refByPc.end()){n.remainingOriginalBlockerPCs.insert(pc);continue;}n.refinedOriginalBlockerPCs.insert(pc);if(!ri->second->sourceInstructionSuppressed&&SystemRootAnalysis::addressIntersectsSpan(ri->second->refinedAddress,n.start,n.end))n.finiteRefinedHitPCs.insert(pc);}
        // New system-root refinements can also be positive references to a verified
        // residual-reference analysis residual span.  Record them even when the source PC was never an
        // original residual-reference analysis blocker; otherwise a newly proven consumer could vanish
        // from the negative-reference audit merely because its address is now finite.
        for(const auto& r:indirectAddressRefinements_)if(r.accepted&&!r.sourceInstructionSuppressed&&SystemRootAnalysis::addressIntersectsSpan(r.refinedAddress,n.start,n.end))n.finiteRefinedHitPCs.insert(r.pc);
        n.newlyRootedUnknownBlockerPCs=newlyRootedUnknown;
        n.exhaustiveModeledStaticAbsence=!n.inheritedPositiveReference&&n.finiteRefinedHitPCs.empty()&&n.remainingOriginalBlockerPCs.empty()&&n.newlyRootedUnknownBlockerPCs.empty();
        n.supportsUnusedClassification=SystemRootAnalysis::supportsUnused(n,old.leftBoundaryProven,old.rightBoundaryProven);
        std::ostringstream note;note<<"system-root reachability analysis versioned negative proof: "<<n.refinedOriginalBlockerPCs.size()<<" original blocker PCs have source-level finite refinements; "<<n.remainingOriginalBlockerPCs.size()<<" original blockers remain unknown. ";if(!n.newlyRootedUnknownBlockerPCs.empty())note<<n.newlyRootedUnknownBlockerPCs.size()<<" additional unknown read PCs become independently static through a system root and conservatively block exhaustive absence. ";if(!n.finiteRefinedHitPCs.empty())note<<"A refined finite domain positively intersects this span. ";note<<"Trace silence remains corroboration only.";n.note=note.str();
        systemRootNegativeReferenceEvidence_.push_back(n);
        if(n.supportsUnusedClassification){UnusedRomRegionRecord u;u.id=systemRootUnusedRomRegions_.size();u.negativeReferenceId=n.id;u.start=n.start;u.end=n.end;u.accepted=true;u.note="system-root reachability analysis exhaustive static negative-reference proof with no dynamic contradiction.";systemRootUnusedRomRegions_.push_back(u);}
    }

    std::map<std::uint16_t,SystemRootClosureProvenanceRecord> prov;
    auto addProv=[&](std::uint16_t a,bool exact,bool bounded,bool code,bool inlineData,std::size_t rootId,int inlineId,const std::set<std::uint16_t>& pcs,const std::string& note){auto& p=prov[a];p.address=a;p.exact=p.exact||exact;p.bounded=p.bounded||bounded;p.code=p.code||code;p.inlineData=p.inlineData||inlineData;if(rootId!=static_cast<std::size_t>(-1))p.rootIds.insert(rootId);if(inlineId>=0)p.inlineDataIds.insert(static_cast<std::size_t>(inlineId));p.sourcePCs.insert(pcs.begin(),pcs.end());if(!p.note.empty())p.note+="; ";p.note+=note;};
    // Additive code closure only affects bytes still unresolved after residual-reference analysis.
    for(const auto& r:systemRootReachability_)for(auto a:r.byteAddresses)if(a<systemRootClosureBytes_.size()&&baseline[a].primary==RomClosurePrimary::Unresolved){auto& b=systemRootClosureBytes_[a];b.code=true;b.primary=RomClosure::classify(b);addProv(a,true,false,true,false,r.rootId,-1,{r.pc},"exact instruction byte reached from independently proven system-root reachability analysis system root");}
    for(const auto& d:systemRootInlineData_)for(std::uint16_t a=d.start;a<d.end&&a<systemRootClosureBytes_.size();++a)if(baseline[a].primary==RomClosurePrimary::Unresolved){auto& b=systemRootClosureBytes_[a];b.hardData=true;b.staticExactDataUse=true;b.consumerPCs.insert(d.sourcePC);b.primary=RomClosure::classify(b);addProv(a,true,false,false,true,d.rootId,static_cast<int>(d.id),{d.sourcePC},"exact inline data extent from source-level call/restart convention");}

    // Accepted system-root reachability analysis refinements whose *entire* effective-address domain lies
    // in ROM become positive static consumer evidence.  A singleton exact domain
    // is an exact data use; multi-address sets/ranges remain bounded alternatives.
    // Mixed ROM/non-ROM or unknown domains are deliberately excluded.
    for(const auto& r:indirectAddressRefinements_){
        if(!r.accepted||r.sourceInstructionSuppressed)continue;
        std::set<std::uint16_t> domain;if(!completeRomDomain18(r.refinedAddress,program.size(),domain))continue;
        const bool exact=r.refinedAddress.kind==AddressValueKind::Exact&&domain.size()==1;
        for(auto a:domain){
            if(a>=systemRootClosureBytes_.size()||baseline[a].primary!=RomClosurePrimary::Unresolved)continue;
            auto& b=systemRootClosureBytes_[a];if(exact)b.staticExactDataUse=true;else b.boundedConsumer=true;b.consumerPCs.insert(r.pc);b.primary=RomClosure::classify(b);
            auto& p=prov[a];p.address=a;p.exact=p.exact||exact;p.bounded=p.bounded||!exact;p.refinedConsumer=true;p.refinementIds.insert(r.id);p.sourcePCs.insert(r.pc);p.sourcePCs.insert(r.proofPCs.begin(),r.proofPCs.end());if(!p.note.empty())p.note+="; ";p.note+=exact?"exact all-ROM effective address from accepted system-root reachability analysis refinement":"bounded all-ROM effective-address alternatives from accepted system-root reachability analysis refinement";
        }
    }
    for(auto& kv:prov)systemRootClosureProvenance_.push_back(kv.second);

    std::size_t unresolved=0,spans=0,newExact=0,newBounded=0;bool in=false;for(std::size_t i=0;i<systemRootClosureBytes_.size();++i){const bool u=systemRootClosureBytes_[i].primary==RomClosurePrimary::Unresolved;if(u){++unresolved;if(!in){++spans;in=true;}}else in=false;if(i<baseline.size()&&baseline[i].primary==RomClosurePrimary::Unresolved&&!u){if(systemRootClosureBytes_[i].code||systemRootClosureBytes_[i].hardData||systemRootClosureBytes_[i].staticExactDataUse)++newExact;else ++newBounded;}}
    std::set<std::uint16_t> refinedOriginal,remainingOriginal,totalRemaining=newlyRootedUnknown;for(const auto& n:systemRootNegativeReferenceEvidence_){refinedOriginal.insert(n.refinedOriginalBlockerPCs.begin(),n.refinedOriginalBlockerPCs.end());remainingOriginal.insert(n.remainingOriginalBlockerPCs.begin(),n.remainingOriginalBlockerPCs.end());if(n.exhaustiveModeledStaticAbsence)++stats_.systemRoot.exhaustiveNegativeReferenceRecords;}totalRemaining.insert(remainingOriginal.begin(),remainingOriginal.end());
    stats_.systemRoot.systemRoots=systemRoots_.size();stats_.systemRoot.reachableInstructions=systemRootReachability_.size();stats_.systemRoot.newlyIndependentInstructions=rooted.newlyIndependentPCs.size();stats_.systemRoot.reachableCodeBytes=rooted.reachableBytes.size();stats_.systemRoot.inlineDataRecords=systemRootInlineData_.size();stats_.systemRoot.refinements=indirectAddressRefinements_.size();stats_.systemRoot.originalResidualReferenceBlockers=originalBlockers.size();stats_.systemRoot.refinedOriginalResidualReferenceBlockers=refinedOriginal.size();stats_.systemRoot.remainingOriginalResidualReferenceBlockers=remainingOriginal.size();stats_.systemRoot.newlyRootedUnknownBlockerPCs=newlyRootedUnknown.size();stats_.systemRoot.totalRemainingUnknownBlockerPCs=totalRemaining.size();stats_.systemRoot.unusedRomRegions=systemRootUnusedRomRegions_.size();stats_.systemRoot.closureProvenanceRecords=systemRootClosureProvenance_.size();stats_.systemRoot.newlyExactExplainedBytes=newExact;stats_.systemRoot.newlyBoundedExplainedBytes=newBounded;stats_.systemRoot.newlyExplainedBytes=newExact+newBounded;stats_.systemRoot.unresolvedAfterSystemRoot=unresolved;stats_.systemRoot.residualSpansAfterSystemRoot=spans;
}

std::vector<std::string> Decompiler::systemRootLines() const{
    std::vector<std::string> o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper system-root reachability analysis system roots");for(const auto& r:systemRoots_)o.push_back("root#"+std::to_string(r.id)+" "+SystemRootAnalysis::rootKindText(r.kind)+" entry=$"+h18(r.entry)+" system#"+std::to_string(r.systemSemanticId)+" vector=$"+h18(r.vectorAddress)+" byte=$"+h18(r.vectorByte).substr(2)+" static="+(r.staticProof?"yes":"no")+" prestatic="+(r.targetStaticBeforeSystemRoot?"yes":"no")+" proof="+pcs18(r.proofPCs)+" :: "+r.note);return o;
}
std::vector<std::string> Decompiler::systemRootReachabilityLines() const{
    std::vector<std::string> o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper system-root reachability analysis system-root reachability");o.push_back("reachable="+std::to_string(stats_.systemRoot.reachableInstructions)+" newly-independent="+std::to_string(stats_.systemRoot.newlyIndependentInstructions)+" code-bytes="+std::to_string(stats_.systemRoot.reachableCodeBytes)+" inline-data="+std::to_string(stats_.systemRoot.inlineDataRecords));for(const auto& r:systemRootReachability_){std::ostringstream s;s<<"reach#"<<r.id<<" root#"<<r.rootId<<" $"<<h18(r.pc)<<" len="<<r.length<<" pred="<<(r.predecessorPc<0?"root":"$"+h18(static_cast<std::uint16_t>(r.predecessorPc)))<<" edge="<<SystemRootAnalysis::edgeKindText(r.edgeKind)<<" prestatic="<<(r.alreadyIndependentStatic?"yes":"no")<<" trace-before="<<(r.traceDiscoveredBeforeSystemRoot?"yes":"no")<<" newly-independent="<<(r.newlyIndependentStatic?"yes":"no");o.push_back(s.str());}for(const auto& d:systemRootInlineData_)o.push_back("inline#"+std::to_string(d.id)+" root#"+std::to_string(d.rootId)+" "+SystemRootAnalysis::inlineKindText(d.kind)+" source=$"+h18(d.sourcePC)+" $"+h18(d.start)+"-$"+h18(static_cast<std::uint16_t>(d.end-1))+" targets="+pcs18(d.dispatchTargets)+" :: "+d.note);return o;
}
std::vector<std::string> Decompiler::indirectRefinementLines() const{
    std::vector<std::string> o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper system-root reachability analysis indirect-address refinements");o.push_back("refinements="+std::to_string(stats_.systemRoot.refinements)+" original-blockers="+std::to_string(stats_.systemRoot.originalResidualReferenceBlockers)+" refined-original="+std::to_string(stats_.systemRoot.refinedOriginalResidualReferenceBlockers)+" remaining-original="+std::to_string(stats_.systemRoot.remainingOriginalResidualReferenceBlockers));for(const auto& r:indirectAddressRefinements_){std::ostringstream s;s<<"refine#"<<r.id<<" pc=$"<<h18(r.pc)<<" kind="<<SystemRootAnalysis::refinementKindText(r.kind)<<" old="<<IndirectAddressAnalysis::kindText(r.originalKind)<<" original-blocker="<<(r.originalResidualReferenceBlocker?"yes":"no")<<" root="<<(r.rootReachable?"yes":"no")<<" suppressed="<<(r.sourceInstructionSuppressed?"yes":"no")<<" rom="<<(r.intersectsRom?"yes":"no")<<" nonrom-only="<<(r.nonRomOnly?"yes":"no")<<" semantic="<<ids18(r.semanticIds,"sem#")<<" inline="<<ids18(r.inlineDataIds,"inline#")<<" proof="<<pcs18(r.proofPCs)<<" :: "<<r.note;o.push_back(s.str());}return o;
}
std::vector<std::string> Decompiler::systemRootNegativeRomEvidenceLines() const{
    std::vector<std::string> o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper system-root reachability analysis versioned negative ROM evidence");for(const auto& n:systemRootNegativeReferenceEvidence_){std::ostringstream s;s<<"negative18#"<<n.id<<" residualReference#"<<n.residualReferenceNegativeReferenceId<<" $"<<h18(n.start)<<"-$"<<h18(static_cast<std::uint16_t>(n.end-1))<<" len="<<n.length<<" refined-original="<<n.refinedOriginalBlockerPCs.size()<<" remaining-original="<<n.remainingOriginalBlockerPCs.size()<<" new-root-unknown="<<n.newlyRootedUnknownBlockerPCs.size()<<" finite-hits="<<n.finiteRefinedHitPCs.size()<<" exhaustive="<<(n.exhaustiveModeledStaticAbsence?"yes":"no")<<" unused="<<(n.supportsUnusedClassification?"yes":"no");o.push_back(s.str());o.push_back("  remaining="+pcs18(n.remainingOriginalBlockerPCs)+" new-root="+pcs18(n.newlyRootedUnknownBlockerPCs)+" finite-hits="+pcs18(n.finiteRefinedHitPCs));o.push_back("  "+n.note);}return o;
}
std::vector<std::string> Decompiler::systemRootClosureLines() const{
    std::vector<std::string> o;if(!ready_)return{"Decompiler model not built."};o.push_back("PacRipper system-root reachability analysis closure delta / provenance");o.push_back("new="+std::to_string(stats_.systemRoot.newlyExplainedBytes)+" exact="+std::to_string(stats_.systemRoot.newlyExactExplainedBytes)+" bounded="+std::to_string(stats_.systemRoot.newlyBoundedExplainedBytes)+" residual="+std::to_string(stats_.systemRoot.unresolvedAfterSystemRoot)+" spans="+std::to_string(stats_.systemRoot.residualSpansAfterSystemRoot)+" total-unknown-blockers="+std::to_string(stats_.systemRoot.totalRemainingUnknownBlockerPCs));for(const auto& p:systemRootClosureProvenance_)o.push_back("$"+h18(p.address)+" exact="+(p.exact?"yes":"no")+" bounded="+(p.bounded?"yes":"no")+" code="+(p.code?"yes":"no")+" inline="+(p.inlineData?"yes":"no")+" refined-consumer="+(p.refinedConsumer?"yes":"no")+" roots="+ids18(p.rootIds,"root#")+" refinements="+ids18(p.refinementIds,"refine#")+" source="+pcs18(p.sourcePCs)+" :: "+p.note);return o;
}

} // namespace pacripper
