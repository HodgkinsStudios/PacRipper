// PacRipper maze-topology analysis maze-topology / retry-loop proofs
// Created by Jacob Hodgkins

#include "MazeTopologyAnalysis.h"
#include "../disasm/Z80Disassembler.h"

#include <algorithm>
#include <array>
#include <map>
#include <sstream>

namespace pacripper {
namespace {

bool insn(const Analyzer& a,std::uint16_t pc,const std::string& mnemonic,const std::string& operands){
    Z80Disassembler d;const auto i=d.decode(a.program(),pc);return i.mnemonic==mnemonic&&i.operands==operands;
}

AddressLatticeValue unknownAddress(const std::set<std::uint16_t>& pcs,const std::string& note){
    AddressLatticeValue a;a.kind=AddressValueKind::Unknown;a.hasUnknownAlternative=true;a.staticProof=false;a.dynamicOnly=false;a.provenancePCs=pcs;a.note=note;return a;
}

AddressLatticeValue finiteAddress(const std::set<std::uint16_t>& values,const std::set<std::uint16_t>& pcs,const std::string& note){
    AddressLatticeValue a;
    if(values.empty())return unknownAddress(pcs,note);
    a.kind=values.size()==1?AddressValueKind::Exact:AddressValueKind::FiniteSet;
    a.values=values;a.rangeStart=*values.begin();a.rangeEnd=*values.rbegin();a.stride=values.size()==1?0:1;
    a.hasUnknownAlternative=false;a.wraparound=false;a.staticProof=true;a.dynamicOnly=false;a.provenancePCs=pcs;a.note=note;return a;
}

std::set<std::uint16_t> directCallers(const Analyzer& analyzer,std::uint16_t target){
    std::set<std::uint16_t> out;auto it=analyzer.codeXrefs().find(target);if(it!=analyzer.codeXrefs().end())out.insert(it->second.begin(),it->second.end());return out;
}

struct MazeGraphResult {
    bool shape=false;
    bool clearShape=false;
    bool decoderShape=false;
    bool streamTerminated=false;
    bool inBounds=true;
    std::uint16_t streamEnd=0;
    std::size_t encodedWrites=0;
    std::size_t passableNodes=0;
    std::size_t minimumDegree=0;
    std::size_t deadEnds=0;
};

MazeGraphResult proveCanonicalMaze(const Analyzer& analyzer){
    MazeGraphResult r;const auto& rom=analyzer.program();
    // $23F3 clears all four 256-byte video-RAM pages to $40. RST $08 is
    // the ROM's 256-byte fill primitive when B enters as zero. Keep this
    // source shape in the proof so the reconstructed background is not an
    // analyzer-side assumption.
    r.clearShape=insn(analyzer,0x0008,"LD","(HL),A")&&insn(analyzer,0x0009,"INC","HL")&&
        insn(analyzer,0x000A,"DJNZ","$0008")&&insn(analyzer,0x000C,"RET","")&&
        insn(analyzer,0x23F3,"LD","A,$40")&&insn(analyzer,0x23F5,"LD","BC,$0004")&&
        insn(analyzer,0x23F8,"LD","HL,$4000")&&insn(analyzer,0x23FB,"RST","$0008")&&
        insn(analyzer,0x23FC,"DEC","C")&&insn(analyzer,0x23FD,"JR","NZ,$23FB")&&insn(analyzer,0x23FF,"RET","");
    r.decoderShape=insn(analyzer,0x2419,"LD","HL,$4000")&&insn(analyzer,0x241C,"LD","BC,$3435")&&
        insn(analyzer,0x241F,"LD","A,(BC)")&&insn(analyzer,0x2420,"AND","A")&&insn(analyzer,0x2421,"RET","Z")&&
        insn(analyzer,0x2422,"JP","M,$242C")&&insn(analyzer,0x2428,"ADD","HL,DE")&&insn(analyzer,0x2429,"DEC","HL")&&
        insn(analyzer,0x242A,"INC","BC")&&insn(analyzer,0x242B,"LD","A,(BC)")&&insn(analyzer,0x242C,"INC","HL")&&
        insn(analyzer,0x242D,"LD","(HL),A")&&insn(analyzer,0x2430,"LD","DE,$83E0")&&insn(analyzer,0x2434,"AND","$1F")&&
        insn(analyzer,0x2436,"ADD","A,A")&&insn(analyzer,0x243A,"ADD","HL,DE")&&insn(analyzer,0x243C,"AND","A")&&
        insn(analyzer,0x243D,"SBC","HL,DE")&&insn(analyzer,0x2440,"XOR","$01")&&insn(analyzer,0x2442,"LD","(HL),A")&&
        insn(analyzer,0x2444,"INC","BC")&&insn(analyzer,0x2445,"JP","$241F");
    r.shape=r.clearShape&&r.decoderShape;
    if(!r.shape||rom.size()<=0x3435)return r;

    std::array<std::uint8_t,0x400> screen{};screen.fill(0x40);
    std::uint16_t hl=0x4000,bc=0x3435;
    for(std::size_t guard=0;guard<2048;++guard){
        if(bc>=rom.size()){r.inBounds=false;break;}
        std::uint8_t a=rom[bc];
        if(a==0){r.streamTerminated=true;r.streamEnd=bc;break;}
        if((a&0x80u)==0){hl=static_cast<std::uint16_t>(hl+a-1u);++bc;if(bc>=rom.size()){r.inBounds=false;break;}a=rom[bc];}
        hl=static_cast<std::uint16_t>(hl+1u);
        if(hl<0x4000||hl>=0x4400){r.inBounds=false;break;}
        screen[hl-0x4000]=a;
        const std::uint16_t original=hl;
        const std::uint16_t mirror=static_cast<std::uint16_t>(0x83E0u+2u*(original&0x001Fu)-original);
        if(mirror<0x4000||mirror>=0x4400){r.inBounds=false;break;}
        screen[mirror-0x4000]=static_cast<std::uint8_t>(a^0x01u);
        ++r.encodedWrites;++bc;
    }
    if(!r.streamTerminated||!r.inBounds)return r;

    const auto tile=[&](std::uint8_t lo,std::uint8_t hi)->std::uint8_t{
        const std::uint16_t off=static_cast<std::uint16_t>(0x40u+static_cast<std::uint8_t>(hi-0x20u)*0x20u+static_cast<std::uint8_t>(lo-0x20u));
        return off<screen.size()?screen[off]:static_cast<std::uint8_t>(0xC0u);
    };
    const auto passable=[&](std::uint8_t lo,std::uint8_t hi){return (tile(lo,hi)&0xC0u)!=0xC0u;};
    static const std::array<std::pair<int,int>,4> delta={{{0,-1},{1,0},{0,1},{-1,0}}};
    r.minimumDegree=4;
    for(unsigned hi=0x21;hi<=0x3A;++hi)for(unsigned lo=0x20;lo<=0x3F;++lo){
        if(!passable(static_cast<std::uint8_t>(lo),static_cast<std::uint8_t>(hi)))continue;
        ++r.passableNodes;std::size_t degree=0;
        for(const auto& d:delta){const auto nl=static_cast<std::uint8_t>(lo+d.first);const auto nh=static_cast<std::uint8_t>(hi+d.second);if(passable(nl,nh))++degree;}
        r.minimumDegree=std::min(r.minimumDegree,degree);if(degree<2)++r.deadEnds;
    }
    if(r.passableNodes==0)r.minimumDegree=0;
    return r;
}


} // namespace

MazeTopologyAnalysisResult MazeTopologyAnalysis::analyze(const Analyzer& analyzer){
    MazeTopologyAnalysisResult out;if(!analyzer.ready())return out;const auto& rom=analyzer.program();
    out.inheritedBlockerPCs={0x294D,0x2950};

    const std::set<std::uint16_t> expectedCallers={0x285B,0x2885,0x28AF,0x28D9};
    const auto actualCallers=directCallers(analyzer,0x291E);
    const bool callerCoverage=actualCallers==expectedCallers;

    MazeTopologyTopologyInputRecord maze;maze.id=out.topologyInputs.size();maze.kind=MazeTopologyTopologyKind::CanonicalMazeDecoder;maze.name="canonical-maze-decoder-graph";
    maze.callerPCs=expectedCallers;maze.coordinateAddresses={0x4D0A,0x4D0C,0x4D0E,0x4D10};maze.directionAddresses={0x4D2C,0x4D2D,0x4D2E,0x4D2F};
    maze.proofPCs={0x0008,0x0009,0x000A,0x000C,0x23F3,0x23F5,0x23F8,0x23FB,0x23FC,0x23FD,0x23FF,0x2419,0x241C,0x241F,0x2420,0x2421,0x2422,0x2428,0x2429,0x242A,0x242B,0x242C,0x242D,0x2430,0x2434,0x2436,0x243A,0x243D,0x2440,0x2442,0x2444,0x2445,0x200F,0x2012,0x2015,0x202D,0x2030,0x2034,0x2039,0x2043,0x2047,0x204A,0x204B,0x204E,0x2051,0x2944,0x2947,0x2949,0x294B};
    const auto mg=proveCanonicalMaze(analyzer);maze.sourceShapeProven=mg.shape&&mg.streamTerminated&&mg.inBounds;maze.passableNodes=mg.passableNodes;maze.minimumPassableDegree=mg.minimumDegree;maze.deadEndNodes=mg.deadEnds;
    maze.topologyComplete=maze.sourceShapeProven&&mg.streamEnd==0x35B1&&mg.encodedWrites==298&&mg.passableNodes==298&&mg.minimumDegree>=2&&mg.deadEnds==0;
    maze.retryExitApplicable=maze.topologyComplete;
    {std::ostringstream n;n<<"ROM-source clear $23F3 and maze decoder $2419 consume the canonical $40 background plus stream $3435-$"<<std::hex<<std::uppercase<<mg.streamEnd<<std::dec<<" and reconstructs "<<mg.passableNodes<<" passable interior nodes; minimum passable-neighbor degree="<<mg.minimumDegree<<", degree<2 nodes="<<mg.deadEnds<<". This proves the decoded maze topology itself has no one-exit/dead-end traversable node under the exact top-two-bit passability rule.";maze.note=n.str();}
    out.topologyInputs.push_back(maze);

    MazeTopologyTopologyInputRecord demo;demo.id=out.topologyInputs.size();demo.kind=MazeTopologyTopologyKind::CharacterDemoBarrier;demo.name="character-demo-barrier-corridor";demo.callerPCs=expectedCallers;demo.coordinateAddresses=maze.coordinateAddresses;demo.directionAddresses=maze.directionAddresses;
    demo.proofPCs={0x0506,0x0508,0x050B,0x050D,0x0511,0x0514,0x0517,0x0519,0x202D,0x2030,0x2034,0x2039,0x2043,0x2047,0x204A,0x204B,0x204E,0x2051,0x2128,0x21D0,0x260F,0x261E,0x2621,0x2624,0x2627,0x262A,0x1BF7,0x1BF9,0x1BFC,0x1C05,0x1CCE,0x1CD0,0x1CD3,0x1CDC,0x1DA5,0x1DA7,0x1DAA,0x1DB3,0x1E7C,0x1E7E,0x1E81,0x1E8A,0x1ED0,0x1ED9,0x1EE3,0x1EED,0x1EF0,0x1EF7,0x1EFA,0x1EFC};
    demo.fixedLowCoordinates={0x32};demo.blockedNeighborLowCoordinates={0x31,0x33};
    const bool coordinateToVideoShape=insn(analyzer,0x202D,"PUSH","AF")&&insn(analyzer,0x2030,"SUB","$20")&&insn(analyzer,0x2034,"SUB","$20")&&
        insn(analyzer,0x2039,"SLA","H")&&insn(analyzer,0x2043,"SLA","H")&&insn(analyzer,0x2047,"LD","C,H")&&
        insn(analyzer,0x204A,"ADD","HL,BC")&&insn(analyzer,0x204B,"LD","BC,$4040")&&insn(analyzer,0x204E,"ADD","HL,BC")&&insn(analyzer,0x2051,"RET","");
    demo.sourceShapeProven=insn(analyzer,0x0506,"LD","A,$FC")&&insn(analyzer,0x0508,"LD","DE,$0020")&&insn(analyzer,0x050B,"LD","B,$1C")&&insn(analyzer,0x050D,"LD","IX,$4040")&&insn(analyzer,0x0511,"LD","(IX+17),A")&&insn(analyzer,0x0514,"LD","(IX+19),A")&&insn(analyzer,0x0517,"ADD","IX,DE")&&insn(analyzer,0x0519,"DJNZ","$0511")&&coordinateToVideoShape&&
        insn(analyzer,0x261E,"LD","HL,$1E32")&&insn(analyzer,0x2621,"LD","($4D0A),HL")&&insn(analyzer,0x2624,"LD","($4D0C),HL")&&insn(analyzer,0x2627,"LD","($4D0E),HL")&&insn(analyzer,0x262A,"LD","($4D10),HL");
    demo.topologyComplete=false;demo.retryExitApplicable=false;
    demo.note="Source proves the attract/demo initializer seeds all four ghost tile coordinates at low coordinate $32. The exact $202D coordinate-to-video mapping makes coordinate lows $31/$33 map to $4040 row offsets +17/+19, matching the two 28-cell $FC barrier columns emitted by $0506. However, maze-topology analysis cannot yet prove a complete lifecycle inventory of every video-RAM writer between barrier setup and every later $291E call, so it does not assume the center corridor remains non-$C0 for every statically possible attract state.";
    out.topologyInputs.push_back(demo);

    MazeTopologyTopologyInputRecord lifecycle;lifecycle.id=out.topologyInputs.size();lifecycle.kind=MazeTopologyTopologyKind::UnresolvedLifecycle;lifecycle.name="screen-topology-lifecycle-coverage";lifecycle.callerPCs=expectedCallers;lifecycle.coordinateAddresses=maze.coordinateAddresses;lifecycle.directionAddresses=maze.directionAddresses;
    lifecycle.proofPCs={0x2108,0x210B,0x2128,0x2130,0x2136,0x21A1,0x21A5,0x21D0,0x2419,0x0506};lifecycle.sourceShapeProven=true;lifecycle.topologyComplete=false;lifecycle.retryExitApplicable=false;
    lifecycle.note="Both the canonical maze and the character/demo screen can reach ghost movement. The remaining static gap is a complete state-to-screen-writer lifecycle proof showing that every $291E scheduling state belongs to a topology whose current tile has at least two passable neighbors. Dynamic observations are intentionally not promoted into this static proof.";
    out.topologyInputs.push_back(lifecycle);

    const bool dirBaseShape=insn(analyzer,0x2929,"AND","$03")&&insn(analyzer,0x292B,"LD","HL,$4D3B")&&insn(analyzer,0x292E,"LD","(HL),A")&&insn(analyzer,0x292F,"ADD","A,A")&&insn(analyzer,0x2933,"LD","IX,$32FF")&&insn(analyzer,0x2937,"ADD","IX,DE");
    const bool retryShape=insn(analyzer,0x2957,"INC","IX")&&insn(analyzer,0x2959,"INC","IX")&&insn(analyzer,0x295B,"LD","HL,$4D3B")&&insn(analyzer,0x295E,"LD","A,(HL)")&&insn(analyzer,0x295F,"INC","A")&&insn(analyzer,0x2960,"AND","$03")&&insn(analyzer,0x2962,"LD","(HL),A")&&insn(analyzer,0x2963,"JP","$293D");
    const bool reverseShape=insn(analyzer,0x2921,"XOR","$02")&&insn(analyzer,0x2923,"LD","($4D3D),A")&&insn(analyzer,0x293D,"LD","A,($4D3D)")&&insn(analyzer,0x2940,"CP","(HL)")&&insn(analyzer,0x2941,"JP","Z,$2957");
    const bool passShape=insn(analyzer,0x2944,"CALL","$200F")&&insn(analyzer,0x2947,"AND","$C0")&&insn(analyzer,0x2949,"SUB","$C0")&&insn(analyzer,0x294B,"JR","Z,$2957")&&insn(analyzer,0x2015,"LD","A,(HL)")&&insn(analyzer,0x2016,"AND","A");
    const bool tunnelShape=insn(analyzer,0x1ED9,"CP","$1D")&&insn(analyzer,0x1EDE,"LD","(HL),$3D")&&insn(analyzer,0x1EE3,"CP","$3E")&&insn(analyzer,0x1EE8,"LD","(HL),$1E")&&insn(analyzer,0x1EED,"LD","B,$21")&&insn(analyzer,0x1EEF,"SUB","B")&&insn(analyzer,0x1EF0,"JP","C,$1EFC")&&insn(analyzer,0x1EF3,"LD","A,(HL)")&&insn(analyzer,0x1EF4,"LD","B,$3B")&&insn(analyzer,0x1EF6,"SUB","B")&&insn(analyzer,0x1EF7,"JP","NC,$1EFC")&&insn(analyzer,0x1EFA,"AND","A")&&insn(analyzer,0x1EFC,"SCF","");
    const bool tunnelCallGates=insn(analyzer,0x1BF9,"CALL","$1ED0")&&insn(analyzer,0x1BFC,"JR","C,$1C19")&&insn(analyzer,0x1CD0,"CALL","$1ED0")&&insn(analyzer,0x1CD3,"JR","C,$1CF0")&&insn(analyzer,0x1DA7,"CALL","$1ED0")&&insn(analyzer,0x1DAA,"JR","C,$1DC7")&&insn(analyzer,0x1E7E,"CALL","$1ED0")&&insn(analyzer,0x1E81,"JR","C,$1E9E");

    // Direction records are consumed directly from the user's authenticated ROM.
    // The only payload property retained by the tool is structural: the second
    // four-record block must duplicate the first four-record block byte-for-byte.
    const bool directionTableReadable=rom.size()>=0x330Fu;
    bool duplicateBacking=directionTableReadable;
    if(duplicateBacking)for(std::size_t i=0;i<8;++i)if(rom[0x32FFu+i]!=rom[0x3307u+i]){duplicateBacking=false;break;}
    for(std::size_t i=0;i<8;++i){MazeTopologyDirectionCandidateRecord c;c.id=out.directionCandidates.size();c.physicalRecordIndex=i;c.semanticDirection=static_cast<std::uint8_t>(i&3u);c.address=static_cast<std::uint16_t>(0x32FFu+2u*i);if(c.address+1u<rom.size()){c.deltaLow=rom[c.address];c.deltaHigh=rom[c.address+1u];}c.duplicateBacking=i>=4;c.byteExact=directionTableReadable;c.proofPCs={0x2929,0x292F,0x2933,0x2937,0x2957,0x2959,0x295F,0x2960,0x2962,0x2963,c.address};c.note=i<4?"primary semantic direction record":"runtime-verified backing duplicate of semantic direction record i mod 4; physical storage duplication is not a fifth semantic direction";out.directionCandidates.push_back(c);}

    MazeTopologyRetryLoopProofRecord loop;loop.id=out.retryLoopProofs.size();loop.callerPCs=actualCallers;loop.topologyInputIds={0,1,2};for(const auto& c:out.directionCandidates)loop.directionCandidateIds.insert(c.id);
    loop.proofPCs={0x1BF9,0x1BFC,0x1CD0,0x1CD3,0x1DA7,0x1DAA,0x1E7E,0x1E81,0x1ED0,0x1EFC,0x200F,0x2015,0x2419,0x2445,0x285B,0x2885,0x28AF,0x28D9,0x291E,0x2921,0x2923,0x2929,0x292E,0x292F,0x2933,0x2937,0x293D,0x2940,0x2941,0x2944,0x2947,0x2949,0x294B,0x294D,0x2950,0x2957,0x2959,0x295E,0x295F,0x2960,0x2962,0x2963,0x32FF,0x3307};
    loop.callerCoverageComplete=callerCoverage;loop.moduloCycleProven=dirBaseShape&&retryShape;loop.reverseRejectionProven=reverseShape;loop.ixProgressionProven=dirBaseShape&&retryShape;loop.passabilityTestProven=passShape;loop.tunnelWrapExclusionProven=tunnelShape&&tunnelCallGates;loop.duplicateBackingProven=duplicateBacking;loop.canonicalMazeExitProven=maze.retryExitApplicable&&loop.moduloCycleProven&&loop.reverseRejectionProven&&loop.passabilityTestProven;
    loop.allTopologyStatesComplete=false;loop.accepted=false;
    loop.missingStaticFact="complete attract/demo screen-writer lifecycle: prove every statically reachable $291E scheduling state retains at least two passable neighbors (or otherwise exits before a fifth semantic test)";
    loop.note="The retry selector is a four-state modulo cycle and IX advances one 2-byte physical record per rejection. The ROM contains two byte-identical copies of the four direction records, so a complete <=4-test proof would yield physical record indices 0..6, not merely the first four records. The canonical maze satisfies the needed degree>=2 invariant and tunnel/wrap states are source-gated away before random-choice scheduling. Because attract/demo screen lifecycle coverage is still incomplete, the global retry bound is deliberately not accepted.";
    out.retryLoopProofs.push_back(loop);

    const std::set<std::uint16_t> lowDomain={0x32FF,0x3301,0x3303,0x3305,0x3307,0x3309,0x330B};
    const std::set<std::uint16_t> highDomain={0x3300,0x3302,0x3304,0x3306,0x3308,0x330A,0x330C};
    auto addAddress=[&](std::uint16_t pc,const std::string& operand,const std::set<std::uint16_t>& candidate){
        MazeTopologyAddressProofRecord p;p.id=out.addressProofs.size();p.pc=pc;p.operand=operand;p.inheritedCommandStreamBlocker=true;p.candidateFiniteDomain=candidate;p.retryLoopProofIds={0};p.topologyInputIds={0,1,2};p.proofPCs=loop.proofPCs;p.candidateDomainConditional=true;p.accepted=loop.accepted;
        if(p.accepted){p.address=finiteAddress(candidate,p.proofPCs,"complete maze-topology analysis retry-loop finite address domain");p.domainClass=RootContextDomainClass::FiniteRom;}
        else{p.address=unknownAddress(p.proofPCs,"conditional finite set withheld because the global retry-loop topology invariant is incomplete");p.domainClass=RootContextDomainClass::Unresolved;}
        p.note="Conditional domain assuming the <=4 semantic-test invariant: "+std::to_string(candidate.size())+" physical byte addresses. The set is exported for audit, but accepted=false preserves the command-stream memory analysis blocker until every topology state is source-proven.";out.addressProofs.push_back(std::move(p));
    };
    addAddress(0x294D,"(IX+0)",lowDomain);addAddress(0x2950,"(IX+1)",highDomain);

    for(const auto& p:out.addressProofs)if(p.accepted)out.refinedInheritedBlockerPCs.insert(p.pc);else out.remainingBlockerPCs.insert(p.pc);
    return out;
}

std::string MazeTopologyAnalysis::topologyKindText(MazeTopologyTopologyKind kind){switch(kind){case MazeTopologyTopologyKind::CanonicalMazeDecoder:return"canonical-maze-decoder";case MazeTopologyTopologyKind::CharacterDemoBarrier:return"character-demo-barrier";default:return"unresolved-lifecycle";}}
std::string MazeTopologyAnalysis::residualKindText(MazeTopologyResidualKind kind){switch(kind){case MazeTopologyResidualKind::RetryLoopDependent:return"retry-loop-dependent";case MazeTopologyResidualKind::DecoderOrTableGap:return"decoder-or-table-gap";case MazeTopologyResidualKind::NoSemanticConsumer:return"no-semantic-consumer";default:return"genuine-unresolved";}}
bool MazeTopologyAnalysis::semanticRomClosureEligible(const MazeTopologyAddressProofRecord& proof){std::set<std::uint16_t>d;return proof.accepted&&proof.domainClass==RootContextDomainClass::FiniteRom&&proof.address.staticProof&&!proof.address.dynamicOnly&&!proof.address.hasUnknownAlternative&&RootContextAnalysis::completeFiniteDomain(proof.address,d)&&!d.empty();}

} // namespace pacripper
