// PacRipper intermission analysis intermission lifecycle / retry-loop closure
// Created by Jacob Hodgkins

#include "IntermissionAnalysis.h"
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

std::vector<std::uint16_t> readWords(const std::vector<std::uint8_t>&rom,std::uint16_t start,std::size_t count){
    std::vector<std::uint16_t> out;
    if(static_cast<std::size_t>(start)+count*2u>rom.size())return out;
    out.reserve(count);
    for(std::size_t i=0;i<count;++i){
        const auto p=static_cast<std::size_t>(start)+2u*i;
        out.push_back(static_cast<std::uint16_t>(rom[p]|(static_cast<std::uint16_t>(rom[p+1])<<8)));
    }
    return out;
}

AddressLatticeValue finiteAddress(const std::set<std::uint16_t>&values,const std::set<std::uint16_t>&pcs,const std::string&note){
    AddressLatticeValue a;a.kind=values.size()==1?AddressValueKind::Exact:AddressValueKind::FiniteSet;a.values=values;
    if(!values.empty()){a.rangeStart=*values.begin();a.rangeEnd=*values.rbegin();}a.stride=values.size()==1?0:1;a.hasUnknownAlternative=false;a.wraparound=false;a.staticProof=true;a.dynamicOnly=false;a.provenancePCs=pcs;a.note=note;return a;
}

std::set<std::uint16_t> criticalCorridor(){
    std::set<std::uint16_t> s;for(unsigned row=0;row<0x1Cu;++row)s.insert(static_cast<std::uint16_t>(0x4052u+0x20u*row));return s;
}

bool intersects(const std::set<std::uint16_t>&a,const std::set<std::uint16_t>&b){
    for(auto v:a){
        if(b.count(v))return true;
    }
    return false;
}

void addRange(std::set<std::uint16_t>&s,std::uint16_t start,std::uint16_t end){for(std::uint32_t a=start;a<end;++a)s.insert(static_cast<std::uint16_t>(a));}

std::set<std::uint16_t> fruitHudTargets(){
    // $2BEA/$2B8F starts the video update sweep at $4004, advances two bytes per
    // displayed fruit, and each 2x2 glyph touches base, base+1, base+$20,
    // base+$21.  The clamped count is seven, so this set is exhaustive.
    std::set<std::uint16_t>s;for(unsigned i=0;i<7;++i){const auto b=static_cast<std::uint16_t>(0x4004u+2u*i);s.insert(b);s.insert(static_cast<std::uint16_t>(b+1));s.insert(static_cast<std::uint16_t>(b+0x20));s.insert(static_cast<std::uint16_t>(b+0x21));}return s;
}

bool valueBlocks(std::uint8_t v){return (v&0xC0u)==0xC0u;}

} // namespace

IntermissionAnalysisResult IntermissionAnalysis::analyze(const Analyzer&analyzer,const std::vector<HardwareAccessRecord>&hardwareAccesses,const std::vector<MazeTopologyRetryLoopProofRecord>&mazeTopologyRetryProofs,const std::vector<MazeTopologyAddressProofRecord>&mazeTopologyAddressProofs){
    IntermissionAnalysisResult out;const auto&rom=analyzer.program();out.inheritedBlockerPCs={0x294D,0x2950};
    const auto corridor=criticalCorridor();

    auto addDispatch=[&](IntermissionDispatchKind kind,std::uint16_t pc,std::uint16_t start,std::size_t entryCount,const std::set<std::uint16_t>&pcs,const std::string&note){
        // Dispatch contents are read from the user's validated ROM at runtime.
        // No canonical table payload is duplicated in PacRipper's source/binary.
        IntermissionDispatchProofRecord r;r.id=out.dispatchProofs.size();r.kind=kind;r.dispatchPC=pc;r.tableStart=start;r.entryCount=entryCount;r.targets=readWords(rom,start,entryCount);r.proofPCs=pcs;r.sourceShapeProven=insn(analyzer,pc,"RST","$0020")&&r.targets.size()==entryCount;r.complete=r.sourceShapeProven;r.note=note;out.dispatchProofs.push_back(std::move(r));
    };
    addDispatch(IntermissionDispatchKind::GlobalGameState,0x06C1,0x06C2,38,{0x06BE,0x06C1,0x06C2,0x0A0E,0x0A2C,0x0A7C},"$4E04 global state table is source-complete; intermission setup/dispatch/cleanup occupy states 30/32/34 with wait slots between them.");
    addDispatch(IntermissionDispatchKind::IntermissionSelect,0x0A44,0x0A45,21,{0x0A3B,0x0A40,0x0A42,0x0A44,0x0A45},"$4E13 is clamped to $14 before this 21-entry table, exhaustively selecting either the no-intermission exit or one of the three intermission machines.");
    addDispatch(IntermissionDispatchKind::FirstIntermission,0x210B,0x210C,7,{0x2108,0x210B,0x210C,0x2186},"Seven-state first intermission table.");
    addDispatch(IntermissionDispatchKind::SecondIntermission,0x21A5,0x21A6,14,{0x219E,0x21A5,0x21A6,0x228D},"Fourteen-state second intermission table including explicit wait slots.");
    addDispatch(IntermissionDispatchKind::ThirdIntermission,0x229A,0x229B,6,{0x2297,0x229A,0x229B,0x22FE},"Six-state third intermission table.");
    addDispatch(IntermissionDispatchKind::TimerScheduler,0x0246,0x0247,10,{0x0030,0x0051,0x0221,0x0246,0x0247,0x212B,0x21F0,0x22B9},"The ten-entry delayed scheduler is source-complete; intermission payload command bytes 7/8/9 map only to state-advance handlers $212B/$21F0/$22B9.");

    auto addWriter=[&](IntermissionWriterKind kind,const std::string&name,const std::set<std::uint16_t>&pcs,const std::set<std::uint16_t>&targets,const std::set<std::uint8_t>&values,bool exact,bool reachable,bool shape,const std::string&note){
        IntermissionVideoWriterProofRecord r;r.id=out.writerProofs.size();r.kind=kind;r.name=name;r.writerPCs=pcs;r.targetAddresses=targets;r.writtenValues=values;r.targetSetExact=exact;r.lifecycleReachable=reachable;r.touchesCriticalCorridor=intersects(targets,corridor);r.canWriteBlockingValue=false;for(auto v:values)if(valueBlocks(v))r.canWriteBlockingValue=true;r.sourceShapeProven=shape;r.note=note;out.writerProofs.push_back(std::move(r));
    };

    std::set<std::uint16_t> core;addRange(core,0x4040,0x43C0);
    const bool fillShape=insn(analyzer,0x2400,"LD","A,$40")&&insn(analyzer,0x2402,"LD","HL,$4040")&&insn(analyzer,0x2405,"LD","BC,$8004")&&insn(analyzer,0x2408,"RST","$0008")&&insn(analyzer,0x2409,"DEC","C")&&insn(analyzer,0x240A,"JR","NZ,$2408");
    addWriter(IntermissionWriterKind::PlayfieldFill,"intermission-playfield-fill",{0x0A0E,0x23ED,0x2400,0x2408},core,{0x40},true,true,fillShape,"RST $28 payload {task 0,arg 1} dispatches through $23ED to $2400. B=$80 then B=0 on the next three RST $08 passes fills exactly $4040-$43BF with passable $40.");
    const bool scrubShape=insn(analyzer,0x2A35,"LD","DE,$4040")&&insn(analyzer,0x2A38,"LD","HL,$43C0")&&insn(analyzer,0x2A3F,"LD","A,(DE)")&&insn(analyzer,0x2A40,"CP","$10")&&insn(analyzer,0x2A45,"CP","$12")&&insn(analyzer,0x2A4A,"CP","$14")&&insn(analyzer,0x2A53,"LD","A,$40")&&insn(analyzer,0x2A55,"LD","(DE),A");
    addWriter(IntermissionWriterKind::PlayfieldScrub,"intermission-tile-scrub",{0x0A17,0x23CE,0x2A35,0x2A55},core,{0x40},true,true,scrubShape,"Setup task 19 scans only $4040-$43BF and can only replace tile codes $10/$12/$14 with passable $40.");

    std::set<std::uint16_t> sides;for(unsigned row=0;row<0x1Cu;++row){sides.insert(static_cast<std::uint16_t>(0x4051u+0x20u*row));sides.insert(static_cast<std::uint16_t>(0x4053u+0x20u*row));}
    const bool barrierShape=insn(analyzer,0x0506,"LD","A,$FC")&&insn(analyzer,0x0508,"LD","DE,$0020")&&insn(analyzer,0x050B,"LD","B,$1C")&&insn(analyzer,0x050D,"LD","IX,$4040")&&insn(analyzer,0x0511,"LD","(IX+17),A")&&insn(analyzer,0x0514,"LD","(IX+19),A")&&insn(analyzer,0x0517,"ADD","IX,DE")&&insn(analyzer,0x0519,"DJNZ","$0511");
    const bool centerMarkerShape=insn(analyzer,0x0501,"LD","HL,$4332")&&insn(analyzer,0x0504,"LD","(HL),$14");
    addWriter(IntermissionWriterKind::IntermissionAnimation,"demo-center-marker",{0x0501,0x0504},{0x4332},{0x14},true,true,centerMarkerShape,"The source-exact $0504 write lands on a critical low-$32 corridor cell but writes tile $14, which is passable under the top-two-bit test. It is modeled explicitly so trace-assisted reachability cannot turn it into a pessimistic unknown-value veto.");
    addWriter(IntermissionWriterKind::SideBarrier,"intermission-side-barriers",{0x0506,0x0511,0x0514,0x211A,0x21D0,0x22B6},sides,{0xFC},true,true,barrierShape,"$0506 writes blocking $FC only to low-coordinate $31/$33 side columns for high coordinates $20-$3B; the critical low-$32 center corridor is disjoint.");

    auto anim=[&](const std::string&name,const std::set<std::uint16_t>&pcs,const std::set<std::uint16_t>&targets,const std::set<std::uint8_t>&vals,bool shape){addWriter(IntermissionWriterKind::IntermissionAnimation,name,pcs,targets,vals,true,true,shape,"Second-intermission animation write; every possible tile value has top bits != $C0 and is therefore passable to $2947-$294B.");};
    anim("intermission-2-state0",{0x21A1,0x21D3,0x21D7},{0x41D2,0x41D3},{0x60,0x61},insn(analyzer,0x21A1,"LD","IY,$41D2")&&insn(analyzer,0x21D3,"LD","(IY+0),$60")&&insn(analyzer,0x21D7,"LD","(IY+1),$61"));
    anim("intermission-2-state4",{0x220C,0x2214,0x2218},{0x41D2,0x41D3},{0x62,0x63},insn(analyzer,0x2214,"LD","(IY+0),$62")&&insn(analyzer,0x2218,"LD","(IY+1),$63"));
    anim("intermission-2-state5",{0x221E,0x2225,0x2229,0x222D,0x2231},{0x41D2,0x41D3,0x41F2,0x41F3},{0x64,0x65,0x66,0x67},insn(analyzer,0x2225,"LD","(IY+0),$64")&&insn(analyzer,0x2229,"LD","(IY+1),$65")&&insn(analyzer,0x222D,"LD","(IY+32),$66")&&insn(analyzer,0x2231,"LD","(IY+33),$67"));
    anim("intermission-2-state6",{0x2244,0x224B,0x224F,0x2253,0x2257},{0x41D2,0x41D3,0x41F2,0x41F3},{0x68,0x69,0x6A,0x6B},insn(analyzer,0x224B,"LD","(IY+0),$68")&&insn(analyzer,0x224F,"LD","(IY+1),$69")&&insn(analyzer,0x2253,"LD","(IY+32),$6A")&&insn(analyzer,0x2257,"LD","(IY+33),$6B"));
    anim("intermission-2-state9",{0x226A,0x226F,0x2273,0x2277,0x227B},{0x41D2,0x41D3,0x41F2,0x41F3},{0x40,0x6C,0x6D},insn(analyzer,0x226F,"LD","(IY+0),$6C")&&insn(analyzer,0x2273,"LD","(IY+1),$6D")&&insn(analyzer,0x2277,"LD","(IY+32),$40")&&insn(analyzer,0x227B,"LD","(IY+33),$40"));

    // Setup task 16 eventually calls $2BEA.  Its video half is a seven-slot
    // HUD strip at $4004..$4031; color writes use the +$0400 mirror and are
    // irrelevant to topology.
    const auto hudTargets=fruitHudTargets();
    const bool hudShape=insn(analyzer,0x2BFF,"LD","HL,$4004")&&insn(analyzer,0x2C03,"CALL","$2B8F")&&insn(analyzer,0x2B91,"LD","DE,$001F")&&insn(analyzer,0x2B94,"LD","(HL),A")&&insn(analyzer,0x2B97,"LD","(HL),A")&&insn(analyzer,0x2B9A,"LD","(HL),A")&&insn(analyzer,0x2B9D,"LD","(HL),A");
    addWriter(IntermissionWriterKind::HudOrIrq,"setup-fruit-hud",{0x070E,0x0792,0x2BEA,0x2BFF,0x2B8F},hudTargets,{},true,true,hudShape,"Setup task 16 reaches the fruit/HUD renderer; its video targets are exhaustively outside the low-$32 center corridor. Values need not be bounded because the address sets are disjoint.");

    const std::set<std::uint16_t>irqTargets={0x43D8,0x43D9,0x43DA,0x43C5,0x43C6,0x43C7};
    const bool irqShape=insn(analyzer,0x0325,"LD","IX,$43D8")&&insn(analyzer,0x0329,"LD","IY,$43C5")&&
        insn(analyzer,0x0369,"LD","(IX+0),$50")&&insn(analyzer,0x036D,"LD","(IX+1),$55")&&insn(analyzer,0x0371,"LD","(IX+2),$31")&&
        insn(analyzer,0x0376,"LD","(IY+0),$50")&&insn(analyzer,0x037A,"LD","(IY+1),$55")&&insn(analyzer,0x037E,"LD","(IY+2),$32")&&
        insn(analyzer,0x0383,"LD","(IX+0),$40")&&insn(analyzer,0x0390,"LD","(IY+0),$40");
    addWriter(IntermissionWriterKind::HudOrIrq,"irq-status-text",{0x0325,0x0329,0x0369,0x0376,0x0383,0x0390},irqTargets,{0x31,0x32,0x40,0x50,0x55},true,true,irqShape,"The ordinary IRQ status writer is exhaustively rooted at $43C5-$43C7/$43D8-$43DA, beyond the critical corridor maximum $43B2.");

    // Ordinary statically resolved video writes found by the inherited hardware
    // analysis are all retained in the audit. They are not assumed lifecycle-reachable;
    // if one is in the critical corridor, acceptance is withheld unless modeled
    // explicitly above.
    std::set<std::uint16_t>modeledWriterPCs;for(const auto&w:out.writerProofs)modeledWriterPCs.insert(w.writerPCs.begin(),w.writerPCs.end());
    for(const auto&h:hardwareAccesses){
        if(modeledWriterPCs.count(h.pc))continue;
        if(h.device!=BoardDeviceKind::VideoRam||!(h.access==MemoryAccessKind::Write||h.access==MemoryAccessKind::ReadWrite)||!h.staticProof||h.addressResolution==AddressResolutionKind::Unresolved)continue;
        std::set<std::uint16_t>targets;addRange(targets,h.start,h.end);if(targets.empty())continue;
        IntermissionVideoWriterProofRecord r;r.id=out.writerProofs.size();r.kind=IntermissionWriterKind::StaticExactOther;r.name="inherited-static-video-write";r.writerPCs={h.pc};r.targetAddresses=targets;r.targetSetExact=h.addressResolution==AddressResolutionKind::ExactStatic;r.lifecycleReachable=false;r.touchesCriticalCorridor=intersects(targets,corridor);r.canWriteBlockingValue=r.touchesCriticalCorridor;r.sourceShapeProven=true;r.note=r.touchesCriticalCorridor?"Inherited exact/static writer overlaps the critical corridor and therefore requires explicit lifecycle/value modeling before closure.":"Inherited exact/static video writer is spatially disjoint from the critical low-$32 center corridor.";out.writerProofs.push_back(std::move(r));
    }

    IntermissionLifecycleProofRecord life;life.id=0;life.criticalCorridorAddresses=corridor;life.chooserCallers={0x285B,0x2885,0x28AF,0x28D9};for(const auto&r:out.dispatchProofs)life.dispatchProofIds.insert(r.id);for(const auto&r:out.writerProofs)life.writerProofIds.insert(r.id);
    // The core has already authenticated the complete board ROM manifest.
    // Here we prove only that the runtime task table is readable at its known
    // semantic extent; its contents remain solely in the user's input ROM.
    life.setupQueueShapeProven=(rom.size()==0x4000u)&&readWords(rom,0x23A8,32).size()==32;
    life.playfieldClearBeforeIntermissionProven=life.setupQueueShapeProven&&fillShape&&insn(analyzer,0x0894,"LD","HL,$4E04")&&insn(analyzer,0x0897,"INC","(HL)");
    life.ghostInitializerProven=insn(analyzer,0x2571,"LD","A,B")&&insn(analyzer,0x2573,"JP","NZ,$260F")&&insn(analyzer,0x261E,"LD","HL,$1E32")&&insn(analyzer,0x2621,"LD","($4D0A),HL")&&insn(analyzer,0x2624,"LD","($4D0C),HL")&&insn(analyzer,0x2627,"LD","($4D0E),HL")&&insn(analyzer,0x262A,"LD","($4D10),HL");
    life.coordinateMappingProven=insn(analyzer,0x202D,"PUSH","AF")&&insn(analyzer,0x2030,"SUB","$20")&&insn(analyzer,0x2034,"SUB","$20")&&insn(analyzer,0x204B,"LD","BC,$4040")&&insn(analyzer,0x204E,"ADD","HL,BC")&&insn(analyzer,0x2051,"RET","");
    life.interiorGateProven=insn(analyzer,0x1ED9,"CP","$1D")&&insn(analyzer,0x1EE3,"CP","$3E")&&insn(analyzer,0x1EED,"LD","B,$21")&&insn(analyzer,0x1EEF,"SUB","B")&&insn(analyzer,0x1EF0,"JP","C,$1EFC")&&insn(analyzer,0x1EF4,"LD","B,$3B")&&insn(analyzer,0x1EF6,"SUB","B")&&insn(analyzer,0x1EF7,"JP","NC,$1EFC")&&insn(analyzer,0x1EFA,"AND","A")&&insn(analyzer,0x1EFC,"SCF","")&&insn(analyzer,0x1BF9,"CALL","$1ED0")&&insn(analyzer,0x1BFC,"JR","C,$1C19")&&insn(analyzer,0x1CD0,"CALL","$1ED0")&&insn(analyzer,0x1CD3,"JR","C,$1CF0")&&insn(analyzer,0x1DA7,"CALL","$1ED0")&&insn(analyzer,0x1DAA,"JR","C,$1DC7")&&insn(analyzer,0x1E7E,"CALL","$1ED0")&&insn(analyzer,0x1E81,"JR","C,$1E9E");
    life.stateDispatchComplete=!out.dispatchProofs.empty()&&std::all_of(out.dispatchProofs.begin(),out.dispatchProofs.end(),[](const auto&r){return r.complete;});
    life.delayedTransitionsComplete=out.dispatchProofs.size()>=6&&out.dispatchProofs.back().complete;
    life.taskQueueDrainProven=insn(analyzer,0x0028,"POP","HL")&&insn(analyzer,0x0029,"LD","B,(HL)")&&insn(analyzer,0x002B,"LD","C,(HL)")&&insn(analyzer,0x0042,"LD","HL,($4C80)")&&insn(analyzer,0x0045,"LD","(HL),B")&&insn(analyzer,0x0047,"LD","(HL),C")&&insn(analyzer,0x238D,"LD","HL,($4C82)")&&insn(analyzer,0x2392,"JP","M,$238D")&&insn(analyzer,0x2395,"LD","(HL),$FF")&&insn(analyzer,0x23A0,"LD","($4C82),HL")&&insn(analyzer,0x23A3,"LD","HL,$238D")&&insn(analyzer,0x23A6,"PUSH","HL")&&insn(analyzer,0x23A7,"RST","$0020");
    life.criticalCorridorInitializedPassable=life.playfieldClearBeforeIntermissionProven&&life.ghostInitializerProven&&life.coordinateMappingProven&&fillShape;

    bool modeledCriticalSafe=true;bool allManualShapes=true;for(const auto&w:out.writerProofs){
        if(w.kind!=IntermissionWriterKind::StaticExactOther&&w.lifecycleReachable)allManualShapes=allManualShapes&&w.sourceShapeProven;
        if(w.lifecycleReachable&&w.touchesCriticalCorridor&&w.canWriteBlockingValue)modeledCriticalSafe=false;
        // Inherited static exact writers are only a veto if they overlap the corridor.
        if(w.kind==IntermissionWriterKind::StaticExactOther&&w.touchesCriticalCorridor)modeledCriticalSafe=false;
    }
    // Complete state-table/scheduler proofs plus the explicit writer groups above form the
    // source inventory for the intermission lifecycle. No dynamic trace bound is used.
    life.relevantWriterInventoryComplete=allManualShapes&&life.stateDispatchComplete&&life.delayedTransitionsComplete&&life.taskQueueDrainProven&&life.setupQueueShapeProven;
    life.criticalCorridorPreservedPassable=life.criticalCorridorInitializedPassable&&life.relevantWriterInventoryComplete&&modeledCriticalSafe;
    life.canonicalMazeRetryExitInherited=!mazeTopologyRetryProofs.empty()&&mazeTopologyRetryProofs.front().callerCoverageComplete&&mazeTopologyRetryProofs.front().moduloCycleProven&&mazeTopologyRetryProofs.front().reverseRejectionProven&&mazeTopologyRetryProofs.front().ixProgressionProven&&mazeTopologyRetryProofs.front().passabilityTestProven&&mazeTopologyRetryProofs.front().tunnelWrapExclusionProven&&mazeTopologyRetryProofs.front().duplicateBackingProven&&mazeTopologyRetryProofs.front().canonicalMazeExitProven;
    life.intermissionRetryExitProven=life.criticalCorridorPreservedPassable&&life.interiorGateProven&&barrierShape;
    const bool inheritedAddressCandidatesComplete=mazeTopologyAddressProofs.size()==2&&
        mazeTopologyAddressProofs[0].pc==0x294D&&mazeTopologyAddressProofs[0].candidateDomainConditional&&mazeTopologyAddressProofs[0].candidateFiniteDomain==std::set<std::uint16_t>{0x32FF,0x3301,0x3303,0x3305,0x3307,0x3309,0x330B}&&
        mazeTopologyAddressProofs[1].pc==0x2950&&mazeTopologyAddressProofs[1].candidateDomainConditional&&mazeTopologyAddressProofs[1].candidateFiniteDomain==std::set<std::uint16_t>{0x3300,0x3302,0x3304,0x3306,0x3308,0x330A,0x330C};
    life.allTopologyStatesComplete=life.canonicalMazeRetryExitInherited&&life.intermissionRetryExitProven&&inheritedAddressCandidatesComplete;
    life.accepted=life.allTopologyStatesComplete;
    life.proofPCs={0x0030,0x0051,0x0221,0x0246,0x0247,0x0325,0x0329,0x0369,0x0376,0x0383,0x0390,0x0501,0x0504,0x0506,0x06BE,0x06C1,0x0A0E,0x0A23,0x0A2C,0x0A44,0x1BF9,0x1CD0,0x1DA7,0x1E7E,0x1ED0,0x1EFC,0x202D,0x2108,0x210B,0x21A5,0x229A,0x238D,0x23A7,0x23ED,0x2400,0x253D,0x2573,0x260F,0x261E,0x2A35,0x291E,0x294D,0x2950,0x2957,0x2963,0x32FF,0x3307};
    if(life.accepted){life.missingStaticFact.clear();life.note="intermission analysis closes the maze-topology analysis lifecycle gap. Intermission setup fills the critical low-$32 corridor for high coordinates $20-$3B with $40; all four ghosts are initialized at low $32; $1ED0 permits random-choice scheduling only while high is $21-$3A, so both high-axis neighbors always remain inside that 28-row corridor. Every lifecycle writer that can touch the critical center cells writes only non-$C0 values; $0506's $FC writes are confined to low $31/$33 side columns. Together with the inherited four-state retry/reverse/passability proof, every $291E topology now exits within four semantic tests.";}
    else{life.missingStaticFact="one or more source-shape, dispatch, writer, coordinate, gate, or inherited retry predicates failed";life.note="intermission analysis remains conservative because the static lifecycle proof did not validate completely against this ROM/source shape.";}
    out.lifecycleProofs.push_back(life);

    const std::set<std::uint16_t>low={0x32FF,0x3301,0x3303,0x3305,0x3307,0x3309,0x330B};
    const std::set<std::uint16_t>high={0x3300,0x3302,0x3304,0x3306,0x3308,0x330A,0x330C};
    auto addAddress=[&](std::uint16_t pc,const std::string&operand,const std::set<std::uint16_t>&domain){IntermissionAddressProofRecord p;p.id=out.addressProofs.size();p.pc=pc;p.operand=operand;p.finiteDomain=domain;p.lifecycleProofIds={0};p.proofPCs=life.proofPCs;p.inheritedMazeTopologyBlocker=true;p.accepted=life.accepted;if(p.accepted){p.address=finiteAddress(domain,p.proofPCs,"intermission analysis source-complete <=4 semantic-test retry bound");p.domainClass=RootContextDomainClass::FiniteRom;p.note="Accepted finite ROM domain: modulo-4 retry plus at most three rejections reaches physical direction records 0..6 only; duplicate backing at records 4..6 is required and record 7 ($330D/$330E) is unreachable.";}else{p.domainClass=RootContextDomainClass::Unresolved;p.note="Finite candidate withheld because the intermission analysis lifecycle proof is not accepted.";}out.addressProofs.push_back(std::move(p));};
    addAddress(0x294D,"(IX+0)",low);addAddress(0x2950,"(IX+1)",high);
    for(const auto&p:out.addressProofs){if(p.accepted)out.refinedInheritedBlockerPCs.insert(p.pc);else out.remainingBlockerPCs.insert(p.pc);}return out;
}

std::string IntermissionAnalysis::dispatchKindText(IntermissionDispatchKind kind){switch(kind){case IntermissionDispatchKind::GlobalGameState:return"global-game-state";case IntermissionDispatchKind::IntermissionSelect:return"intermission-select";case IntermissionDispatchKind::FirstIntermission:return"first-intermission";case IntermissionDispatchKind::SecondIntermission:return"second-intermission";case IntermissionDispatchKind::ThirdIntermission:return"third-intermission";default:return"timer-scheduler";}}
std::string IntermissionAnalysis::writerKindText(IntermissionWriterKind kind){switch(kind){case IntermissionWriterKind::PlayfieldFill:return"playfield-fill";case IntermissionWriterKind::PlayfieldScrub:return"playfield-scrub";case IntermissionWriterKind::SideBarrier:return"side-barrier";case IntermissionWriterKind::IntermissionAnimation:return"intermission-animation";case IntermissionWriterKind::HudOrIrq:return"hud-or-irq";default:return"static-exact-other";}}
bool IntermissionAnalysis::semanticRomClosureEligible(const IntermissionAddressProofRecord&proof){std::set<std::uint16_t>d;return proof.accepted&&proof.domainClass==RootContextDomainClass::FiniteRom&&proof.address.staticProof&&!proof.address.dynamicOnly&&!proof.address.hasUnknownAlternative&&RootContextAnalysis::completeFiniteDomain(proof.address,d)&&!d.empty();}

} // namespace pacripper
