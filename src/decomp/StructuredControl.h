#pragma once
// Created by Jacob Hodgkins

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace pacripper {

struct DominatorInfo {
    std::set<std::uint16_t> dominators;
    int immediateDominator = -1;
};

struct PostDominatorInfo {
    std::set<std::uint16_t> postDominators;
    int immediatePostDominator = -1;
};

struct LoopRegion {
    std::uint16_t header = 0;
    std::set<std::uint16_t> blocks;
    std::set<std::uint16_t> latches;
    std::set<std::uint16_t> exits;
};

enum class RegionKind {
    Block,
    Sequence,
    If,
    IfElse,
    While,
    DoWhile,
    GotoFallback
};

struct StructuredRegion {
    RegionKind kind = RegionKind::GotoFallback;
    std::uint16_t entry = 0;
    std::uint16_t conditionAddress = 0;
    std::string condition;
    int join = -1;
    int trueTarget = -1;
    int falseTarget = -1;
    std::set<std::uint16_t> blocks;
    std::set<std::uint16_t> trueBlocks;
    std::set<std::uint16_t> falseBlocks;
    std::set<std::uint16_t> sourceBlocks;
    std::vector<StructuredRegion> children;
};

struct StructuralGraph {
    std::uint16_t entry = 0;
    std::set<std::uint16_t> nodes;
    std::map<std::uint16_t,std::set<std::uint16_t>> successors;
    std::map<std::uint16_t,std::set<std::uint16_t>> predecessors;
    std::set<std::uint16_t> exits;
    std::set<std::uint16_t> externalEntryBlocks;
};

struct BranchDescriptor {
    std::uint16_t block = 0;
    std::uint16_t sourceAddress = 0;
    int taken = -1;
    int notTaken = -1;
    std::string takenCondition;
    std::string notTakenCondition;
};

struct StructureAnalysis {
    StructuralGraph graph;
    std::map<std::uint16_t,DominatorInfo> dominators;
    std::map<std::uint16_t,PostDominatorInfo> postDominators;
    std::vector<LoopRegion> loops;
    std::vector<StructuredRegion> regions;
    std::set<std::uint16_t> fallbackBlocks;
};

class StructuredControl {
public:
    static void rebuildPredecessors(StructuralGraph& graph);
    static std::set<std::uint16_t> reachableNodes(const StructuralGraph& graph);
    static std::map<std::uint16_t,DominatorInfo> computeDominators(const StructuralGraph& graph);
    static std::map<std::uint16_t,PostDominatorInfo> computePostDominators(const StructuralGraph& graph);
    static std::vector<LoopRegion> detectNaturalLoops(const StructuralGraph& graph,
                                                       const std::map<std::uint16_t,DominatorInfo>& dominators);
    static std::vector<StructuredRegion> recognizeRegions(
        const StructuralGraph& graph,
        const std::map<std::uint16_t,DominatorInfo>& dominators,
        const std::map<std::uint16_t,PostDominatorInfo>& postDominators,
        const std::vector<LoopRegion>& loops,
        const std::map<std::uint16_t,BranchDescriptor>& branches);
    static StructureAnalysis analyze(const StructuralGraph& graph,
                                     const std::map<std::uint16_t,BranchDescriptor>& branches);
    static bool dominates(const std::map<std::uint16_t,DominatorInfo>& dominators,
                          std::uint16_t dominator,std::uint16_t node);
    static std::string regionKindText(RegionKind kind);
    static std::vector<const StructuredRegion*> flattenRegions(const std::vector<StructuredRegion>& roots);
};

} // namespace pacripper
