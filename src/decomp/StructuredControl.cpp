// Created by Jacob Hodgkins
#include "StructuredControl.h"

#include <algorithm>
#include <limits>
#include <queue>
#include <functional>

namespace pacripper {
namespace {

std::set<std::uint16_t> setIntersection(const std::set<std::uint16_t>& a,
                                        const std::set<std::uint16_t>& b) {
    std::set<std::uint16_t> out;
    std::set_intersection(a.begin(),a.end(),b.begin(),b.end(),std::inserter(out,out.end()));
    return out;
}

bool setsOverlap(const std::set<std::uint16_t>& a,const std::set<std::uint16_t>& b) {
    auto i=a.begin(),j=b.begin();
    while(i!=a.end()&&j!=b.end()) {
        if(*i==*j) return true;
        if(*i<*j) ++i; else ++j;
    }
    return false;
}

bool isSubset(const std::set<std::uint16_t>& a,const std::set<std::uint16_t>& b) {
    return std::includes(b.begin(),b.end(),a.begin(),a.end());
}

std::set<std::uint16_t> collectBranchRegion(
    const StructuralGraph& graph,
    const std::map<std::uint16_t,DominatorInfo>& dom,
    const std::map<std::uint16_t,PostDominatorInfo>& pdom,
    std::uint16_t conditionBlock,std::uint16_t start,std::uint16_t join,bool& valid) {
    valid=true;
    std::set<std::uint16_t> region;
    std::queue<std::uint16_t> q;
    q.push(start);
    while(!q.empty()) {
        const auto n=q.front();q.pop();
        if(n==join) continue;
        if(n==conditionBlock || !graph.nodes.count(n)) { valid=false; break; }
        if(region.count(n)) continue;
        const auto di=dom.find(n);
        const auto pi=pdom.find(n);
        if(di==dom.end() || !di->second.dominators.count(conditionBlock) ||
           pi==pdom.end() || !pi->second.postDominators.count(join)) {
            valid=false;break;
        }
        region.insert(n);
        const auto si=graph.successors.find(n);
        if(si==graph.successors.end()) continue;
        for(auto s:si->second) if(s!=join) q.push(s);
    }
    return region;
}

bool branchHasSafeEntries(const StructuralGraph& graph,
                          const std::set<std::uint16_t>& region,
                          std::uint16_t conditionBlock) {
    for(auto n:region) {
        if(graph.externalEntryBlocks.count(n)) return false;
        const auto pi=graph.predecessors.find(n);
        if(pi==graph.predecessors.end()) continue;
        for(auto p:pi->second) if(p!=conditionBlock && !region.count(p)) return false;
    }
    return true;
}

bool branchHasOnlyLocalExits(const StructuralGraph& graph,
                             const std::set<std::uint16_t>& region,
                             std::uint16_t join) {
    for(auto n:region) {
        const auto si=graph.successors.find(n);
        if(si==graph.successors.end()) continue;
        for(auto s:si->second) if(s!=join && !region.count(s)) return false;
    }
    return true;
}

std::vector<StructuredRegion> makeLaminar(std::vector<StructuredRegion> regions) {
    std::vector<StructuredRegion> accepted;
    for(auto& candidate:regions) {
        bool partial=false;
        for(const auto& existing:accepted) {
            if(!setsOverlap(candidate.blocks,existing.blocks)) continue;
            if(isSubset(candidate.blocks,existing.blocks) || isSubset(existing.blocks,candidate.blocks)) continue;
            partial=true;break;
        }
        if(!partial) accepted.push_back(candidate);
    }
    if(accepted.empty()) return accepted;

    const std::size_t n=accepted.size();
    std::vector<int> parent(n,-1);
    for(std::size_t i=0;i<n;++i) {
        std::size_t bestSize=std::numeric_limits<std::size_t>::max();
        for(std::size_t j=0;j<n;++j) {
            if(i==j || accepted[j].blocks.size()<=accepted[i].blocks.size()) continue;
            if(isSubset(accepted[i].blocks,accepted[j].blocks) && accepted[j].blocks.size()<bestSize) {
                parent[i]=static_cast<int>(j);bestSize=accepted[j].blocks.size();
            }
        }
    }
    std::vector<std::vector<std::size_t>> children(n);
    std::vector<std::size_t> roots;
    for(std::size_t i=0;i<n;++i) {
        if(parent[i]<0) roots.push_back(i); else children[static_cast<std::size_t>(parent[i])].push_back(i);
    }
    std::function<StructuredRegion(std::size_t)> build=[&](std::size_t i) {
        StructuredRegion r=accepted[i];r.children.clear();
        for(auto c:children[i]) r.children.push_back(build(c));
        std::sort(r.children.begin(),r.children.end(),[](const StructuredRegion&a,const StructuredRegion&b){return a.entry<b.entry;});
        return r;
    };
    std::vector<StructuredRegion> out;
    for(auto r:roots) out.push_back(build(r));
    std::sort(out.begin(),out.end(),[](const StructuredRegion&a,const StructuredRegion&b){return a.entry<b.entry;});
    return out;
}

void flattenOne(const StructuredRegion& r,std::vector<const StructuredRegion*>& out) {
    out.push_back(&r);
    for(const auto& c:r.children) flattenOne(c,out);
}

} // namespace

void StructuredControl::rebuildPredecessors(StructuralGraph& graph) {
    graph.predecessors.clear();
    for(auto n:graph.nodes) { graph.successors[n];graph.predecessors[n]; }
    for(const auto& kv:graph.successors) {
        if(!graph.nodes.count(kv.first)) continue;
        for(auto s:kv.second) if(graph.nodes.count(s)) graph.predecessors[s].insert(kv.first);
    }
}

std::set<std::uint16_t> StructuredControl::reachableNodes(const StructuralGraph& graph) {
    std::set<std::uint16_t> out;
    if(!graph.nodes.count(graph.entry)) return out;
    std::queue<std::uint16_t> q;q.push(graph.entry);
    while(!q.empty()) {
        const auto n=q.front();q.pop();
        if(!out.insert(n).second) continue;
        const auto si=graph.successors.find(n);
        if(si==graph.successors.end()) continue;
        for(auto s:si->second) if(graph.nodes.count(s) && !out.count(s)) q.push(s);
    }
    return out;
}

std::map<std::uint16_t,DominatorInfo> StructuredControl::computeDominators(const StructuralGraph& graph) {
    std::map<std::uint16_t,DominatorInfo> result;
    const auto nodes=reachableNodes(graph);
    if(nodes.empty()) return result;
    for(auto n:nodes) result[n].dominators=(n==graph.entry?std::set<std::uint16_t>{n}:nodes);
    bool changed=true;
    while(changed) {
        changed=false;
        for(auto n:nodes) {
            if(n==graph.entry) continue;
            std::set<std::uint16_t> next;
            bool havePred=false;
            const auto pi=graph.predecessors.find(n);
            if(pi!=graph.predecessors.end()) for(auto p:pi->second) {
                if(!nodes.count(p)) continue;
                if(!havePred) { next=result[p].dominators;havePred=true; }
                else next=setIntersection(next,result[p].dominators);
            }
            if(!havePred) next.clear();
            next.insert(n);
            if(next!=result[n].dominators) {result[n].dominators=next;changed=true;}
        }
    }
    for(auto n:nodes) {
        if(n==graph.entry) continue;
        std::set<std::uint16_t> strict=result[n].dominators;strict.erase(n);
        for(auto d:strict) {
            bool deepest=true;
            for(auto other:strict) if(other!=d && !result[d].dominators.count(other)) {deepest=false;break;}
            if(deepest) { result[n].immediateDominator=d;break; }
        }
    }
    return result;
}

std::map<std::uint16_t,PostDominatorInfo> StructuredControl::computePostDominators(const StructuralGraph& graph) {
    std::map<std::uint16_t,PostDominatorInfo> out;
    const auto reachable=reachableNodes(graph);
    if(reachable.empty()) return out;
    constexpr int syntheticExit=0x10000;
    std::set<int> universe;for(auto n:reachable)universe.insert(n);universe.insert(syntheticExit);
    std::map<int,std::set<int>> succ;
    for(auto n:reachable) {
        const auto si=graph.successors.find(n);
        if(si!=graph.successors.end()) for(auto s:si->second) if(reachable.count(s)) succ[n].insert(s);
        if(graph.exits.count(n) || succ[n].empty()) succ[n].insert(syntheticExit);
    }
    succ[syntheticExit]={};
    std::map<int,std::set<int>> pd;
    pd[syntheticExit]={syntheticExit};
    for(auto n:reachable) pd[n]=universe;
    bool changed=true;
    while(changed) {
        changed=false;
        for(auto n:reachable) {
            std::set<int> next;bool first=true;
            for(auto s:succ[n]) {
                if(first) {next=pd[s];first=false;}
                else {
                    std::set<int> inter;
                    std::set_intersection(next.begin(),next.end(),pd[s].begin(),pd[s].end(),std::inserter(inter,inter.end()));
                    next.swap(inter);
                }
            }
            if(first) next={syntheticExit};
            next.insert(n);
            if(next!=pd[n]) {pd[n]=next;changed=true;}
        }
    }
    for(auto n:reachable) {
        for(auto p:pd[n]) if(p!=syntheticExit) out[n].postDominators.insert(static_cast<std::uint16_t>(p));
        std::set<int> strict=pd[n];strict.erase(n);
        int immediate=-1;
        for(auto d:strict) {
            bool closest=true;
            for(auto other:strict) if(other!=d && !pd[d].count(other)) {closest=false;break;}
            if(closest) {immediate=d;break;}
        }
        if(immediate!=syntheticExit) out[n].immediatePostDominator=immediate;
    }
    return out;
}

bool StructuredControl::dominates(const std::map<std::uint16_t,DominatorInfo>& dominators,
                                  std::uint16_t dominator,std::uint16_t node) {
    const auto it=dominators.find(node);return it!=dominators.end()&&it->second.dominators.count(dominator)!=0;
}

std::vector<LoopRegion> StructuredControl::detectNaturalLoops(
    const StructuralGraph& graph,const std::map<std::uint16_t,DominatorInfo>& dominators) {
    std::map<std::uint16_t,LoopRegion> byHeader;
    for(const auto& kv:graph.successors) {
        if(!dominators.count(kv.first)) continue;
        for(auto header:kv.second) {
            if(!dominates(dominators,header,kv.first)) continue;
            auto& loop=byHeader[header];loop.header=header;loop.blocks.insert(header);loop.blocks.insert(kv.first);loop.latches.insert(kv.first);
            std::queue<std::uint16_t> q;if(kv.first!=header)q.push(kv.first);
            while(!q.empty()) {
                const auto n=q.front();q.pop();const auto pi=graph.predecessors.find(n);if(pi==graph.predecessors.end())continue;
                for(auto p:pi->second) if(dominators.count(p)&&loop.blocks.insert(p).second&&p!=header)q.push(p);
            }
        }
    }
    std::vector<LoopRegion> loops;
    for(auto& kv:byHeader) {
        auto& loop=kv.second;
        for(auto b:loop.blocks) {
            const auto si=graph.successors.find(b);if(si==graph.successors.end())continue;
            for(auto s:si->second) if(!loop.blocks.count(s))loop.exits.insert(s);
        }
        loops.push_back(loop);
    }
    std::sort(loops.begin(),loops.end(),[](const LoopRegion&a,const LoopRegion&b){if(a.blocks.size()!=b.blocks.size())return a.blocks.size()>b.blocks.size();return a.header<b.header;});
    return loops;
}

std::vector<StructuredRegion> StructuredControl::recognizeRegions(
    const StructuralGraph& graph,
    const std::map<std::uint16_t,DominatorInfo>& dom,
    const std::map<std::uint16_t,PostDominatorInfo>& pdom,
    const std::vector<LoopRegion>& loops,
    const std::map<std::uint16_t,BranchDescriptor>& branches) {
    std::vector<StructuredRegion> candidates;
    std::set<std::uint16_t> loopControlBlocks;

    for(const auto& loop:loops) {
        // A natural loop must remain single-entry at its header in the full defensible static
        // graph. Ownership filtering can intentionally omit shared/unowned blocks, so an
        // external structural edge into any non-header member makes structured lifting unsafe.
        bool unsafeSideEntry=false;
        for(auto n:loop.blocks) if(n!=loop.header&&graph.externalEntryBlocks.count(n)) {unsafeSideEntry=true;break;}
        if(unsafeSideEntry) continue;

        bool emitted=false;
        const auto hi=branches.find(loop.header);
        const bool headerIsLatch=loop.latches.count(loop.header)!=0;
        if(!headerIsLatch && hi!=branches.end() && hi->second.taken>=0 && hi->second.notTaken>=0) {
            const bool ti=loop.blocks.count(static_cast<std::uint16_t>(hi->second.taken))!=0;
            const bool ni=loop.blocks.count(static_cast<std::uint16_t>(hi->second.notTaken))!=0;
            if(ti!=ni) {
                StructuredRegion r;r.kind=RegionKind::While;r.entry=loop.header;r.conditionAddress=hi->second.sourceAddress;r.blocks=loop.blocks;r.sourceBlocks=loop.blocks;
                if(ti) {r.trueTarget=hi->second.taken;r.falseTarget=hi->second.notTaken;r.condition=hi->second.takenCondition;}
                else {r.trueTarget=hi->second.notTaken;r.falseTarget=hi->second.taken;r.condition=hi->second.notTakenCondition;}
                r.trueBlocks=loop.blocks;r.trueBlocks.erase(loop.header);r.join=r.falseTarget;
                candidates.push_back(r);loopControlBlocks.insert(loop.header);emitted=true;
            }
        }
        if(emitted) continue;
        for(auto latch:loop.latches) {
            const auto li=branches.find(latch);if(li==branches.end()||li->second.taken<0||li->second.notTaken<0)continue;
            const bool tBack=li->second.taken==loop.header;
            const bool nBack=li->second.notTaken==loop.header;
            if(tBack==nBack) continue;
            const int exitTarget=tBack?li->second.notTaken:li->second.taken;
            if(exitTarget>=0 && loop.blocks.count(static_cast<std::uint16_t>(exitTarget))) continue;
            StructuredRegion r;r.kind=RegionKind::DoWhile;r.entry=loop.header;r.conditionAddress=li->second.sourceAddress;r.blocks=loop.blocks;r.sourceBlocks=loop.blocks;r.trueBlocks=loop.blocks;r.join=exitTarget;
            r.trueTarget=loop.header;r.falseTarget=exitTarget;r.condition=tBack?li->second.takenCondition:li->second.notTakenCondition;
            candidates.push_back(r);loopControlBlocks.insert(latch);emitted=true;break;
        }
    }

    for(const auto& bk:branches) {
        const auto& b=bk.second;
        if(loopControlBlocks.count(b.block)||b.taken<0||b.notTaken<0||b.taken==b.notTaken)continue;
        if(!graph.nodes.count(b.block)||!graph.nodes.count(static_cast<std::uint16_t>(b.taken))||!graph.nodes.count(static_cast<std::uint16_t>(b.notTaken)))continue;
        const auto pi=pdom.find(b.block);if(pi==pdom.end()||pi->second.immediatePostDominator<0)continue;
        const auto join=static_cast<std::uint16_t>(pi->second.immediatePostDominator);
        if(join==b.block||!graph.nodes.count(join))continue;
        const bool takenIsJoin=static_cast<std::uint16_t>(b.taken)==join;
        const bool notIsJoin=static_cast<std::uint16_t>(b.notTaken)==join;
        if(takenIsJoin&&notIsJoin)continue;

        if(takenIsJoin!=notIsJoin) {
            const std::uint16_t bodyStart=static_cast<std::uint16_t>(takenIsJoin?b.notTaken:b.taken);
            bool valid=false;auto body=collectBranchRegion(graph,dom,pdom,b.block,bodyStart,join,valid);
            if(!valid||body.empty()||!branchHasSafeEntries(graph,body,b.block)||!branchHasOnlyLocalExits(graph,body,join))continue;
            StructuredRegion r;r.kind=RegionKind::If;r.entry=b.block;r.conditionAddress=b.sourceAddress;r.join=join;r.blocks=body;r.blocks.insert(b.block);r.sourceBlocks=r.blocks;r.trueBlocks=body;r.trueTarget=bodyStart;r.falseTarget=join;
            r.condition=takenIsJoin?b.notTakenCondition:b.takenCondition;
            candidates.push_back(r);
        } else {
            bool va=false,vb=false;auto t=collectBranchRegion(graph,dom,pdom,b.block,static_cast<std::uint16_t>(b.taken),join,va);auto f=collectBranchRegion(graph,dom,pdom,b.block,static_cast<std::uint16_t>(b.notTaken),join,vb);
            if(!va||!vb||t.empty()||f.empty()||setsOverlap(t,f))continue;
            if(!branchHasSafeEntries(graph,t,b.block)||!branchHasSafeEntries(graph,f,b.block)||!branchHasOnlyLocalExits(graph,t,join)||!branchHasOnlyLocalExits(graph,f,join))continue;
            bool cross=false;
            for(auto n:t){const auto si=graph.successors.find(n);if(si!=graph.successors.end())for(auto s:si->second)if(f.count(s)){cross=true;break;}if(cross)break;}
            for(auto n:f){const auto si=graph.successors.find(n);if(si!=graph.successors.end())for(auto s:si->second)if(t.count(s)){cross=true;break;}if(cross)break;}
            if(cross)continue;
            StructuredRegion r;r.kind=RegionKind::IfElse;r.entry=b.block;r.conditionAddress=b.sourceAddress;r.join=join;r.trueTarget=b.taken;r.falseTarget=b.notTaken;r.condition=b.takenCondition;r.trueBlocks=t;r.falseBlocks=f;r.blocks=t;r.blocks.insert(f.begin(),f.end());r.blocks.insert(b.block);r.sourceBlocks=r.blocks;
            candidates.push_back(r);
        }
    }
    return makeLaminar(std::move(candidates));
}

StructureAnalysis StructuredControl::analyze(const StructuralGraph& input,
                                             const std::map<std::uint16_t,BranchDescriptor>& branches) {
    StructureAnalysis a;a.graph=input;rebuildPredecessors(a.graph);a.dominators=computeDominators(a.graph);a.postDominators=computePostDominators(a.graph);a.loops=detectNaturalLoops(a.graph,a.dominators);a.regions=recognizeRegions(a.graph,a.dominators,a.postDominators,a.loops,branches);
    const auto reachable=reachableNodes(a.graph);std::set<std::uint16_t> structured;
    for(const auto* r:flattenRegions(a.regions))structured.insert(r->blocks.begin(),r->blocks.end());
    for(auto n:reachable)if(!structured.count(n))a.fallbackBlocks.insert(n);
    return a;
}

std::string StructuredControl::regionKindText(RegionKind kind) {
    switch(kind){case RegionKind::Block:return"block";case RegionKind::Sequence:return"sequence";case RegionKind::If:return"if";case RegionKind::IfElse:return"if-else";case RegionKind::While:return"while";case RegionKind::DoWhile:return"do-while";case RegionKind::GotoFallback:return"goto-fallback";}return"?";
}

std::vector<const StructuredRegion*> StructuredControl::flattenRegions(const std::vector<StructuredRegion>& roots) {
    std::vector<const StructuredRegion*> out;for(const auto& r:roots)flattenOne(r,out);return out;
}

} // namespace pacripper
