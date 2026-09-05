#pragma once
// PacRipper native-PC recoder/source-generation pipeline contract
// Created by Jacob Hodgkins

#include <array>
#include <cstddef>
#include <string_view>

namespace pacripper {

enum class PortPipelineStage {
    RomLoadAndValidation,
    RecoveryAndDisassembly,
    CanonicalSemanticModel,
    ExactReconstruction,
    NativeLogicRecoding,
    NativeRuntimeAndPlatform,
    GeneratedNativeProject,
    ReferenceDifferentialValidation
};

struct PortPipelineStageStatus {
    PortPipelineStage stage;
    std::string_view name;
    bool implemented;
    bool complete;
    bool shippingDependency;
};

class PortPipeline {
public:
    static constexpr std::array<PortPipelineStageStatus,8> currentStatus() {
        return {{
            {PortPipelineStage::RomLoadAndValidation,"ROM loader / validator",true,true,false},
            {PortPipelineStage::RecoveryAndDisassembly,"recovery + disassembly/decomposition",true,true,false},
            {PortPipelineStage::CanonicalSemanticModel,"canonical recovered semantic model",true,true,false},
            {PortPipelineStage::ExactReconstruction,"exact reconstruction / rebuild tooling",true,true,false},
            {PortPipelineStage::NativeLogicRecoding,"native-PC recoder / coverage layer",true,true,true},
            {PortPipelineStage::NativeRuntimeAndPlatform,"native PC runtime / platform support",true,false,true},
            {PortPipelineStage::GeneratedNativeProject,"generated human-readable native C++ project",true,false,true},
            {PortPipelineStage::ReferenceDifferentialValidation,"reference / differential validation",true,true,false}
        }};
    }

    static constexpr std::size_t currentNativeOperations() { return 5414; }
    static constexpr std::size_t currentRecoveredOperations() { return 5414; }
    static constexpr bool freshRomToNativeProjectComplete() { return false; }
};

}
