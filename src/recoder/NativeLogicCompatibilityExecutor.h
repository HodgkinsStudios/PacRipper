#pragma once
// PacRipper compatibility backend for the certified historical WaveXX executors
// Portable Native Core Consolidation control-flow analysis
// Created by Jacob Hodgkins

#include "../runtime/CertifiedNativeExecutor.h"

namespace pacripper {

class WaveCompatibilityNativeExecutor final : public CertifiedNativeExecutor {
public:
    static const WaveCompatibilityNativeExecutor& instance();

    bool executeRecord(std::size_t recordIndex,SemanticExecutionState& state,
                       std::size_t& equivalentOperations,std::string& error,
                       GeneratedExecutionBoundary* boundary=nullptr) const override;
    bool executeSecondaryEntry(std::uint16_t sourcePC,SemanticExecutionState& state,
                               std::size_t& equivalentOperations,std::string& error,
                               GeneratedExecutionBoundary* boundary=nullptr) const override;
    const char* backendName() const override { return "Certified portable-catalog + WaveXX compatibility backend"; }

private:
    WaveCompatibilityNativeExecutor()=default;
};

} // namespace pacripper
