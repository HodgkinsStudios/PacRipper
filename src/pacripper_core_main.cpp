// PacRipper internal disassembly engine
// Created by Jacob Hodgkins
#include "rom/RomSet.h"
#include "recovery/BoardResourceRecovery.h"
#include "analysis/Analyzer.h"
#include "decomp/Decompiler.h"
#include "decomp/RomRebuilder.h"
#include <iostream>
#include <string>

namespace {
int loadCanonical(const std::string& path, pacripper::RomSet& rom, pacripper::RomVariant& variant) {
    std::string error;
    if (!rom.load(path, error)) {
        std::cerr << "Load failed: " << error << "\n";
        return 1;
    }
    if (!rom.validateSupportedPacmanFamily(error, &variant)) {
        std::cerr << "Canonical Pac-Man/Puckman ROM validation failed: " << error << "\n";
        return 1;
    }
    return 0;
}
}

int main(int argc, char** argv) {
    if (argc != 4) {
        std::cerr << "PacRipperCore is an internal helper used by PacRipper.\n";
        return 2;
    }

    const std::string mode = argv[1];
    const std::string romPath = argv[2];
    const std::string outPath = argv[3];
    pacripper::RomSet rom;
    pacripper::RomVariant variant = pacripper::RomVariant::Unknown;
    if (loadCanonical(romPath, rom, variant)) return 1;
    std::string error;

    if (mode == "--board-export") {
        pacripper::BoardAudioResult result;
        if (!pacripper::BoardResourceRecovery::exportAudio(rom, outPath, result, error)) {
            std::cerr << "Board-resource export failed: " << error << "\n";
            return 1;
        }
        if (!result.stats.allPassed) {
            std::cerr << "Board-resource round-trip verification failed.\n";
            return 1;
        }
        std::cout << "PacRipper board-resource export: PASS\n";
        return 0;
    }

    if (mode == "--program-export") {
        pacripper::Analyzer analyzer;
        if (!analyzer.analyze(rom, error)) {
            std::cerr << "Program analysis failed: " << error << "\n";
            return 1;
        }
        pacripper::Decompiler decompiler;
        if (!decompiler.build(analyzer, error)) {
            std::cerr << "Program disassembly/reconstruction analysis failed: " << error << "\n";
            return 1;
        }
        if (!decompiler.romRebuilderRebuildResult().stats.verified) {
            std::cerr << "Exact 16-KiB program reconstruction verification failed.\n";
            return 1;
        }
        if (!decompiler.exportAll(outPath, error)) {
            std::cerr << "Program release-input export failed: " << error << "\n";
            return 1;
        }
        const auto program = rom.assembledProgramROM();
        std::cout << "PacRipper program release-input export: PASS variant=" << pacripper::RomSet::variantName(variant) << "\n";
        std::cout << "5414/5414 instructions; 16384/16384 program bytes\n";
        std::cout << "program_sha256=" << pacripper::RomRebuilder::sha256(program) << "\n";
        return 0;
    }

    std::cerr << "Unknown internal PacRipperCore mode.\n";
    return 2;
}
