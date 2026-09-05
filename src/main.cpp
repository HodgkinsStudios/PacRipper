// PacRipper public command-line front end
// Created by Jacob Hodgkins
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <process.h>
#else
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace {
constexpr const char* kVersion = "1.0.0";

bool commandExists(const char* command) {
#ifdef _WIN32
    const std::string test = std::string(command) + " --version >NUL 2>&1";
#else
    const std::string test = std::string(command) + " --version >/dev/null 2>&1";
#endif
    return std::system(test.c_str()) == 0;
}

fs::path findRoot(const char* argv0) {
    std::vector<fs::path> candidates;
    std::error_code ec;
    candidates.push_back(fs::current_path(ec));
    const fs::path executable = fs::absolute(fs::path(argv0), ec);
    if (!ec) {
        candidates.push_back(executable.parent_path());
        candidates.push_back(executable.parent_path().parent_path());
    }
    for (const auto& candidate : candidates) {
        if (!candidate.empty() && fs::is_regular_file(candidate / "scripts" / "pacripper_pipeline.py", ec))
            return candidate;
    }
    return {};
}

int runPython(const std::string& python, const fs::path& script,
              const std::string& input, const std::string& output, bool force) {
    const std::string scriptText = script.string();
    const std::string forceText = "--force";
    std::vector<const char*> args;
    args.push_back(python.c_str());
    args.push_back(scriptText.c_str());
    if (force) args.push_back(forceText.c_str());
    args.push_back(input.c_str());
    args.push_back(output.c_str());
    args.push_back(nullptr);
#ifdef _WIN32
    const intptr_t rc = _spawnvp(_P_WAIT, python.c_str(), args.data());
    return rc < 0 ? 127 : static_cast<int>(rc);
#else
    const pid_t pid = fork();
    if (pid < 0) return 127;
    if (pid == 0) {
        execvp(python.c_str(), const_cast<char* const*>(args.data()));
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return 127;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return 128;
#endif
}

void printUsage() {
    std::cerr << "PacRipper " << kVersion << " - complete Pac-Man/Puckman board disassembly/reconstruction tool\n"
              << "Usage: PacRipper [--force] <pacman.7z|puckman.zip> <output-folder>\n"
              << "  --force  deliberately replace an existing safe output destination\n";
}
}

int main(int argc, char** argv) {
    if (argc == 2 && std::string(argv[1]) == "--version") {
        std::cout << "PacRipper " << kVersion << "\n";
        return 0;
    }

    bool force = false;
    int arg = 1;
    if (argc > 1 && std::string(argv[1]) == "--force") {
        force = true;
        ++arg;
    }
    if (argc - arg != 2) {
        printUsage();
        return 2;
    }

    const fs::path root = findRoot(argv[0]);
    if (root.empty()) {
        std::cerr << "PacRipper error: could not locate scripts/pacripper_pipeline.py. "
                     "Keep the bin and scripts folders together in the PacRipper package.\n";
        return 1;
    }

    const char* envPython = std::getenv("PACRIPPER_PYTHON");
    std::string python;
    if (envPython && *envPython) python = envPython;
#ifdef _WIN32
    else if (commandExists("python")) python = "python";
    else if (commandExists("python3")) python = "python3";
#else
    else if (commandExists("python3")) python = "python3";
    else if (commandExists("python")) python = "python";
#endif
    else {
        std::cerr << "PacRipper error: Python 3 was not found. Install Python 3 or set PACRIPPER_PYTHON.\n";
        return 1;
    }

    const fs::path script = root / "scripts" / "pacripper_pipeline.py";
    const int rc = runPython(python, script, argv[arg], argv[arg + 1], force);
    if (rc != 0) {
        std::cerr << "PacRipper failed.\n";
        return 1;
    }
    return 0;
}
