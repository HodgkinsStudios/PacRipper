// PacRipper public command-line front end
// Created by Jacob Hodgkins
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <process.h>
#include <windows.h>
#else
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace {
constexpr const char* kVersion = "1.0.0";

void printUsage() {
    std::cerr << "PacRipper " << kVersion << " - complete Pac-Man/Puckman board disassembly/reconstruction tool\n"
              << "Usage: PacRipper [--force] <pacman.7z|puckman.zip> <output-folder>\n"
              << "  --force  deliberately replace an existing safe output destination\n";
}

#ifndef _WIN32

bool commandExists(const char* command) {
    const std::string test = std::string(command) + " --version >/dev/null 2>&1";
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
        ec.clear();
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
}

int runPlatformMain(int argc, char** argv) {
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
    else if (commandExists("python3")) python = "python3";
    else if (commandExists("python")) python = "python";
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

#else

struct PythonCommand {
    std::wstring executable;
    std::vector<std::wstring> prefixArgs;
};

std::vector<std::wstring> parseWindowsCommandLine(const wchar_t* commandLine) {
    std::vector<std::wstring> args;
    const wchar_t* p = commandLine ? commandLine : L"";

    while (*p) {
        while (*p == L' ' || *p == L'\t') ++p;
        if (!*p) break;

        std::wstring arg;
        bool inQuotes = false;

        while (*p) {
            if (!inQuotes && (*p == L' ' || *p == L'\t')) break;

            if (*p == L'\\') {
                std::size_t slashCount = 0;
                while (*p == L'\\') {
                    ++slashCount;
                    ++p;
                }

                if (*p == L'"') {
                    arg.append(slashCount / 2, L'\\');
                    if ((slashCount % 2) != 0) {
                        arg.push_back(L'"');
                        ++p;
                    } else {
                        if (inQuotes && p[1] == L'"') {
                            arg.push_back(L'"');
                            p += 2;
                        } else {
                            inQuotes = !inQuotes;
                            ++p;
                        }
                    }
                } else {
                    arg.append(slashCount, L'\\');
                }
                continue;
            }

            if (*p == L'"') {
                if (inQuotes && p[1] == L'"') {
                    arg.push_back(L'"');
                    p += 2;
                } else {
                    inQuotes = !inQuotes;
                    ++p;
                }
                continue;
            }

            arg.push_back(*p);
            ++p;
        }

        args.push_back(std::move(arg));
        while (*p == L' ' || *p == L'\t') ++p;
    }

    return args;
}

fs::path executablePathWindows() {
    std::vector<wchar_t> buffer(1024);
    for (;;) {
        const DWORD size = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (size == 0) return {};
        if (size < buffer.size() - 1) return fs::path(std::wstring(buffer.data(), size));
        if (buffer.size() >= 32768) return {};
        buffer.resize(buffer.size() * 2);
    }
}

fs::path findRootWindows() {
    std::vector<fs::path> candidates;
    std::error_code ec;
    candidates.push_back(fs::current_path(ec));

    const fs::path executable = executablePathWindows();
    if (!executable.empty()) {
        candidates.push_back(executable.parent_path());
        candidates.push_back(executable.parent_path().parent_path());
    }

    for (const auto& candidate : candidates) {
        ec.clear();
        if (!candidate.empty() && fs::is_regular_file(candidate / L"scripts" / L"pacripper_pipeline.py", ec))
            return candidate;
    }
    return {};
}

std::wstring quoteWindowsArgument(const std::wstring& arg) {
    if (arg.empty()) return L"\"\"";

    const bool needsQuotes =
        arg.find_first_of(L" \t\"") != std::wstring::npos;
    if (!needsQuotes) return arg;

    std::wstring out;
    out.push_back(L'"');
    std::size_t backslashes = 0;

    for (const wchar_t ch : arg) {
        if (ch == L'\\') {
            ++backslashes;
            continue;
        }

        if (ch == L'"') {
            out.append(backslashes * 2 + 1, L'\\');
            out.push_back(L'"');
            backslashes = 0;
            continue;
        }

        out.append(backslashes, L'\\');
        backslashes = 0;
        out.push_back(ch);
    }

    // Backslashes immediately before the closing quote must be doubled.
    out.append(backslashes * 2, L'\\');
    out.push_back(L'"');
    return out;
}

int spawnWindows(const PythonCommand& python, const std::vector<std::wstring>& tailArgs) {
    // PacRipper accepts Unicode Windows paths. Force Python's standard streams
    // to UTF-8 so diagnostics containing those paths do not fail under a legacy
    // Windows console code page (for example CP-1252).
    SetEnvironmentVariableW(L"PYTHONUTF8", L"1");
    SetEnvironmentVariableW(L"PYTHONIOENCODING", L"utf-8");

    std::vector<std::wstring> owned;
    owned.reserve(1 + python.prefixArgs.size() + tailArgs.size());
    owned.push_back(python.executable);
    owned.insert(owned.end(), python.prefixArgs.begin(), python.prefixArgs.end());
    owned.insert(owned.end(), tailArgs.begin(), tailArgs.end());

    std::wstring commandLine;
    for (const auto& item : owned) {
        if (!commandLine.empty()) commandLine.push_back(L' ');
        commandLine += quoteWindowsArgument(item);
    }

    std::vector<wchar_t> mutableCommand(commandLine.begin(), commandLine.end());
    mutableCommand.push_back(L'\0');

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};

    if (!CreateProcessW(
            nullptr,
            mutableCommand.data(),
            nullptr,
            nullptr,
            FALSE,
            0,
            nullptr,
            nullptr,
            &startup,
            &process)) {
        return 127;
    }

    const DWORD waitResult = WaitForSingleObject(process.hProcess, INFINITE);
    DWORD exitCode = 127;
    if (waitResult == WAIT_OBJECT_0)
        GetExitCodeProcess(process.hProcess, &exitCode);

    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return static_cast<int>(exitCode);
}

bool isPython3(const PythonCommand& python) {
    return spawnWindows(
        python,
        {L"-c", L"import sys; raise SystemExit(0 if sys.version_info[0] >= 3 else 1)"}
    ) == 0;
}

std::optional<PythonCommand> selectWindowsPython(bool& explicitSettingFailed) {
    explicitSettingFailed = false;

    if (const wchar_t* configured = _wgetenv(L"PACRIPPER_PYTHON"); configured && *configured) {
        PythonCommand candidate{configured, {}};
        if (isPython3(candidate)) return candidate;
        explicitSettingFailed = true;
        return std::nullopt;
    }

    const std::vector<PythonCommand> candidates = {
        {L"py", {L"-3"}},
        {L"python", {}},
        {L"python3", {}},
    };
    for (const auto& candidate : candidates) {
        if (isPython3(candidate)) return candidate;
    }
    return std::nullopt;
}

int runPythonWindows(const PythonCommand& python, const fs::path& script,
                     const fs::path& input, const fs::path& output, bool force) {
    std::vector<std::wstring> args;
    args.push_back(script.wstring());
    if (force) args.push_back(L"--force");
    args.push_back(input.wstring());
    args.push_back(output.wstring());
    return spawnWindows(python, args);
}

int runPlatformMainWindows(const std::vector<std::wstring>& argv) {
    if (argv.size() == 2 && argv[1] == L"--version") {
        std::cout << "PacRipper " << kVersion << "\n";
        return 0;
    }

    bool force = false;
    std::size_t arg = 1;
    if (argv.size() > 1 && argv[1] == L"--force") {
        force = true;
        ++arg;
    }
    if (argv.size() - arg != 2) {
        printUsage();
        return 2;
    }

    const fs::path root = findRootWindows();
    if (root.empty()) {
        std::cerr << "PacRipper error: could not locate scripts/pacripper_pipeline.py. "
                     "Keep the bin and scripts folders together in the PacRipper package.\n";
        return 1;
    }

    bool explicitSettingFailed = false;
    const auto python = selectWindowsPython(explicitSettingFailed);
    if (!python) {
        if (explicitSettingFailed) {
            std::cerr << "PacRipper error: PACRIPPER_PYTHON does not point to a working Python 3 interpreter.\n";
        } else {
            std::cerr << "PacRipper error: Python 3 was not found. Install Python 3 (the Windows py launcher is supported) "
                         "or set PACRIPPER_PYTHON.\n";
        }
        return 1;
    }

    const fs::path script = root / L"scripts" / L"pacripper_pipeline.py";
    const int rc = runPythonWindows(*python, script, fs::path(argv[arg]), fs::path(argv[arg + 1]), force);
    if (rc != 0) {
        std::cerr << "PacRipper failed.\n";
        return 1;
    }
    return 0;
}

#endif
} // namespace

int main(int argc, char** argv) {
#ifdef _WIN32
    (void)argc;
    (void)argv;
    const auto wideArgs = parseWindowsCommandLine(GetCommandLineW());
    if (wideArgs.empty()) {
        std::cerr << "PacRipper error: unable to read the Windows command line.\n";
        return 1;
    }
    return runPlatformMainWindows(wideArgs);
#else
    return runPlatformMain(argc, argv);
#endif
}
