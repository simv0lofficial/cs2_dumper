#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <chrono>

#include "process.hpp"
#include "analysis.hpp"
#include "output.hpp"

// Defined in analysis.cpp.
extern void set_verbose_level(int level);

struct Args {
    std::string process_name = "cs2.exe";
    std::vector<std::string> file_types = {"cs", "hpp", "json", "rs", "zig"};
    int indent_size = 4;
    std::filesystem::path output_dir = "output";
    int verbose = 0;
    bool no_log_file = false;
};

static void print_help(const char* prog) {
    std::cout << "Usage: " << prog << " [options]\n"
              << "Options:\n"
              << "  -f, --file-types <types>   Comma-separated output types (default: cs,hpp,json,rs,zig)\n"
              << "  -i, --indent-size <n>      Spaces per indent level (default: 4)\n"
              << "  -o, --output <dir>         Output directory (default: output)\n"
              << "  -p, --process-name <name>  Target process (default: cs2.exe)\n"
              << "  -v, --verbose              Increase verbosity (can repeat)\n"
              << "  --no-log-file              Don't create cs2-dumper.log\n"
              << "  -h, --help                 Show this help\n";
}

static std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> parts;
    std::string current;
    for (char c : s) {
        if (c == delim) {
            if (!current.empty()) parts.push_back(current);
            current.clear();
        } else {
            current += c;
        }
    }
    if (!current.empty()) parts.push_back(current);
    return parts;
}

static Args parse_args(int argc, char* argv[]) {
    Args args;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "-h" || a == "--help") {
            print_help(argv[0]);
            std::exit(0);
        }
        if ((a == "-f" || a == "--file-types") && i + 1 < argc) {
            args.file_types = split(argv[++i], ',');
        } else if ((a == "-i" || a == "--indent-size") && i + 1 < argc) {
            args.indent_size = std::atoi(argv[++i]);
        } else if ((a == "-o" || a == "--output") && i + 1 < argc) {
            args.output_dir = argv[++i];
        } else if ((a == "-p" || a == "--process-name") && i + 1 < argc) {
            args.process_name = argv[++i];
        } else if (a == "-v" || a == "--verbose") {
            args.verbose++;
        } else if (a == "--no-log-file") {
            args.no_log_file = true;
        }
    }
    return args;
}

int main(int argc, char* argv[]) {
    auto args = parse_args(argc, argv);

    set_verbose_level(args.verbose);

    // Optional log file.
    std::ofstream log_file;

    if (!args.no_log_file) {
        log_file.open("cs2-dumper.log", std::ios::out | std::ios::trunc);
    }

    // Find process.
    auto pid = Process::find_by_name(args.process_name);
    if (!pid) {
        std::cerr << "[ERROR] process \"" << args.process_name << "\" not found\n";
        return 1;
    }

    Process process(*pid);
    if (!process.is_valid()) {
        std::cerr << "[ERROR] failed to open process (run as administrator?)\n";
        return 1;
    }

    std::cout << "[INFO] attached to " << args.process_name << " (PID " << *pid << ")\n";

    auto start = std::chrono::steady_clock::now();

    auto result = analyze_all(process);

    Output output(args.file_types, args.indent_size, args.output_dir, result);
    output.dump_all(process);

    auto elapsed = std::chrono::steady_clock::now() - start;
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();

    std::cout << "[INFO] analysis completed in " << ms << "ms\n";
    std::cout << "[INFO] output written to " << std::filesystem::absolute(args.output_dir).string() << "\n";

    return 0;
}
