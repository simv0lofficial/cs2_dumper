#pragma once

// Output code generators — writes analysis results as .cs, .hpp, .json, .rs, .zig files.

#include <cstdint>
#include <filesystem>
#include <sstream>
#include <string>
#include <vector>

#include "analysis.hpp"
#include "process.hpp"

// ── Formatter ───────────────────────────────────────────────
// Handles indentation-aware string building.

class Formatter {
public:
    explicit Formatter(int indent_size = 4);

    void write(const std::string& text);
    void writeln(const std::string& line = "");

    // Write "heading {", call f(), write "};" or "}".
    template <typename F>
    void block(const std::string& heading, bool semicolon, F&& f) {
        writeln(heading + " {");
        indent();
        f(*this);
        dedent();
        writeln(semicolon ? "};" : "}");
    }

    void indent();
    void dedent();

    [[nodiscard]] std::string str() const { return m_out.str(); }

private:
    std::ostringstream m_out;
    int m_indent_size;
    int m_indent_level = 0;

    void push_indentation();
};

// ── Output ──────────────────────────────────────────────────

class Output {
public:
    Output(const std::vector<std::string>& file_types,
           int indent_size,
           const std::filesystem::path& out_dir,
           const AnalysisResult& result);

    // Dump all results: buttons, interfaces, offsets, schemas, info.json.
    void dump_all(Process& process) const;

private:
    std::vector<std::string>  m_file_types;
    int                       m_indent_size;
    std::filesystem::path     m_out_dir;
    const AnalysisResult&     m_result;
    std::string               m_timestamp; // ISO 8601

    void dump_buttons() const;
    void dump_interfaces() const;
    void dump_offsets() const;
    void dump_schemas() const;
    void dump_info(Process& process) const;

    // Banner written at top of non-JSON files.
    void write_banner(Formatter& fmt) const;

    // Per-format writers.
    static void write_buttons_cs(Formatter& fmt, const ButtonMap& buttons);
    static void write_buttons_hpp(Formatter& fmt, const ButtonMap& buttons);
    static void write_buttons_json(Formatter& fmt, const ButtonMap& buttons);
    static void write_buttons_rs(Formatter& fmt, const ButtonMap& buttons);
    static void write_buttons_zig(Formatter& fmt, const ButtonMap& buttons);

    static void write_interfaces_cs(Formatter& fmt, const InterfaceMap& ifaces);
    static void write_interfaces_hpp(Formatter& fmt, const InterfaceMap& ifaces);
    static void write_interfaces_json(Formatter& fmt, const InterfaceMap& ifaces);
    static void write_interfaces_rs(Formatter& fmt, const InterfaceMap& ifaces);
    static void write_interfaces_zig(Formatter& fmt, const InterfaceMap& ifaces);

    static void write_offsets_cs(Formatter& fmt, const OffsetMap& offsets);
    static void write_offsets_hpp(Formatter& fmt, const OffsetMap& offsets);
    static void write_offsets_json(Formatter& fmt, const OffsetMap& offsets);
    static void write_offsets_rs(Formatter& fmt, const OffsetMap& offsets);
    static void write_offsets_zig(Formatter& fmt, const OffsetMap& offsets);

    static void write_schemas_cs(Formatter& fmt, const SchemaMap& schemas);
    static void write_schemas_hpp(Formatter& fmt, const SchemaMap& schemas);
    static void write_schemas_json(Formatter& fmt, const SchemaMap& schemas);
    static void write_schemas_rs(Formatter& fmt, const SchemaMap& schemas);
    static void write_schemas_zig(Formatter& fmt, const SchemaMap& schemas);
};

// ── String helpers ──────────────────────────────────────────

std::string slugify(const std::string& input);
std::string to_pascal_case(const std::string& input);
std::string to_snake_case(const std::string& input);
std::string zig_ident(const std::string& input);
std::string hex_str(uint64_t value);
