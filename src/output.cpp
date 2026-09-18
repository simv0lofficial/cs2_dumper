#include "output.hpp"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <set>

#include "json.hpp"

using json = nlohmann::json;

// ════════════════════════════════════════════════════════════
//  String helpers
// ════════════════════════════════════════════════════════════

std::string slugify(const std::string& input) {
    std::string result;
    result.reserve(input.size());
    for (char c : input) {
        result += (std::isalnum(static_cast<unsigned char>(c)) ? c : '_');
    }
    return result;
}

std::string to_pascal_case(const std::string& input) {
    std::string result;
    bool capitalize = true;
    for (char c : input) {
        if (c == '_') { capitalize = true; continue; }
        result += capitalize ? static_cast<char>(std::toupper(static_cast<unsigned char>(c))) : c;
        capitalize = false;
    }
    return result;
}

std::string to_snake_case(const std::string& input) {
    std::string result;
    for (char c : input) {
        result += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return result;
}

static bool is_zig_keyword(const std::string& s) {
    static const std::set<std::string> keywords = {
        "addrspace","align","allowzero","and","anyframe","anytype","asm","async",
        "await","break","callconv","catch","comptime","const","continue","defer",
        "else","enum","errdefer","error","export","extern","false","fn","for",
        "if","inline","linksection","noalias","noinline","nosuspend","null",
        "opaque","or","orelse","packed","pub","resume","return","struct",
        "suspend","switch","test","threadlocal","true","try","union",
        "unreachable","usingnamespace","var","volatile","while"
    };
    return keywords.count(s) > 0;
}

static bool is_zig_ident_char(char c, bool first) {
    if (c == '_') return true;
    if (first) return std::isalpha(static_cast<unsigned char>(c)) != 0;
    return std::isalnum(static_cast<unsigned char>(c)) != 0;
}

std::string zig_ident(const std::string& input) {
    if (input.empty()) return "@\"\"";
    bool valid = is_zig_ident_char(input[0], true);
    if (valid) {
        for (size_t i = 1; i < input.size(); i++) {
            if (!is_zig_ident_char(input[i], false)) { valid = false; break; }
        }
    }
    if (valid && !is_zig_keyword(input)) return input;
    // Escape.
    std::string escaped;
    for (char c : input) {
        if (c == '\\') escaped += "\\\\";
        else if (c == '"') escaped += "\\\"";
        else escaped += c;
    }
    return "@\"" + escaped + "\"";
}

std::string hex_str(uint64_t value) {
    std::ostringstream ss;
    ss << "0x" << std::uppercase << std::hex << value;
    return ss.str();
}

// ════════════════════════════════════════════════════════════
//  Formatter
// ════════════════════════════════════════════════════════════

Formatter::Formatter(int indent_size) : m_indent_size(indent_size) {}

void Formatter::push_indentation() {
    if (m_indent_level > 0)
        m_out << std::string(static_cast<size_t>(m_indent_level * m_indent_size), ' ');
}

void Formatter::write(const std::string& text) {
    m_out << text;
}

void Formatter::writeln(const std::string& line) {
    if (!line.empty()) push_indentation();
    m_out << line << "\n";
}

void Formatter::indent() { m_indent_level++; }
void Formatter::dedent() { if (m_indent_level > 0) m_indent_level--; }

// ════════════════════════════════════════════════════════════
//  Output — construction & coordination
// ════════════════════════════════════════════════════════════

static std::string get_iso_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf{};
    gmtime_s(&tm_buf, &t);
    std::ostringstream ss;
    ss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

Output::Output(const std::vector<std::string>& file_types,
               int indent_size,
               const std::filesystem::path& out_dir,
               const AnalysisResult& result)
    : m_file_types(file_types)
    , m_indent_size(indent_size)
    , m_out_dir(out_dir)
    , m_result(result)
    , m_timestamp(get_iso_timestamp())
{
    std::filesystem::create_directories(m_out_dir);
}

void Output::write_banner(Formatter& fmt) const {
    fmt.writeln("// Generated using https://github.com/simv0lofficial/cs2_dumper");
    fmt.writeln("// " + m_timestamp);
    fmt.writeln();
}

void Output::dump_all(Process& process) const {
    dump_buttons();
    dump_interfaces();
    dump_offsets();
    dump_schemas();
    dump_info(process);
}

// Helper to write a file with the given content via a format-specific writer.
static void write_file(const std::filesystem::path& path, const std::string& content) {
    std::ofstream out(path, std::ios::binary);
    out << content;
}

// ════════════════════════════════════════════════════════════
//  BUTTONS
// ════════════════════════════════════════════════════════════

void Output::dump_buttons() const {
    for (const auto& ft : m_file_types) {
        Formatter fmt(m_indent_size);
        if (ft != "json") write_banner(fmt);

        if (ft == "cs")   write_buttons_cs(fmt, m_result.buttons);
        else if (ft == "hpp")  write_buttons_hpp(fmt, m_result.buttons);
        else if (ft == "json") write_buttons_json(fmt, m_result.buttons);
        else if (ft == "rs")   write_buttons_rs(fmt, m_result.buttons);
        else if (ft == "zig")  write_buttons_zig(fmt, m_result.buttons);

        write_file(m_out_dir / ("buttons." + ft), fmt.str());
    }
}

void Output::write_buttons_cs(Formatter& fmt, const ButtonMap& buttons) {
    fmt.block("namespace CS2Dumper", false, [&](Formatter& f) {
        f.writeln("// Module: client.dll");
        f.block("public static class Buttons", false, [&](Formatter& f2) {
            for (const auto& [name, value] : buttons)
                f2.writeln("public const nint " + name + " = " + hex_str(value) + ";");
        });
    });
}

void Output::write_buttons_hpp(Formatter& fmt, const ButtonMap& buttons) {
    fmt.writeln("#pragma once");
    fmt.writeln();
    fmt.writeln("#include <cstddef>");
    fmt.writeln("#include <cstdint>");
    fmt.writeln();
    fmt.block("namespace cs2_dumper", false, [&](Formatter& f) {
        f.writeln("// Module: client.dll");
        f.block("namespace buttons", false, [&](Formatter& f2) {
            for (const auto& [name, value] : buttons)
                f2.writeln("constexpr std::ptrdiff_t " + name + " = " + hex_str(value) + ";");
        });
    });
}

void Output::write_buttons_json(Formatter& fmt, const ButtonMap& buttons) {
    json j;
    json btn_obj = json::object();
    for (const auto& [name, value] : buttons) btn_obj[name] = value;
    j["client.dll"] = btn_obj;
    fmt.write(j.dump(4));
}

void Output::write_buttons_rs(Formatter& fmt, const ButtonMap& buttons) {
    fmt.writeln("#![allow(non_upper_case_globals, unused)]");
    fmt.writeln();
    fmt.block("pub mod cs2_dumper", false, [&](Formatter& f) {
        f.writeln("// Module: client.dll");
        f.block("pub mod buttons", false, [&](Formatter& f2) {
            for (const auto& [name, value] : buttons) {
                std::string n = (name == "use") ? "r#use" : name;
                f2.writeln("pub const " + n + ": usize = " + hex_str(value) + ";");
            }
        });
    });
}

void Output::write_buttons_zig(Formatter& fmt, const ButtonMap& buttons) {
    fmt.block("pub const cs2_dumper = struct", true, [&](Formatter& f) {
        f.writeln("// Module: client.dll");
        f.block("pub const buttons = struct", true, [&](Formatter& f2) {
            for (const auto& [name, value] : buttons)
                f2.writeln("pub const " + zig_ident(name) + ": usize = " + hex_str(value) + ";");
        });
    });
}

// ════════════════════════════════════════════════════════════
//  INTERFACES
// ════════════════════════════════════════════════════════════

void Output::dump_interfaces() const {
    for (const auto& ft : m_file_types) {
        Formatter fmt(m_indent_size);
        if (ft != "json") write_banner(fmt);

        if (ft == "cs")   write_interfaces_cs(fmt, m_result.interfaces);
        else if (ft == "hpp")  write_interfaces_hpp(fmt, m_result.interfaces);
        else if (ft == "json") write_interfaces_json(fmt, m_result.interfaces);
        else if (ft == "rs")   write_interfaces_rs(fmt, m_result.interfaces);
        else if (ft == "zig")  write_interfaces_zig(fmt, m_result.interfaces);

        write_file(m_out_dir / ("interfaces." + ft), fmt.str());
    }
}

void Output::write_interfaces_cs(Formatter& fmt, const InterfaceMap& ifaces) {
    fmt.block("namespace CS2Dumper.Interfaces", false, [&](Formatter& f) {
        for (const auto& [module_name, entries] : ifaces) {
            f.writeln("// Module: " + module_name);
            f.block("public static class " + to_pascal_case(slugify(module_name)), false, [&](Formatter& f2) {
                for (const auto& [name, value] : entries) {
                    if (value > static_cast<uint64_t>(INT32_MAX))
                        f2.writeln("public static readonly nint " + name + " = unchecked((nint)" + hex_str(value) + ");");
                    else
                        f2.writeln("public const nint " + name + " = " + hex_str(value) + ";");
                }
            });
        }
    });
}

void Output::write_interfaces_hpp(Formatter& fmt, const InterfaceMap& ifaces) {
    fmt.writeln("#pragma once");
    fmt.writeln();
    fmt.writeln("#include <cstddef>");
    fmt.writeln("#include <cstdint>");
    fmt.writeln();
    fmt.block("namespace cs2_dumper", false, [&](Formatter& f) {
        f.block("namespace interfaces", false, [&](Formatter& f2) {
            for (const auto& [module_name, entries] : ifaces) {
                f2.writeln("// Module: " + module_name);
                f2.block("namespace " + to_snake_case(slugify(module_name)), false, [&](Formatter& f3) {
                    for (const auto& [name, value] : entries)
                        f3.writeln("constexpr std::ptrdiff_t " + name + " = " + hex_str(value) + ";");
                });
            }
        });
    });
}

void Output::write_interfaces_json(Formatter& fmt, const InterfaceMap& ifaces) {
    json j;
    for (const auto& [module_name, entries] : ifaces) {
        json mod_obj = json::object();
        for (const auto& [name, value] : entries) mod_obj[name] = value;
        j[module_name] = mod_obj;
    }
    fmt.write(j.dump(4));
}

void Output::write_interfaces_rs(Formatter& fmt, const InterfaceMap& ifaces) {
    fmt.writeln("#![allow(non_upper_case_globals, unused)]");
    fmt.writeln();
    fmt.block("pub mod cs2_dumper", false, [&](Formatter& f) {
        f.block("pub mod interfaces", false, [&](Formatter& f2) {
            for (const auto& [module_name, entries] : ifaces) {
                f2.writeln("// Module: " + module_name);
                f2.block("pub mod " + to_snake_case(slugify(module_name)), false, [&](Formatter& f3) {
                    for (const auto& [name, value] : entries)
                        f3.writeln("pub const " + name + ": usize = " + hex_str(value) + ";");
                });
            }
        });
    });
}

void Output::write_interfaces_zig(Formatter& fmt, const InterfaceMap& ifaces) {
    fmt.block("pub const cs2_dumper = struct", true, [&](Formatter& f) {
        f.block("pub const interfaces = struct", true, [&](Formatter& f2) {
            for (const auto& [module_name, entries] : ifaces) {
                f2.writeln("// Module: " + module_name);
                f2.block("pub const " + zig_ident(to_snake_case(slugify(module_name))) + " = struct", true, [&](Formatter& f3) {
                    for (const auto& [name, value] : entries)
                        f3.writeln("pub const " + zig_ident(name) + ": usize = " + hex_str(value) + ";");
                });
            }
        });
    });
}

// ════════════════════════════════════════════════════════════
//  OFFSETS
// ════════════════════════════════════════════════════════════

void Output::dump_offsets() const {
    for (const auto& ft : m_file_types) {
        Formatter fmt(m_indent_size);
        if (ft != "json") write_banner(fmt);

        if (ft == "cs")   write_offsets_cs(fmt, m_result.offsets);
        else if (ft == "hpp")  write_offsets_hpp(fmt, m_result.offsets);
        else if (ft == "json") write_offsets_json(fmt, m_result.offsets);
        else if (ft == "rs")   write_offsets_rs(fmt, m_result.offsets);
        else if (ft == "zig")  write_offsets_zig(fmt, m_result.offsets);

        write_file(m_out_dir / ("offsets." + ft), fmt.str());
    }
}

void Output::write_offsets_cs(Formatter& fmt, const OffsetMap& offsets) {
    fmt.block("namespace CS2Dumper.Offsets", false, [&](Formatter& f) {
        for (const auto& [module_name, entries] : offsets) {
            f.writeln("// Module: " + module_name);
            f.block("public static class " + to_pascal_case(slugify(module_name)), false, [&](Formatter& f2) {
                for (const auto& [name, value] : entries)
                    f2.writeln("public const nint " + name + " = " + hex_str(value) + ";");
            });
        }
    });
}

void Output::write_offsets_hpp(Formatter& fmt, const OffsetMap& offsets) {
    fmt.writeln("#pragma once");
    fmt.writeln();
    fmt.writeln("#include <cstddef>");
    fmt.writeln("#include <cstdint>");
    fmt.writeln();
    fmt.block("namespace cs2_dumper", false, [&](Formatter& f) {
        f.block("namespace offsets", false, [&](Formatter& f2) {
            for (const auto& [module_name, entries] : offsets) {
                f2.writeln("// Module: " + module_name);
                f2.block("namespace " + to_snake_case(slugify(module_name)), false, [&](Formatter& f3) {
                    for (const auto& [name, value] : entries)
                        f3.writeln("constexpr std::ptrdiff_t " + name + " = " + hex_str(value) + ";");
                });
            }
        });
    });
}

void Output::write_offsets_json(Formatter& fmt, const OffsetMap& offsets) {
    json j;
    for (const auto& [module_name, entries] : offsets) {
        json mod_obj = json::object();
        for (const auto& [name, value] : entries) mod_obj[name] = value;
        j[module_name] = mod_obj;
    }
    fmt.write(j.dump(4));
}

void Output::write_offsets_rs(Formatter& fmt, const OffsetMap& offsets) {
    fmt.writeln("#![allow(non_upper_case_globals, unused)]");
    fmt.writeln();
    fmt.block("pub mod cs2_dumper", false, [&](Formatter& f) {
        f.block("pub mod offsets", false, [&](Formatter& f2) {
            for (const auto& [module_name, entries] : offsets) {
                f2.writeln("// Module: " + module_name);
                f2.block("pub mod " + to_snake_case(slugify(module_name)), false, [&](Formatter& f3) {
                    for (const auto& [name, value] : entries)
                        f3.writeln("pub const " + name + ": usize = " + hex_str(value) + ";");
                });
            }
        });
    });
}

void Output::write_offsets_zig(Formatter& fmt, const OffsetMap& offsets) {
    fmt.block("pub const cs2_dumper = struct", true, [&](Formatter& f) {
        f.block("pub const offsets = struct", true, [&](Formatter& f2) {
            for (const auto& [module_name, entries] : offsets) {
                f2.writeln("// Module: " + module_name);
                f2.block("pub const " + zig_ident(to_snake_case(slugify(module_name))) + " = struct", true, [&](Formatter& f3) {
                    for (const auto& [name, value] : entries)
                        f3.writeln("pub const " + zig_ident(name) + ": usize = " + hex_str(value) + ";");
                });
            }
        });
    });
}

// ════════════════════════════════════════════════════════════
//  SCHEMAS
// ════════════════════════════════════════════════════════════

static void write_metadata_comments(Formatter& fmt, const std::vector<ClassMetadata>& metadata) {
    if (metadata.empty()) return;
    fmt.writeln("//");
    fmt.writeln("// Metadata:");
    for (const auto& m : metadata) {
        switch (m.type) {
        case ClassMetadata::Type::NetworkChangeCallback:
            fmt.writeln("// NetworkChangeCallback: " + m.name);
            break;
        case ClassMetadata::Type::NetworkVarNames:
            fmt.writeln("// NetworkVarNames: " + m.name + " (" + m.type_name + ")");
            break;
        case ClassMetadata::Type::Unknown:
            fmt.writeln("// " + m.name);
            break;
        }
    }
}

void Output::dump_schemas() const {
    for (const auto& [module_name, data] : m_result.schemas) {
        SchemaMap single_module;
        single_module[module_name] = data;

        for (const auto& ft : m_file_types) {
            Formatter fmt(m_indent_size);
            if (ft != "json") write_banner(fmt);

            if (ft == "cs")   write_schemas_cs(fmt, single_module);
            else if (ft == "hpp")  write_schemas_hpp(fmt, single_module);
            else if (ft == "json") write_schemas_json(fmt, single_module);
            else if (ft == "rs")   write_schemas_rs(fmt, single_module);
            else if (ft == "zig")  write_schemas_zig(fmt, single_module);

            write_file(m_out_dir / (slugify(module_name) + "." + ft), fmt.str());
        }
    }
}

// ── schemas CS ──

void Output::write_schemas_cs(Formatter& fmt, const SchemaMap& schemas) {
    fmt.block("namespace CS2Dumper.Schemas", false, [&](Formatter& f) {
        for (const auto& [module_name, data] : schemas) {
            const auto& [classes, enums] = data;
            f.writeln("// Module: " + module_name);
            f.writeln("// Class count: " + std::to_string(classes.size()));
            f.writeln("// Enum count: " + std::to_string(enums.size()));

            f.block("public static class " + to_pascal_case(slugify(module_name)), false, [&](Formatter& f2) {
                for (const auto& e : enums) {
                    const char* type_name;
                    switch (e.alignment) {
                        case 1: type_name = "byte"; break;
                        case 2: type_name = "ushort"; break;
                        case 4: type_name = "uint"; break;
                        case 8: type_name = "ulong"; break;
                        default: continue;
                    }
                    f2.writeln("// Alignment: " + std::to_string(e.alignment));
                    f2.writeln("// Member count: " + std::to_string(e.member_count));
                    f2.block("public enum " + slugify(e.name) + " : " + type_name, false, [&](Formatter& f3) {
                        for (size_t i = 0; i < e.members.size(); i++) {
                            auto& m = e.members[i];
                            std::string val;
                            if (m.value >= 0 && m.value <= INT32_MAX) val = hex_str(static_cast<uint64_t>(m.value));
                            else val = std::string("unchecked((") + type_name + ")" + std::to_string(m.value) + ")";
                            std::string sep = (i + 1 < e.members.size()) ? "," : "";
                            f3.writeln(m.name + " = " + val + sep);
                        }
                    });
                }
                for (const auto& cls : classes) {
                    std::string parent = cls.parent_name.value_or("None");
                    if (parent != "None") parent = slugify(parent);
                    f2.writeln("// Parent: " + parent);
                    f2.writeln("// Field count: " + std::to_string(cls.fields.size()));
                    write_metadata_comments(f2, cls.metadata);
                    f2.block("public static class " + slugify(cls.name), false, [&](Formatter& f3) {
                        for (const auto& field : cls.fields)
                            f3.writeln("public const nint " + field.name + " = " + hex_str(static_cast<uint64_t>(field.offset)) + "; // " + field.type_name);
                    });
                }
            });
        }
    });
}

// ── schemas HPP ──

void Output::write_schemas_hpp(Formatter& fmt, const SchemaMap& schemas) {
    fmt.writeln("#pragma once");
    fmt.writeln();
    fmt.writeln("#include <cstddef>");
    fmt.writeln("#include <cstdint>");
    fmt.writeln();
    fmt.block("namespace cs2_dumper", false, [&](Formatter& f) {
        f.block("namespace schemas", false, [&](Formatter& f2) {
            for (const auto& [module_name, data] : schemas) {
                const auto& [classes, enums] = data;
                f2.writeln("// Module: " + module_name);
                f2.writeln("// Class count: " + std::to_string(classes.size()));
                f2.writeln("// Enum count: " + std::to_string(enums.size()));

                f2.block("namespace " + to_snake_case(slugify(module_name)), false, [&](Formatter& f3) {
                    for (const auto& e : enums) {
                        const char* type_name;
                        switch (e.alignment) {
                            case 1: type_name = "uint8_t"; break;
                            case 2: type_name = "uint16_t"; break;
                            case 4: type_name = "uint32_t"; break;
                            case 8: type_name = "uint64_t"; break;
                            default: continue;
                        }
                        f3.writeln("// Alignment: " + std::to_string(e.alignment));
                        f3.writeln("// Member count: " + std::to_string(e.member_count));
                        f3.block("enum class " + slugify(e.name) + " : " + type_name, true, [&](Formatter& f4) {
                            for (size_t i = 0; i < e.members.size(); i++) {
                                auto& m = e.members[i];
                                std::string val;
                                if (m.value >= 0 && m.value <= INT32_MAX) {
                                    val = hex_str(static_cast<uint64_t>(m.value));
                                } else {
                                    uint64_t max_val = 0;
                                    if (std::string(type_name) == "uint8_t") max_val = 0xFF;
                                    else if (std::string(type_name) == "uint16_t") max_val = 0xFFFF;
                                    else if (std::string(type_name) == "uint32_t") max_val = 0xFFFFFFFF;
                                    else max_val = 0xFFFFFFFFFFFFFFFF;
                                    val = hex_str(max_val);
                                }
                                std::string sep = (i + 1 < e.members.size()) ? "," : "";
                                f4.writeln(m.name + " = " + val + sep);
                            }
                        });
                    }
                    for (const auto& cls : classes) {
                        std::string parent = cls.parent_name.value_or("None");
                        if (parent != "None") parent = slugify(parent);
                        f3.writeln("// Parent: " + parent);
                        f3.writeln("// Field count: " + std::to_string(cls.fields.size()));
                        write_metadata_comments(f3, cls.metadata);
                        f3.block("namespace " + slugify(cls.name), false, [&](Formatter& f4) {
                            for (const auto& field : cls.fields)
                                f4.writeln("constexpr std::ptrdiff_t " + field.name + " = " + hex_str(static_cast<uint64_t>(field.offset)) + "; // " + field.type_name);
                        });
                    }
                });
            }
        });
    });
}

// ── schemas JSON ──

void Output::write_schemas_json(Formatter& fmt, const SchemaMap& schemas) {
    json j;
    for (const auto& [module_name, data] : schemas) {
        const auto& [classes, enums] = data;
        json classes_obj = json::object();
        for (const auto& cls : classes) {
            json fields_obj = json::object();
            for (const auto& f : cls.fields) fields_obj[f.name] = f.offset;
            json meta_arr = json::array();
            for (const auto& m : cls.metadata) {
                json mo;
                switch (m.type) {
                case ClassMetadata::Type::NetworkChangeCallback:
                    mo = {{"type", "NetworkChangeCallback"}, {"name", m.name}}; break;
                case ClassMetadata::Type::NetworkVarNames:
                    mo = {{"type", "NetworkVarNames"}, {"name", m.name}, {"type_name", m.type_name}}; break;
                default:
                    mo = {{"type", "Unknown"}, {"name", m.name}}; break;
                }
                meta_arr.push_back(mo);
            }
            classes_obj[slugify(cls.name)] = {
                {"parent", cls.parent_name.has_value() ? json(cls.parent_name.value()) : json(nullptr)},
                {"fields", fields_obj},
                {"metadata", meta_arr}
            };
        }
        json enums_obj = json::object();
        for (const auto& e : enums) {
            json members_obj = json::object();
            for (const auto& m : e.members) members_obj[m.name] = m.value;
            const char* type_name;
            switch (e.alignment) {
                case 1: type_name = "uint8"; break;
                case 2: type_name = "uint16"; break;
                case 4: type_name = "uint32"; break;
                case 8: type_name = "uint64"; break;
                default: type_name = "unknown"; break;
            }
            enums_obj[slugify(e.name)] = {
                {"alignment", e.alignment},
                {"type", type_name},
                {"members", members_obj}
            };
        }
        j[module_name] = {{"classes", classes_obj}, {"enums", enums_obj}};
    }
    fmt.write(j.dump(4));
}

// ── schemas RS ──

void Output::write_schemas_rs(Formatter& fmt, const SchemaMap& schemas) {
    fmt.writeln("#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case, unused)]");
    fmt.writeln();
    fmt.block("pub mod cs2_dumper", false, [&](Formatter& f) {
        f.block("pub mod schemas", false, [&](Formatter& f2) {
            for (const auto& [module_name, data] : schemas) {
                const auto& [classes, enums] = data;
                f2.writeln("// Module: " + module_name);
                f2.writeln("// Class count: " + std::to_string(classes.size()));
                f2.writeln("// Enum count: " + std::to_string(enums.size()));
                f2.block("pub mod " + to_snake_case(slugify(module_name)), false, [&](Formatter& f3) {
                    for (const auto& e : enums) {
                        const char* type_name;
                        switch (e.alignment) {
                            case 1: type_name = "u8"; break;
                            case 2: type_name = "u16"; break;
                            case 4: type_name = "u32"; break;
                            case 8: type_name = "u64"; break;
                            default: continue;
                        }
                        f3.writeln("// Alignment: " + std::to_string(e.alignment));
                        f3.writeln("// Member count: " + std::to_string(e.member_count));
                        std::set<int64_t> used_values;
                        f3.block("#[repr(" + std::string(type_name) + ")]\npub enum " + slugify(e.name), false, [&](Formatter& f4) {
                            bool first = true;
                            for (const auto& m : e.members) {
                                if (!used_values.insert(m.value).second) continue;
                                std::string val;
                                if (m.value == -1) val = std::string(type_name) + "::MAX";
                                else val = hex_str(static_cast<uint64_t>(m.value));
                                if (!first) f4.write(",\n");
                                first = false;
                                f4.writeln(m.name + " = " + val);
                            }
                        });
                    }
                    for (const auto& cls : classes) {
                        std::string parent = cls.parent_name.value_or("None");
                        if (parent != "None") parent = slugify(parent);
                        f3.writeln("// Parent: " + parent);
                        f3.writeln("// Field count: " + std::to_string(cls.fields.size()));
                        write_metadata_comments(f3, cls.metadata);
                        f3.block("pub mod " + slugify(cls.name), false, [&](Formatter& f4) {
                            for (const auto& field : cls.fields)
                                f4.writeln("pub const " + field.name + ": usize = " + hex_str(static_cast<uint64_t>(field.offset)) + "; // " + field.type_name);
                        });
                    }
                });
            }
        });
    });
}

// ── schemas ZIG ──

static std::string format_zig_enum_value(int64_t value, const std::string& type_name) {
    if (value >= 0) return hex_str(static_cast<uint64_t>(value));
    uint64_t wrapped;
    if (type_name == "u8") wrapped = static_cast<uint8_t>(value);
    else if (type_name == "u16") wrapped = static_cast<uint16_t>(value);
    else if (type_name == "u32") wrapped = static_cast<uint32_t>(value);
    else wrapped = static_cast<uint64_t>(value);
    return hex_str(wrapped);
}

void Output::write_schemas_zig(Formatter& fmt, const SchemaMap& schemas) {
    fmt.block("pub const cs2_dumper = struct", true, [&](Formatter& f) {
        f.block("pub const schemas = struct", true, [&](Formatter& f2) {
            for (const auto& [module_name, data] : schemas) {
                const auto& [classes, enums] = data;
                f2.writeln("// Module: " + module_name);
                f2.writeln("// Class count: " + std::to_string(classes.size()));
                f2.writeln("// Enum count: " + std::to_string(enums.size()));
                f2.block("pub const " + zig_ident(to_snake_case(slugify(module_name))) + " = struct", true, [&](Formatter& f3) {
                    for (const auto& e : enums) {
                        const char* type_name;
                        switch (e.alignment) {
                            case 1: type_name = "u8"; break;
                            case 2: type_name = "u16"; break;
                            case 4: type_name = "u32"; break;
                            case 8: type_name = "u64"; break;
                            default: continue;
                        }
                        f3.writeln("// Alignment: " + std::to_string(e.alignment));
                        f3.writeln("// Member count: " + std::to_string(e.member_count));
                        std::set<int64_t> used_values;
                        f3.block("pub const " + zig_ident(slugify(e.name)) + " = enum(" + type_name + ")", true, [&](Formatter& f4) {
                            bool first = true;
                            for (const auto& m : e.members) {
                                if (!used_values.insert(m.value).second) continue;
                                if (!first) f4.write(",\n");
                                first = false;
                                f4.writeln(zig_ident(m.name) + " = " + format_zig_enum_value(m.value, type_name));
                            }
                        });
                    }
                    for (const auto& cls : classes) {
                        std::string parent = cls.parent_name.value_or("None");
                        if (parent != "None") parent = slugify(parent);
                        f3.writeln("// Parent: " + parent);
                        f3.writeln("// Field count: " + std::to_string(cls.fields.size()));
                        write_metadata_comments(f3, cls.metadata);
                        f3.block("pub const " + zig_ident(slugify(cls.name)) + " = struct", true, [&](Formatter& f4) {
                            for (const auto& field : cls.fields)
                                f4.writeln("pub const " + zig_ident(field.name) + ": usize = " + hex_str(static_cast<uint64_t>(field.offset)) + "; // " + field.type_name);
                        });
                    }
                });
            }
        });
    });
}

// ════════════════════════════════════════════════════════════
//  INFO.JSON
// ════════════════════════════════════════════════════════════

void Output::dump_info(Process& process) const {
    uint32_t build_number = 0;

    for (const auto& [module_name, offsets] : m_result.offsets) {
        auto it = offsets.find("dwBuildNumber");
        if (it == offsets.end()) continue;

        auto mod = process.module_by_name(module_name);
        if (!mod) continue;

        build_number = process.read<uint32_t>(mod->base + it->second);
        if (build_number != 0) break;
    }

    json j = {
        {"timestamp", m_timestamp},
        {"build_number", build_number}
    };

    write_file(m_out_dir / "info.json", j.dump(4));
}
