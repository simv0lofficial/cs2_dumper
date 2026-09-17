#pragma once

// CS2 analysis result types and analysis entry point.

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "process.hpp"
#include "pe.hpp"

// ── Result types ────────────────────────────────────────────

// buttons: BTreeMap<String, umem> → map<name, rva>
using ButtonMap = std::map<std::string, uint64_t>;

// interfaces: BTreeMap<String, BTreeMap<String, umem>>
using InterfaceMap = std::map<std::string, std::map<std::string, uint64_t>>;

// offsets: BTreeMap<String, BTreeMap<String, Rva>>
using OffsetMap = std::map<std::string, std::map<std::string, uint32_t>>;

// ── Schema result types ─────────────────────────────────────

struct ClassMetadata {
    enum class Type { Unknown, NetworkChangeCallback, NetworkVarNames };
    Type type = Type::Unknown;
    std::string name;
    std::string type_name; // only for NetworkVarNames
};

struct ClassField {
    std::string name;
    std::string type_name;
    int32_t     offset = 0;
};

struct ClassInfo {
    std::string              name;
    std::string              module_name;
    std::optional<std::string> parent_name;
    std::vector<ClassMetadata> metadata;
    std::vector<ClassField>  fields;
};

struct EnumMember {
    std::string name;
    int64_t     value = 0;
};

struct EnumInfo {
    std::string            name;
    uint8_t                alignment = 0;
    uint16_t               member_count = 0;
    std::vector<EnumMember> members;
};

// schemas: BTreeMap<String, (Vec<Class>, Vec<Enum>)>
using SchemaMap = std::map<std::string, std::pair<std::vector<ClassInfo>, std::vector<EnumInfo>>>;

struct AnalysisResult {
    ButtonMap     buttons;
    InterfaceMap  interfaces;
    OffsetMap     offsets;
    SchemaMap     schemas;
};

// ── Analysis entry point ────────────────────────────────────

AnalysisResult analyze_all(Process& process);
