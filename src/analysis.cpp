#include "analysis.hpp"
#include "source2.hpp"

#include <algorithm>
#include <cstring>
#include <iostream>
#include <set>

// ── Logging helpers ─────────────────────────────────────────

static int g_verbose = 0;
void set_verbose_level(int level) { g_verbose = level; }

static void log_info(const std::string& msg) {
    if (g_verbose >= 2) std::cerr << "[INFO] " << msg << "\n";
}

static void log_debug(const std::string& msg) {
    if (g_verbose >= 3) std::cerr << "[DEBUG] " << msg << "\n";
}

static void log_error(const std::string& msg) {
    std::cerr << "[ERROR] " << msg << "\n";
}

// ════════════════════════════════════════════════════════════
//  BUTTONS
// ════════════════════════════════════════════════════════════

static ButtonMap analyze_buttons(Process& process) {
    ButtonMap result;

    auto mod = process.module_by_name("client.dll");
    if (!mod) { log_error("client.dll not found"); return result; }

    auto buf = process.read_raw(mod->base, mod->size);
    if (buf.empty()) { log_error("failed to read client.dll"); return result; }

    PeView view(buf);
    if (!view.is_valid()) { log_error("invalid PE: client.dll"); return result; }

    std::vector<uint32_t> save;
    if (!PatternScanner::finds_code(view, "488b15${'} 4885d2 74? 488b02 4885c0", save)) {
        log_error("outdated button list pattern");
        return result;
    }

    uint64_t list_head = process.read_ptr(mod->base + save[1]);
    if (!list_head) return result;

    uint64_t button_ptr = list_head;
    while (button_ptr) {
        KeyButton button = process.read<KeyButton>(button_ptr);
        std::string name = process.read_string(button.name, 32);
        if (name.empty()) break;

        auto state_addr = button_ptr + offsetof(KeyButton, state);
        auto state_rva = state_addr - mod->base;

        log_debug("found \"" + name + "\" at 0x" + std::to_string(state_rva));
        result[name] = state_rva;

        button_ptr = button.next;
    }

    return result;
}

// ════════════════════════════════════════════════════════════
//  INTERFACES
// ════════════════════════════════════════════════════════════

static std::map<std::string, uint64_t> read_interfaces(
    Process& process, const ModuleInfo& mod, uint64_t list_head)
{
    std::map<std::string, uint64_t> result;
    uint64_t reg_ptr = list_head;

    while (reg_ptr) {
        InterfaceReg reg = process.read<InterfaceReg>(reg_ptr);
        std::string name = process.read_string(reg.name, 128);
        if (name.empty()) break;

        auto instance_addr = address::resolve_rip(process, reg.create_fn);
        if (instance_addr > mod.base) {
            auto instance_rva = instance_addr - mod.base;
            log_debug("found \"" + name + "\" (" + mod.name + " + 0x" + std::to_string(instance_rva) + ")");
            result[name] = instance_rva;
        }

        reg_ptr = reg.next;
    }

    return result;
}

static InterfaceMap analyze_interfaces(Process& process) {
    InterfaceMap result;

    auto modules = process.module_list();
    for (const auto& mod : modules) {
        auto buf = process.read_raw(mod.base, mod.size);
        if (buf.empty()) continue;

        PeView view(buf);
        if (!view.is_valid()) continue;

        auto ci_rva = view.export_rva("CreateInterface");
        if (!ci_rva) continue;

        auto list_ptr = address::resolve_rip(process, mod.base + *ci_rva);
        auto list_head = process.read_ptr(list_ptr);
        if (!list_head) continue;

        auto ifaces = read_interfaces(process, mod, list_head);
        if (!ifaces.empty())
            result[mod.name] = std::move(ifaces);
    }

    return result;
}

// ════════════════════════════════════════════════════════════
//  OFFSETS
// ════════════════════════════════════════════════════════════

struct OffsetPattern {
    const char* name;
    const char* pattern;
    // Optional callback: (pe_view, results_map, primary_rva)
    std::function<void(const PeView&, std::map<std::string, uint32_t>&, uint32_t)> callback;
};

static std::map<std::string, uint32_t> scan_module_offsets(
    Process& process, const std::string& module_name,
    const std::vector<OffsetPattern>& patterns)
{
    std::map<std::string, uint32_t> result;

    auto mod = process.module_by_name(module_name);
    if (!mod) { log_error(module_name + " not found"); return result; }

    auto buf = process.read_raw(mod->base, mod->size);
    if (buf.empty()) { log_error("failed to read " + module_name); return result; }

    PeView view(buf);
    if (!view.is_valid()) { log_error("invalid PE: " + module_name); return result; }

    for (const auto& pat : patterns) {
        std::vector<uint32_t> save;
        if (!PatternScanner::finds_code(view, pat.pattern, save)) {
            log_error(std::string("outdated pattern: ") + pat.name);
            continue;
        }

        uint32_t rva = save[1];
        result[pat.name] = rva;

        if (pat.callback) {
            pat.callback(view, result, rva);
        }
    }

    for (const auto& [name, value] : result) {
        log_debug("found \"" + name + "\" (" + module_name + " + 0x" + std::to_string(value) + ")");
    }

    return result;
}

static OffsetMap analyze_offsets(Process& process) {
    OffsetMap result;

    // ── client.dll ──
    result["client.dll"] = scan_module_offsets(process, "client.dll", {
        {"dwCSGOInput", "488905${'} 0f57c0 0f1105",
            [](const PeView& view, std::map<std::string, uint32_t>& map, uint32_t rva) {
                std::vector<uint32_t> save;
                if (PatternScanner::finds_code(view, "f2420f108428u4", save))
                    map["dwViewAngles"] = rva + save[1];
            }
        },
        {"dwEntityList",       "48890d${'} e9${} cc", nullptr},
        {"dwGameEntitySystem", "488b1d${'} 48891d[4] 4c63b3", nullptr},
        {"dwGameEntitySystem_highestEntityIndex", "ff81u4 4885d2", nullptr},
        {"dwGameRules",        "f6c1010f85${} 4c8b05${'} 4d85", nullptr},
        {"dwGlobalVars",       "488915${'} 488942", nullptr},
        {"dwGlowManager",      "488b05${'} c3 cccccccccccccccc 8b41", nullptr},
        {"dwLocalPlayerController", "488b05${'} 4189be", nullptr},
        {"dwPlantedC4",        "488b1d${'} 4532f6", nullptr},
        {"dwPrediction",       "488d05${'} c3 cccccccccccccccc 405356 4154",
            [](const PeView& view, std::map<std::string, uint32_t>& map, uint32_t rva) {
                std::vector<uint32_t> save;
                if (PatternScanner::finds_code(view, "4c39b6u4 74? 4488be", save))
                    map["dwLocalPlayerPawn"] = rva + save[1];
            }
        },
        {"dwSensitivity",      "488d0d${[8]'} 660f6ecd",
            [](const PeView&, std::map<std::string, uint32_t>& map, uint32_t) {
                map["dwSensitivity_sensitivity"] = 0x58;
            }
        },
        {"dwViewMatrix",       "488d0d${'} 48c1e006", nullptr},
        {"dwViewRender",       "488905${'} 488bc8 4885c0", nullptr},
        {"dwWeaponC4",         "488b15${'} 488b5c24? ffc0 8905${} 488bc6 488934ea 80be", nullptr},
    });

    // ── engine2.dll ──
    result["engine2.dll"] = scan_module_offsets(process, "engine2.dll", {
        {"dwBuildNumber",    "8905${'} 488d0d${} ff15${} 488b0d", nullptr},
        {"dwNetworkGameClient", "48893d${'} ff87", nullptr},
        {"dwNetworkGameClient_clientTickCount",
            "8b81u4 c3 cccccccccccccccccc 8b81${} c3 cccccccccccccccccc 83b9", nullptr},
        {"dwNetworkGameClient_deltaTick", "4c8db7u4 4c897c24", nullptr},
        {"dwNetworkGameClient_isBackgroundMap",
            "0fb681u4 c3 cccccccccccccccc 0fb681${} c3 cccccccccccccccc 4883ec", nullptr},
        {"dwNetworkGameClient_localPlayer",
            "428b94d3u4 5b 49ffe3 32c0 5b c3 cccccccccccccccc 4053", nullptr},
        {"dwNetworkGameClient_maxClients",
            "8b81u4 c3????????? 8b81[4] c3????????? 8b81", nullptr},
        {"dwNetworkGameClient_serverTickCount",
            "8b81u4 c3 cccccccccccccccccc 83b9", nullptr},
        {"dwNetworkGameClient_signOnState", "448b81u4 488d0d", nullptr},
        {"dwWindowHeight", "8b05${'} 8903", nullptr},
        {"dwWindowWidth",  "8b05${'} 8907", nullptr},
    });

    // ── inputsystem.dll ──
    result["inputsystem.dll"] = scan_module_offsets(process, "inputsystem.dll", {
        {"dwInputSystem", "488905${'} 33c0", nullptr},
    });

    // ── matchmaking.dll ──
    result["matchmaking.dll"] = scan_module_offsets(process, "matchmaking.dll", {
        {"dwGameTypes", "488d0d${'} ff90", nullptr},
    });

    // ── soundsystem.dll ──
    result["soundsystem.dll"] = scan_module_offsets(process, "soundsystem.dll", {
        {"dwSoundSystem", "488d0d${'} e8${} 488b0d${} [3] 4c8b82", nullptr},
        {"dwSoundSystem_engineViewData", "0f1147u1 0f104e? 0f118f", nullptr},
    });

    return result;
}

// ════════════════════════════════════════════════════════════
//  SCHEMAS
// ════════════════════════════════════════════════════════════

// Collect element pointers from a UtlTsHash embedded in a type scope buffer.
static std::vector<uint64_t> utl_ts_hash_elements(
    Process& process, const UtlTsHash& hash)
{
    std::vector<uint64_t> elements;
    std::set<uint64_t> seen;

    int used_count = hash.entry_mem.blocks_allocated;
    int free_count = hash.entry_mem.peak_allocated;

    // Traverse bucket linked lists (allocated elements).
    for (int i = 0; i < UTL_TS_HASH_BUCKET_COUNT; i++) {
        uint64_t node_ptr = hash.buckets[i].first_uncommitted;
        while (node_ptr) {
            UtlTsHashFixedData node = process.read<UtlTsHashFixedData>(node_ptr);
            if (node.data && seen.insert(node.data).second) {
                elements.push_back(node.data);
            }
            if (static_cast<int>(elements.size()) >= used_count) break;
            node_ptr = node.next;
        }
    }

    // Traverse free list (unallocated blobs).
    uint64_t blob_ptr = hash.entry_mem.free_list_head;
    int blob_count = 0;
    while (blob_ptr && blob_count < free_count) {
        UtlTsHashAllocatedBlob blob = process.read<UtlTsHashAllocatedBlob>(blob_ptr);
        if (blob.data && seen.insert(blob.data).second) {
            elements.push_back(blob.data);
        }
        blob_ptr = blob.next;
        blob_count++;
    }

    return elements;
}

static bool is_valid_ident(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' && c != ':')
            return false;
    }
    return true;
}

static ClassInfo read_class_binding(Process& process, uint64_t binding_ptr) {
    ClassInfo cls;
    auto binding = process.read<SchemaClassInfoData>(binding_ptr);

    auto mod_name = process.read_string(binding.module_name, 128);
    cls.module_name = mod_name.empty() ? "" : (mod_name + ".dll");
    cls.name = process.read_string(binding.name, 128);
    if (!is_valid_ident(cls.name)) return {};

    // Parent class.
    if (binding.base_classes) {
        auto base_info = process.read<SchemaBaseClassInfoData>(binding.base_classes);
        if (base_info.class_ptr) {
            auto base_class = process.read<SchemaBaseClass>(base_info.class_ptr);
            auto parent = process.read_string(base_class.name, 128);
            if (is_valid_ident(parent)) cls.parent_name = parent;
        }
    }

    // Fields.
    if (binding.fields && binding.field_count > 0 && binding.field_count <= 8192) {
        for (int i = 0; i < binding.field_count; i++) {
            auto field_addr = binding.fields + static_cast<uint64_t>(i) * sizeof(SchemaClassFieldData);
            auto field = process.read<SchemaClassFieldData>(field_addr);

            if (!field.type_ptr) continue;

            ClassField cf;
            cf.name = process.read_string(field.name, 128);
            if (!is_valid_ident(cf.name)) continue;

            auto schema_type = process.read<SchemaType>(field.type_ptr);
            cf.type_name = process.read_string(schema_type.name, 128);
            // Remove spaces (matching Rust behavior).
            cf.type_name.erase(std::remove(cf.type_name.begin(), cf.type_name.end(), ' '), cf.type_name.end());
            cf.offset = field.offset;
            cls.fields.push_back(std::move(cf));
        }
    }

    // Metadata.
    if (binding.static_metadata && binding.static_metadata_count > 0 && binding.static_metadata_count <= 1024) {
        for (int i = 0; i < binding.static_metadata_count; i++) {
            auto meta_addr = binding.static_metadata + static_cast<uint64_t>(i) * sizeof(SchemaMetadataEntryData);
            auto meta = process.read<SchemaMetadataEntryData>(meta_addr);

            if (!meta.network_value) continue;

            auto meta_name = process.read_string(meta.name, 128);
            auto net_value = process.read<SchemaNetworkValue>(meta.network_value);

            ClassMetadata cm;
            if (meta_name == "MNetworkChangeCallback") {
                cm.type = ClassMetadata::Type::NetworkChangeCallback;
                cm.name = process.read_string(net_value.value.name_ptr, 128);
            } else if (meta_name == "MNetworkVarNames") {
                cm.type = ClassMetadata::Type::NetworkVarNames;
                cm.name = process.read_string(net_value.value.var_value.name, 128);
                cm.type_name = process.read_string(net_value.value.var_value.type_name, 128);
                cm.type_name.erase(std::remove(cm.type_name.begin(), cm.type_name.end(), ' '), cm.type_name.end());
            } else {
                cm.type = ClassMetadata::Type::Unknown;
                cm.name = meta_name;
            }
            cls.metadata.push_back(std::move(cm));
        }
    }

    return cls;
}

static EnumInfo read_enum_binding(Process& process, uint64_t binding_ptr) {
    EnumInfo en;
    auto binding = process.read<SchemaEnumInfoData>(binding_ptr);

    en.name = process.read_string(binding.name, 128);
    if (!is_valid_ident(en.name)) return {};

    if (binding.alignment != 1 && binding.alignment != 2 && binding.alignment != 4 && binding.alignment != 8)
        return {};

    if (binding.enumerator_count <= 0 || binding.enumerator_count > 4096)
        return {};

    en.alignment = binding.alignment;
    en.member_count = binding.enumerator_count;

    if (binding.enumerators) {
        for (int i = 0; i < binding.enumerator_count; i++) {
            auto enum_addr = binding.enumerators + static_cast<uint64_t>(i) * sizeof(SchemaEnumeratorInfoData);
            auto enumerator = process.read<SchemaEnumeratorInfoData>(enum_addr);

            EnumMember em;
            em.name = process.read_string(enumerator.name, 128);
            if (!is_valid_ident(em.name)) return {};
            em.value = static_cast<int64_t>(enumerator.value);
            en.members.push_back(std::move(em));
        }
    }

    return en;
}

static SchemaMap analyze_schemas(Process& process) {
    SchemaMap result;

    // Find schema system.
    auto mod = process.module_by_name("schemasystem.dll");
    if (!mod) { log_error("schemasystem.dll not found"); return result; }

    auto buf = process.read_raw(mod->base, mod->size);
    if (buf.empty()) { log_error("failed to read schemasystem.dll"); return result; }

    PeView view(buf);
    if (!view.is_valid()) { log_error("invalid PE: schemasystem.dll"); return result; }

    std::vector<uint32_t> save;
    if (!PatternScanner::finds_code(view, "4c8d35${'} 0f2845", save)) {
        log_error("outdated schema system pattern");
        return result;
    }

    auto schema_system = process.read<SchemaSystem>(mod->base + save[1]);

    if (schema_system.registration_count == 0) {
        log_error("no schema registrations");
        return result;
    }

    // Read type scopes.
    int scope_count = schema_system.type_scopes.count;
    for (int i = 0; i < scope_count; i++) {
        auto ptr_addr = schema_system.type_scopes.data + static_cast<uint64_t>(i) * sizeof(uint64_t);
        auto scope_ptr = process.read<uint64_t>(ptr_addr);
        if (!scope_ptr) continue;

        auto scope = process.read<SchemaSystemTypeScope>(scope_ptr);
        std::string module_name(scope.name, strnlen(scope.name, sizeof(scope.name)));

        // Read class bindings.
        auto class_ptrs = utl_ts_hash_elements(process, scope.class_bindings);
        std::vector<ClassInfo> classes;
        for (auto ptr : class_ptrs) {
            auto cls = read_class_binding(process, ptr);
            if (!cls.name.empty())
                classes.push_back(std::move(cls));
        }

        // Read enum bindings.
        auto enum_ptrs = utl_ts_hash_elements(process, scope.enum_bindings);
        std::vector<EnumInfo> enums;
        for (auto ptr : enum_ptrs) {
            auto en = read_enum_binding(process, ptr);
            if (!en.name.empty())
                enums.push_back(std::move(en));
        }

        if (classes.empty() && enums.empty()) continue;

        log_debug("module \"" + module_name + "\" contains " +
                  std::to_string(classes.size()) + " class(es) and " +
                  std::to_string(enums.size()) + " enum(s)");

        result[module_name] = {std::move(classes), std::move(enums)};
    }

    return result;
}

// ════════════════════════════════════════════════════════════
//  MAIN ENTRY POINT
// ════════════════════════════════════════════════════════════

AnalysisResult analyze_all(Process& process) {
    AnalysisResult result;

    result.buttons = analyze_buttons(process);
    log_info("found " + std::to_string(result.buttons.size()) + " buttons");

    result.interfaces = analyze_interfaces(process);
    size_t iface_count = 0;
    for (const auto& [_, v] : result.interfaces) iface_count += v.size();
    log_info("found " + std::to_string(iface_count) + " interfaces across " +
             std::to_string(result.interfaces.size()) + " modules");

    result.offsets = analyze_offsets(process);
    size_t offset_count = 0;
    for (const auto& [_, v] : result.offsets) offset_count += v.size();
    log_info("found " + std::to_string(offset_count) + " offsets across " +
             std::to_string(result.offsets.size()) + " modules");

    result.schemas = analyze_schemas(process);
    size_t class_count = 0, enum_count = 0;
    for (const auto& [_, v] : result.schemas) {
        class_count += v.first.size();
        enum_count += v.second.size();
    }
    log_info("found " + std::to_string(class_count) + " classes and " +
             std::to_string(enum_count) + " enums across " +
             std::to_string(result.schemas.size()) + " modules");

    return result;
}
