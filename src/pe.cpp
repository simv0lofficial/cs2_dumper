#include "pe.hpp"

#include <algorithm>
#include <cstring>
#include <cctype>

#include <Windows.h>

// ── PeSection ───────────────────────────────────────────────

bool PeSection::is_executable() const {
    return (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
}

// ── PeView ──────────────────────────────────────────────────

PeView::PeView(const std::vector<uint8_t>& data)
    : m_data(data.data()), m_data_size(data.size())
{
    if (m_data_size < sizeof(IMAGE_DOS_HEADER)) return;

    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(m_data);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

    auto nt_offset = static_cast<size_t>(dos->e_lfanew);
    if (nt_offset + sizeof(IMAGE_NT_HEADERS64) > m_data_size) return;

    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(m_data + nt_offset);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return;

    m_image_base = nt->OptionalHeader.ImageBase;

    // Export directory.
    if (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT) {
        m_export_rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        m_export_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }

    // Sections.
    auto* section_hdr = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        PeSection sec;
        sec.name.assign(reinterpret_cast<const char*>(section_hdr[i].Name),
                        strnlen(reinterpret_cast<const char*>(section_hdr[i].Name), 8));
        sec.virtual_address = section_hdr[i].VirtualAddress;
        sec.virtual_size    = section_hdr[i].Misc.VirtualSize;
        sec.raw_offset      = section_hdr[i].PointerToRawData;
        sec.raw_size        = section_hdr[i].SizeOfRawData;
        sec.characteristics = section_hdr[i].Characteristics;
        m_sections.push_back(sec);
    }

    m_valid = true;
}

std::optional<uint32_t> PeView::export_rva(const std::string& name) const {
    if (!m_valid || m_export_rva == 0) return std::nullopt;
    if (m_export_rva >= m_data_size) return std::nullopt;

    auto* exp_dir = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(m_data + m_export_rva);

    auto names_rva = exp_dir->AddressOfNames;
    auto ordinals_rva = exp_dir->AddressOfNameOrdinals;
    auto funcs_rva = exp_dir->AddressOfFunctions;

    for (DWORD i = 0; i < exp_dir->NumberOfNames; i++) {
        auto name_ptr_rva_offset = names_rva + i * sizeof(uint32_t);
        if (name_ptr_rva_offset + sizeof(uint32_t) > m_data_size) break;

        uint32_t name_rva;
        std::memcpy(&name_rva, m_data + name_ptr_rva_offset, sizeof(uint32_t));
        if (name_rva >= m_data_size) continue;

        const char* export_name = reinterpret_cast<const char*>(m_data + name_rva);
        if (name == export_name) {
            auto ord_offset = ordinals_rva + i * sizeof(uint16_t);
            if (ord_offset + sizeof(uint16_t) > m_data_size) return std::nullopt;

            uint16_t ordinal;
            std::memcpy(&ordinal, m_data + ord_offset, sizeof(uint16_t));

            auto func_offset = funcs_rva + ordinal * sizeof(uint32_t);
            if (func_offset + sizeof(uint32_t) > m_data_size) return std::nullopt;

            uint32_t func_rva;
            std::memcpy(&func_rva, m_data + func_offset, sizeof(uint32_t));

            // Check for forwarded export (RVA points inside export directory).
            if (func_rva >= m_export_rva && func_rva < m_export_rva + m_export_size)
                return std::nullopt;

            return func_rva;
        }
    }
    return std::nullopt;
}

// ── Pattern Scanner ─────────────────────────────────────────

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool is_hex(char c) { return hex_val(c) >= 0; }

std::vector<PatternScanner::Op> PatternScanner::parse(const std::string& pattern) {
    std::vector<Op> ops;
    uint8_t next_save = 1; // save[0] is reserved for match start RVA
    size_t i = 0;
    const size_t len = pattern.size();

    while (i < len) {
        char c = pattern[i];

        // Skip whitespace.
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') { i++; continue; }

        // Hex byte pair.
        if (is_hex(c) && i + 1 < len && is_hex(pattern[i + 1])) {
            Op op;
            op.type = OpType::Byte;
            op.byte_val = static_cast<uint8_t>((hex_val(c) << 4) | hex_val(pattern[i + 1]));
            ops.push_back(op);
            i += 2;
            continue;
        }

        // Wildcard.
        if (c == '?') {
            ops.push_back({OpType::Wildcard});
            i++;
            continue;
        }

        // Skip [N].
        if (c == '[') {
            i++;
            uint32_t n = 0;
            while (i < len && pattern[i] >= '0' && pattern[i] <= '9') {
                n = n * 10 + (pattern[i] - '0');
                i++;
            }
            if (i < len && pattern[i] == ']') i++; // consume ']'
            Op op;
            op.type = OpType::Skip;
            op.skip_count = n;
            ops.push_back(op);
            continue;
        }

        // RIP-relative: ${'} or ${} or ${[N]'}
        if (c == '$' && i + 1 < len && pattern[i + 1] == '{') {
            i += 2; // skip '${'
            uint32_t extra = 0;
            bool has_save = false;

            // Parse inside braces.
            while (i < len && pattern[i] != '}') {
                if (pattern[i] == '[') {
                    // Parse [N] inside braces.
                    i++;
                    while (i < len && pattern[i] >= '0' && pattern[i] <= '9') {
                        extra = extra * 10 + (pattern[i] - '0');
                        i++;
                    }
                    if (i < len && pattern[i] == ']') i++;
                } else if (pattern[i] == '\'') {
                    has_save = true;
                    i++;
                } else {
                    i++;
                }
            }
            if (i < len && pattern[i] == '}') i++; // consume '}'

            if (has_save) {
                Op op;
                op.type = OpType::RipSave;
                op.skip_count = extra;
                op.save_slot = next_save++;
                ops.push_back(op);
            } else {
                ops.push_back({OpType::RipNoSave});
            }
            continue;
        }

        // Standalone $ followed by {} handled above.
        // For safety, also handle standalone $ (treat as rip-no-save skip 4).
        if (c == '$') {
            // Check if next is { (should have been caught above).
            // Otherwise, unexpected. Skip.
            ops.push_back({OpType::RipNoSave});
            i++;
            continue;
        }

        // u4 / u1 — read unsigned value and save.
        if (c == 'u' && i + 1 < len) {
            if (pattern[i + 1] == '4') {
                Op op;
                op.type = OpType::ReadU32Save;
                op.save_slot = next_save++;
                ops.push_back(op);
                i += 2;
                continue;
            }
            if (pattern[i + 1] == '1') {
                Op op;
                op.type = OpType::ReadU8Save;
                op.save_slot = next_save++;
                ops.push_back(op);
                i += 2;
                continue;
            }
        }

        // Unknown character — skip.
        i++;
    }

    return ops;
}

bool PatternScanner::try_match(const uint8_t* base, size_t buf_size,
                                size_t offset, const std::vector<Op>& ops,
                                std::vector<uint32_t>& save)
{
    size_t cursor = offset;

    for (const auto& op : ops) {
        switch (op.type) {
        case OpType::Byte:
            if (cursor >= buf_size) return false;
            if (base[cursor] != op.byte_val) return false;
            cursor++;
            break;

        case OpType::Wildcard:
            if (cursor >= buf_size) return false;
            cursor++;
            break;

        case OpType::Skip:
            cursor += op.skip_count;
            if (cursor > buf_size) return false;
            break;

        case OpType::RipSave: {
            // Read rel32 at cursor, resolve target RVA, add extra, save.
            if (cursor + 4 > buf_size) return false;
            int32_t rel32;
            std::memcpy(&rel32, base + cursor, sizeof(int32_t));
            auto target = static_cast<uint32_t>(cursor + 4 + rel32 + op.skip_count);
            if (op.save_slot < save.size())
                save[op.save_slot] = target;
            cursor += 4; // advance past the rel32
            break;
        }

        case OpType::RipNoSave:
            if (cursor + 4 > buf_size) return false;
            cursor += 4; // just skip the 4-byte relative displacement
            break;

        case OpType::ReadU32Save: {
            if (cursor + 4 > buf_size) return false;
            uint32_t val;
            std::memcpy(&val, base + cursor, sizeof(uint32_t));
            if (op.save_slot < save.size())
                save[op.save_slot] = val;
            cursor += 4;
            break;
        }

        case OpType::ReadU8Save: {
            if (cursor >= buf_size) return false;
            uint8_t val = base[cursor];
            if (op.save_slot < save.size())
                save[op.save_slot] = val;
            cursor++;
            break;
        }
        }
    }

    return true;
}

bool PatternScanner::finds_code(const PeView& pe,
                                 const std::string& pattern,
                                 std::vector<uint32_t>& save)
{
    auto ops = parse(pattern);
    if (ops.empty()) return false;

    // Determine required save slots.
    uint8_t max_slot = 0;
    for (const auto& op : ops) {
        if (op.type == OpType::RipSave || op.type == OpType::ReadU32Save || op.type == OpType::ReadU8Save) {
            if (op.save_slot > max_slot) max_slot = op.save_slot;
        }
    }
    save.resize(max_slot + 1, 0);

    const uint8_t* base = pe.data();
    size_t total_size = pe.data_size();

    // Scan executable sections.
    for (const auto& sec : pe.sections()) {
        if (!sec.is_executable()) continue;

        size_t start = sec.virtual_address;
        size_t end = start + sec.virtual_size;
        if (end > total_size) end = total_size;

        for (size_t offset = start; offset < end; offset++) {
            if (try_match(base, total_size, offset, ops, save)) {
                save[0] = static_cast<uint32_t>(offset);
                return true;
            }
        }
    }

    return false;
}
