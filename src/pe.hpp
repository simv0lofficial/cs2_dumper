#pragma once

// PE64 image parser and pelite-compatible byte-pattern scanner.

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// ── PeView ──────────────────────────────────────────────────

struct PeSection {
    std::string name;
    uint32_t virtual_address;
    uint32_t virtual_size;
    uint32_t raw_offset;
    uint32_t raw_size;
    uint32_t characteristics;
    bool is_executable() const;
};

class PeView {
public:
    // Construct from raw PE image bytes (buffer must outlive PeView).
    explicit PeView(const std::vector<uint8_t>& data);

    [[nodiscard]] bool is_valid() const { return m_valid; }
    [[nodiscard]] uint64_t image_base() const { return m_image_base; }

    // Get all sections.
    [[nodiscard]] const std::vector<PeSection>& sections() const { return m_sections; }

    // Resolve an export by name. Returns its RVA.
    [[nodiscard]] std::optional<uint32_t> export_rva(const std::string& name) const;

    // Raw data pointer.
    [[nodiscard]] const uint8_t* data() const { return m_data; }
    [[nodiscard]] size_t data_size() const { return m_data_size; }

private:
    const uint8_t* m_data = nullptr;
    size_t         m_data_size = 0;
    bool           m_valid = false;
    uint64_t       m_image_base = 0;

    // Export directory info.
    uint32_t m_export_rva  = 0;
    uint32_t m_export_size = 0;

    std::vector<PeSection> m_sections;
};

// ── Pattern Scanner ─────────────────────────────────────────
//
// Supports a subset of pelite pattern syntax:
//   HH        — match exact hex byte (e.g. "48", "8b")
//   ?         — wildcard byte
//   [N]       — skip N bytes
//   ${'} — follow RIP-relative (4 bytes), save resolved target RVA
//   ${}       — follow RIP-relative but don't save (skip 4 bytes)
//   ${[N]'}   — follow RIP-relative, add N, save
//   u4        — read uint32, save, advance 4
//   u1        — read uint8, save, advance 1

class PatternScanner {
public:
    // Scan executable sections of a PE image for the pattern.
    // On match: save[0] = match start RVA, save[1..] = captured values.
    // Returns true on first match.
    static bool finds_code(const PeView& pe,
                           const std::string& pattern,
                           std::vector<uint32_t>& save);

private:
    // Internal pattern operation types.
    enum class OpType : uint8_t {
        Byte,           // match exact byte
        Wildcard,       // skip 1 byte
        Skip,           // skip N bytes
        RipSave,        // follow RIP-relative, optionally add extra, save to slot
        RipNoSave,      // follow RIP-relative, skip 4 bytes (no save)
        ReadU32Save,    // read uint32, save, advance 4
        ReadU8Save,     // read uint8, save, advance 1
    };

    struct Op {
        OpType   type;
        uint8_t  byte_val = 0;     // for Byte
        uint32_t skip_count = 0;   // for Skip, RipSave extra
        uint8_t  save_slot = 0;    // for save operations
    };

    static std::vector<Op> parse(const std::string& pattern);
    static bool try_match(const uint8_t* base, size_t buf_size,
                          size_t offset, const std::vector<Op>& ops,
                          std::vector<uint32_t>& save);
};
