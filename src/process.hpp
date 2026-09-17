#pragma once

// Windows process memory reading abstraction for CS2 dumper.

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

struct ModuleInfo {
    std::string name;
    uintptr_t   base = 0;
    size_t      size = 0;
};

class Process {
public:
    // Find PID by process name (e.g. "cs2.exe").
    static std::optional<uint32_t> find_by_name(const std::string& process_name);

    Process() = default;
    explicit Process(uint32_t pid);
    ~Process();

    Process(const Process&) = delete;
    Process& operator=(const Process&) = delete;
    Process(Process&& other) noexcept;
    Process& operator=(Process&& other) noexcept;

    [[nodiscard]] bool is_valid() const;

    // Module enumeration.
    std::vector<ModuleInfo> module_list() const;
    std::optional<ModuleInfo> module_by_name(const std::string& name) const;

    // Raw memory read. Returns empty vector on failure.
    std::vector<uint8_t> read_raw(uintptr_t addr, size_t len) const;

    // Typed read. Returns default-initialised T on failure.
    template <typename T>
    T read(uintptr_t addr) const {
        T value{};
        read_into(addr, &value, sizeof(T));
        return value;
    }

    // Read a 64-bit pointer.
    uint64_t read_ptr(uintptr_t addr) const;

    // Read a null-terminated UTF-8 string (up to max_len bytes).
    std::string read_string(uintptr_t addr, size_t max_len = 256) const;

private:
    bool read_into(uintptr_t addr, void* buf, size_t len) const;
    void* m_handle = nullptr;
};

// RIP-relative address resolution helpers.
// These read from process memory to resolve relative addresses.
namespace address {
    // Resolve RIP-relative: reads int32 at (base + offset), returns base + offset + 4 + rel32.
    uintptr_t resolve_rip(const Process& proc, uintptr_t base, size_t offset = 3);
    uintptr_t follow_call(const Process& proc, uintptr_t base);
    uintptr_t follow_jmp(const Process& proc, uintptr_t base);
}
