#include "process.hpp"

#include <algorithm>
#include <cctype>

#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

// ── helpers ──────────────────────────────────────────────────

static std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

// ── Process ──────────────────────────────────────────────────

std::optional<uint32_t> Process::find_by_name(const std::string& process_name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return std::nullopt;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    std::string target = to_lower(process_name);

    if (Process32FirstW(snap, &pe)) {
        do {
            // Convert wide string to narrow for comparison.
            char narrow[MAX_PATH]{};
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, narrow, MAX_PATH, nullptr, nullptr);
            if (to_lower(narrow) == target) {
                CloseHandle(snap);
                return pe.th32ProcessID;
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return std::nullopt;
}

Process::Process(uint32_t pid) {
    m_handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
}

Process::~Process() {
    if (m_handle) CloseHandle(m_handle);
}

Process::Process(Process&& other) noexcept : m_handle(other.m_handle) {
    other.m_handle = nullptr;
}

Process& Process::operator=(Process&& other) noexcept {
    if (this != &other) {
        if (m_handle) CloseHandle(m_handle);
        m_handle = other.m_handle;
        other.m_handle = nullptr;
    }
    return *this;
}

bool Process::is_valid() const {
    return m_handle != nullptr;
}

std::vector<ModuleInfo> Process::module_list() const {
    std::vector<ModuleInfo> result;
    if (!m_handle) return result;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                           GetProcessId(m_handle));
    if (snap == INVALID_HANDLE_VALUE) return result;

    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);

    if (Module32FirstW(snap, &me)) {
        do {
            // Only include 64-bit modules.
            if (me.modBaseSize == 0) continue;

            char narrow[MAX_PATH]{};
            WideCharToMultiByte(CP_UTF8, 0, me.szModule, -1, narrow, MAX_PATH, nullptr, nullptr);

            ModuleInfo info;
            info.name = narrow;
            info.base = reinterpret_cast<uintptr_t>(me.modBaseAddr);
            info.size = me.modBaseSize;
            result.push_back(std::move(info));
        } while (Module32NextW(snap, &me));
    }

    CloseHandle(snap);
    return result;
}

std::optional<ModuleInfo> Process::module_by_name(const std::string& name) const {
    std::string target = to_lower(name);
    for (auto& mod : module_list()) {
        if (to_lower(mod.name) == target)
            return mod;
    }
    return std::nullopt;
}

std::vector<uint8_t> Process::read_raw(uintptr_t addr, size_t len) const {
    std::vector<uint8_t> buf(len, 0);
    if (!read_into(addr, buf.data(), len))
        buf.clear();
    return buf;
}

uint64_t Process::read_ptr(uintptr_t addr) const {
    return read<uint64_t>(addr);
}

std::string Process::read_string(uintptr_t addr, size_t max_len) const {
    if (!addr || !m_handle) return {};

    std::vector<char> buf(max_len + 1, 0);
    SIZE_T bytes_read = 0;
    ReadProcessMemory(m_handle, reinterpret_cast<LPCVOID>(addr),
                      buf.data(), max_len, &bytes_read);

    buf[bytes_read] = '\0';
    return std::string(buf.data());
}

bool Process::read_into(uintptr_t addr, void* buf, size_t len) const {
    if (!m_handle || !addr) return false;

    SIZE_T bytes_read = 0;
    return ReadProcessMemory(m_handle, reinterpret_cast<LPCVOID>(addr),
                             buf, len, &bytes_read) && bytes_read == len;
}

// ── address helpers ─────────────────────────────────────────

uintptr_t address::resolve_rip(const Process& proc, uintptr_t base, size_t offset) {
    int32_t rel32 = proc.read<int32_t>(base + offset);
    auto instr_end = static_cast<int64_t>(base + offset + sizeof(int32_t));
    return static_cast<uintptr_t>(instr_end + rel32);
}

uintptr_t address::follow_call(const Process& proc, uintptr_t base) {
    return resolve_rip(proc, base, 1);
}

uintptr_t address::follow_jmp(const Process& proc, uintptr_t base) {
    return resolve_rip(proc, base, 1);
}
