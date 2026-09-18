# cs2-dumper (C++20 Port)

A high-performance, standalone 64-bit offsets, buttons, interfaces, and Source 2 schema dumper for **Counter-Strike 2**, completely rewritten in modern **C++20 (x64)**.

---

## 🌟 Credits & Acknowledgements

1. **Original Project:**
   * Special thanks to [**@a2x**](https://github.com/a2x) for the original [**cs2-dumper**](https://github.com/a2x/cs2-dumper) written in Rust. All signature patterns, Source 2 layout reverse-engineering, and output generation formats are based on their outstanding work.

2. **Porting & Development History (AI Collaboration):**
   * **Gemini (Stage 1 — Reverse Analysis & Architectural Design):**
     * Comprehensive analysis of the original Rust codebase (memflow memory subsystems, PE parser, signature scanner, Source 2 `SchemaSystem`, `UtlTsHash`, `UtlMemoryPool` structures).
     * Architectural design for porting to native C++20, replacing `memflow` with direct Win32 API calls (`OpenProcess`, `ReadProcessMemory`).
     * Prepared the detailed technical Implementation Plan.
   * **Claude Opus (Stage 2 — Core Engine Implementation):**
     * Initial translation of the project logic from Rust to C++20.
     * Established the modular project structure: `CMakeLists.txt`, `source2.hpp`, `process.cpp`, `pe.cpp`, `analysis.cpp`, `output.cpp`, `main.cpp`.
     * Implemented code generators for all 5 target output formats.
     * Configured initial MSVC compilation and resolved compiler warnings.
   * **Gemini (Stage 3 — Recovery, Live Debugging & Critical Fixes):**
     * Complete restoration of the project codebase from transaction history following accidental deletion.
     * End-to-end testing and runtime verification on live `cs2.exe` process memory.
     * **Resolved Critical Crash (Access Violation `0xC0000005`):** Pinpointed and resolved a crash in `analyze_schemas`. When traversing the Source 2 memory pool free list (`UtlTsHash`), `client.dll` yielded an unallocated/stale memory block with an invalid count of `62,385` enumerators. Implemented strict identifier validation (`is_valid_ident`), enum alignment checks, and bounds validation (`enumerator_count <= 4096`, `field_count <= 8192`), safely filtering corrupt blocks just like the original Rust implementation.
     * Updated the output file header banner URL from the original Rust repo to [https://github.com/simv0lofficial/cs2_dumper](https://github.com/simv0lofficial/cs2_dumper).
     * Finalized x64 Release builds, configured repository `.gitignore`, and completed documentation.

---

## ⚡ Features

* **Pure C++20 (x64):** No bulky external dependencies, virtual machines, or third-party kernel drivers required.
* **Native Win32 API:** Direct, fast virtual memory reading via standard Windows API.
* **Export to 5 Formats:**
  * **C#** (`.cs`)
  * **C++** (`.hpp`)
  * **JSON** (`.json`)
  * **Rust** (`.rs`)
  * **Zig** (`.zig`)
* **Full Source 2 Coverage:**
  * Input button offsets (`buttons.*`)
  * Global module offsets (`offsets.*` — `dwEntityList`, `dwLocalPlayerPawn`, `dwViewMatrix`, etc.)
  * Registered module interfaces (`interfaces.*`)
  * Exhaustive class schemas, member fields, type names, offsets, and enums for all engine DLLs (`client.dll`, `engine2.dll`, `server.dll`, etc.)
  * Build metadata (`info.json`) with game `build_number` and generation timestamp.
* **Blazing Fast:** Complete dump across all 86 files finishes in under **1 second** (~790–870 ms).

---

## 🛠 Building with Visual Studio

### Prerequisites
* Windows 10 / 11 (64-bit)
* **Visual Studio 2022** (Community, Professional, or Enterprise)
* Required Visual Studio Workloads & Components:
  * **Desktop development with C++**
  * **C++ CMake tools for Windows**

---

### Option 1: Visual Studio GUI (Recommended)

1. Open **Visual Studio 2022**.
2. On the start window, select **«Open a local folder»** and choose the `cs2_dumper` project directory.
3. Wait for Visual Studio to detect `CMakeLists.txt` and finish CMake cache generation (check the Output window: *CMake generation finished*).
4. In the top toolbar configuration dropdown, select **`x64-Release`** (or `Release`).
5. In the menu, go to: **Build** -> **Build All** (or press `Ctrl + Shift + B`).
6. The compiled binary will be located at:
   ```text
   out/build/x64-Release/cs2-dumper.exe
   ```

---

### Option 2: Command Line (CLI / PowerShell)

You can build directly using CMake and MSBuild from PowerShell or Developer Command Prompt:

```powershell
# 1. Generate x64 Visual Studio build files
cmake -B build -A x64

# 2. Compile Release configuration
cmake --build build --config Release
```

The output executable will be placed in:
```text
build/Release/cs2-dumper.exe
```

---

## 🚀 Usage

1. Launch **Counter-Strike 2** and wait until you reach the main menu.
2. Run the compiled `cs2-dumper.exe` (running as Administrator is recommended for full memory access):
   ```powershell
   .\cs2-dumper.exe
   ```
3. Once the analysis is complete, an **`output/`** folder will be created in the current working directory containing all dumped files.

### Command Line Options

```text
Usage: cs2-dumper.exe [options]
Options:
  -f, --file-types <types>   Comma-separated output types (default: cs,hpp,json,rs,zig)
  -i, --indent-size <n>      Spaces per indent level (default: 4)
  -o, --output <dir>         Output directory (default: output)
  -p, --process-name <name>  Target process name (default: cs2.exe)
  -v, --verbose              Increase verbosity (can repeat, e.g. -v or -vv)
  --no-log-file              Do not create cs2-dumper.log
  -h, --help                 Show help message
```

**Example: Dumping only C++ and C# files to a custom directory:**
```powershell
.\cs2-dumper.exe -f hpp,cs -o "C:\MyCS2Dump"
```

---

## 📄 License

This project is licensed under the MIT License - see the original repository [a2x/cs2-dumper](https://github.com/a2x/cs2-dumper) for details.
