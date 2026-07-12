# syail

Stealth injection framework for Windows (x64/x86). Manual-map PE loader in C++23.

Fork of [orange-cpp/yail](https://github.com/orange-cpp/yail) ("Yet Another Injection Library"). Same public mapping API, with a different process-touch path.

![banner](.github/banner.png)

## Diff vs upstream yail

Kept from [yail](https://github.com/orange-cpp/yail):

- Manual map of DLL/EXE (no `LoadLibrary` module list entry)
- TLS, imports (static + delay), SEH/unwind registration
- Inject by PID or process name, from file or raw bytes
- `std::expected` API under `yail::`

Added / changed in **syail**:

- **HWBP + VEH syscall engine** - `NtOpenProcess`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtProtectVirtualMemory`, `NtFreeVirtualMemory`, `NtCreateThreadEx` go through hardware breakpoints and a VEH handler instead of plain Win32/`ntdll` imports where wired
- **Indirect syscalls** - SSN resolution with neighbor-stub walk when the primary stub looks hooked
- **Stack spoofing** - return gadgets from runtime DLLs (`add rsp, …; ret` style) on the syscall path
- **Header-only pattern scanner** - replaces heavier helper deps (no `omath`)

If you only need a clean manual-map loader, use upstream. If you want the stealth syscall path, use this fork.

## Features (shared with yail)

- Manual PE mapping (no `LoadLibrary` traces)
  - **x64**: unwind table registration via `RtlInsertInvertedFunctionTable` (`RtlAddFunctionTable` fallback)
  - **x86**: SEH validation via `RtlInsertInvertedFunctionTable` (Win11 24H2 `__fastcall` stubs)
- Maps **DLLs** and **EXEs** (auto via `IMAGE_FILE_DLL`)
  - DLLs: `DllMain(HMODULE, DLL_PROCESS_ATTACH, nullptr)`
  - EXEs: `mainCRTStartup` / `WinMain` entry shapes
- Static TLS via signature-scanned `LdrpHandleTlsData`
- TLS callbacks (`.CRT$XLB`)
- Static and delay-loaded imports
- Exception handling (SEH/VEH/C++) on mapped images
- Per-section protections (RX, RW, RO, RWX)
- Inject by process ID or process name
- Load from file path or raw bytes
- `std::expected<uintptr_t, std::string>` (no thrown errors on the public API)

## Requirements

- Windows 10 / 11 (ntdll signatures verified on Windows 11 24H2; older builds may need pattern updates)
- C++23 compiler (MSVC recommended)
- CMake 3.28+
- vcpkg

## Building

x64:

```bash
cmake --preset windows-debug-vcpkg
cmake --build cmake-build/build/windows-debug-vcpkg
```

x86:

```bash
cmake --preset windows-debug-vcpkg-x86
cmake --build cmake-build/build/windows-debug-vcpkg-x86
```

Native injection needs matching bitness. An x64 build can also inject x86 PEs into WOW64 targets via the embedded x86 loader.

Examples build by default. Disable with `-DYAIL_BUILD_EXAMPLES=OFF`.

Do not commit `build/` or `cmake-build/` (see `.gitignore`).

## Usage

### Inject a DLL by process name

```cpp
#include <yail/yail.hpp>

auto result = yail::manual_map_injection_from_file("my.dll", "target.exe");

if (!result)
    std::println("Failed: {}", result.error());
else
    std::println("Loaded at 0x{:x}", result.value());
```

### Inject by PID

```cpp
auto result = yail::manual_map_injection_from_file("my.dll", GetCurrentProcessId());
```

### Inject an EXE

Same API; entry shape is detected from the PE:

```cpp
auto result = yail::manual_map_injection_from_file("my.exe", GetCurrentProcessId());
```

EXE caveats:

- If the EXE entry returns, CRT may call `exit()` / `ExitProcess` and kill the **host**. Keep the host alive with `ExitThread(0)` from the entry (see `test_exe`).
- `GetModuleHandle(nullptr)` inside the mapped EXE is the **host** base. `WinMain`'s `hInstance` is correct (`__ImageBase`).

### Inject from raw bytes

```cpp
std::vector<uint8_t> bytes = /* ... */;
auto result = yail::manual_map_injection_from_raw(bytes, "target.exe");
```

## API

```cpp
namespace yail
{
    std::expected<uintptr_t, std::string>
    manual_map_injection_from_file(std::string_view pe_path, std::uintptr_t process_id);

    std::expected<uintptr_t, std::string>
    manual_map_injection_from_file(std::string_view pe_path, std::string_view process_name);

    std::expected<uintptr_t, std::string>
    manual_map_injection_from_raw(const std::span<std::uint8_t>& raw_pe, std::uintptr_t process_id);

    std::expected<uintptr_t, std::string>
    manual_map_injection_from_raw(const std::span<std::uint8_t>& raw_pe, std::string_view process_name);
}
```

On success: base address in the target. That address is **not** a loader `HMODULE` - do not pass it to `FreeLibrary`.

## CMake

```cmake
find_package(yail CONFIG REQUIRED)
target_link_libraries(my_target PRIVATE yail::yail)
```

## Examples

| Target | Purpose |
|--------|---------|
| `loader` | Map a PE into the current process: `loader.exe <path>` |
| `remote_loader` | Map into another process: `remote_loader.exe <dll> <process.exe>` |
| `test_dll` | Self-test DLL (TLS, SEH, exceptions, delay imports, …) |
| `test_exe` | Console EXE via `main()` |
| `test_winexe` | GUI EXE via `WinMain` |

```bash
loader.exe test_dll.dll
loader.exe test_exe.exe
loader.exe test_winexe.exe
```

## Signature notes

Non-exported ntdll helpers are found by byte patterns:

- `LdrpHandleTlsData` - static TLS registration
- `RtlInsertInvertedFunctionTable` - exception/SEH visibility

Verified on **Windows 11 24H2**. Older builds: dump the function in WinDbg, take ~16 unique bytes, update patterns in `source/native_loader.cpp` / `source/wow64.cpp`.

Shellcode generator: `tools/generate_shellcode.cpp`. After edits, rebuild and refresh `source/shellcode.cpp`.

## License

[Zlib](LICENSE) (same as upstream yail)

Upstream: [orange-cpp/yail](https://github.com/orange-cpp/yail). See [CREDITS.md](CREDITS.md).
