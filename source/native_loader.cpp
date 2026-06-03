#include "native_loader.hpp"
#include <winternl.h>
#include <array>
#include <omath/utility/pe_pattern_scan.hpp>

namespace yail::detail
{
    namespace
    {
        struct LdrDataTableEntryFull final
        {
            LIST_ENTRY in_load_order_links;
            LIST_ENTRY in_memory_order_links;
            LIST_ENTRY in_initialization_order_links;
            PVOID dll_base;
            PVOID entry_point;
            ULONG size_of_image;
            [[maybe_unused]] UNICODE_STRING full_dll_name;
            [[maybe_unused]] UNICODE_STRING base_dll_name;
            [[maybe_unused]] ULONG flags;
            [[maybe_unused]] USHORT obsolete_load_count;
            [[maybe_unused]] USHORT tls_index;
            LIST_ENTRY hash_links;
            [[maybe_unused]] ULONG time_date_stamp;
        };

#ifdef _WIN64
        using LdrpHandleTlsDataFn = NTSTATUS(NTAPI*)(LdrDataTableEntryFull*);
        using RtlInsertInvertedFunctionTableFn = void(NTAPI*)(PVOID image_base, ULONG size_of_image);
#else
        // Modern x86 ntdll uses __fastcall for these internal functions despite the
        // legacy `_Name@N` symbol decoration - args come in ECX/EDX, not on the stack.
        using LdrpHandleTlsDataFn = NTSTATUS(__fastcall*)(LdrDataTableEntryFull*);
        using RtlInsertInvertedFunctionTableFn = void(__fastcall*)(PVOID image_base, ULONG size_of_image);
#endif

        template <typename T>
        [[nodiscard]]
        void* erase_function_pointer(T function)
        {
            return reinterpret_cast<void*>(function);
        }

        // Disabled reference implementation used to regenerate source/shellcode.hpp.
        // Temporarily change this to #if 1, rebuild both architectures, run
        // tools/generate_shellcode.py, then restore #if 0.
#if 0
        // Disable all CRT instrumentation so the function is fully self-contained.
        // No __security_check_cookie, no __RTC_*, no __chkstk references.
#ifdef _MSC_VER
#pragma runtime_checks("", off)
#pragma optimize("ts", on)
#pragma strict_gs_check(push, off)
#endif
        // A dedicated PE section keeps sizing independent from consumer linker ordering.
        __declspec(safebuffers) __declspec(noinline) __declspec(code_seg(".yail$a")) DWORD WINAPI
        remote_shellcode(const RemoteLoaderData* data)
        {
            auto* base = data->image_base;
            auto* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(base + data->nt_headers_rva);

            // --- Resolve imports ---
            // ReSharper disable once CppUseStructuredBinding
            // ReSharper disable once CppTooWideScopeInitStatement
            const auto& import_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            if (import_dir.Size)
            {
                const auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + import_dir.VirtualAddress);
                while (desc->Characteristics)
                {
                    const HMODULE module_handle = data->fn_load_library_a(reinterpret_cast<LPCSTR>(base + desc->Name));
                    if (!module_handle)
                        return 1;

                    const auto* original_trunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + desc->OriginalFirstThunk);
                    auto* first_trunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + desc->FirstThunk);

                    while (original_trunk->u1.AddressOfData)
                    {
                        FARPROC fn;
                        if (original_trunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                            fn = data->fn_get_proc_address(module_handle,
                                                           reinterpret_cast<LPCSTR>(original_trunk->u1.Ordinal
                                                                                     & 0xFFFF));
                        else
                        {
                            const auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                                    base + original_trunk->u1.AddressOfData);
                            fn = data->fn_get_proc_address(module_handle, ibn->Name);
                        }
                        if (!fn)
                            return 2;
                        first_trunk->u1.Function = reinterpret_cast<std::uintptr_t>(fn);
                        original_trunk++;
                        first_trunk++;
                    }
                    desc++;
                }
            }

            // --- Resolve delay imports ---
            // ReSharper disable once CppUseStructuredBinding
            // ReSharper disable once CppTooWideScopeInitStatement
            const auto& delay_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
            if (delay_dir.Size)
            {
                auto* delay_desc = reinterpret_cast<IMAGE_DELAYLOAD_DESCRIPTOR*>(base + delay_dir.VirtualAddress);
                while (delay_desc->DllNameRVA)
                {
                    const HMODULE module_handle = data->fn_load_library_a(
                            reinterpret_cast<LPCSTR>(base + delay_desc->DllNameRVA));
                    if (!module_handle)
                        return 3;

                    const auto* name_thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + delay_desc->ImportNameTableRVA);
                    auto* addr_thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
                            base + delay_desc->ImportAddressTableRVA);

                    while (name_thunk->u1.AddressOfData)
                    {
                        FARPROC fn;
                        if (name_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                            fn = data->fn_get_proc_address(module_handle,
                                                           reinterpret_cast<LPCSTR>(name_thunk->u1.Ordinal & 0xFFFF));
                        else
                        {
                            const auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                                    base + name_thunk->u1.AddressOfData);
                            fn = data->fn_get_proc_address(module_handle, ibn->Name);
                        }
                        if (!fn)
                            return 4;
                        addr_thunk->u1.Function = reinterpret_cast<std::uintptr_t>(fn);
                        name_thunk++;
                        addr_thunk++;
                    }

                    delay_desc->ModuleHandleRVA =
                            static_cast<DWORD>(reinterpret_cast<std::uint8_t*>(module_handle) - base);
                    delay_desc++;
                }
            }

            // --- Handle static TLS ---
            // ReSharper disable once CppUseStructuredBinding
            const auto& tls_directory = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
            if (tls_directory.Size && data->fn_ldrp_handle_tls_data)
            {
                // Build fake LDR_DATA_TABLE_ENTRY on the stack - zero without memset.
                LdrDataTableEntryFull entry;
                auto* raw = reinterpret_cast<volatile uint8_t*>(&entry);
                for (size_t i = 0; i < sizeof(entry); i++)
                    raw[i] = 0;

                entry.dll_base = base;
                entry.size_of_image = nt_headers->OptionalHeader.SizeOfImage;
                entry.entry_point = base + nt_headers->OptionalHeader.AddressOfEntryPoint;

                entry.in_load_order_links.Flink = &entry.in_load_order_links;
                entry.in_load_order_links.Blink = &entry.in_load_order_links;
                entry.in_memory_order_links.Flink = &entry.in_memory_order_links;
                entry.in_memory_order_links.Blink = &entry.in_memory_order_links;
                entry.in_initialization_order_links.Flink = &entry.in_initialization_order_links;
                entry.in_initialization_order_links.Blink = &entry.in_initialization_order_links;
                entry.hash_links.Flink = &entry.hash_links;
                entry.hash_links.Blink = &entry.hash_links;

#ifdef _WIN64
                (reinterpret_cast<NTSTATUS(NTAPI*)(LdrDataTableEntryFull*)>(data->fn_ldrp_handle_tls_data)(&entry));
#else
                (reinterpret_cast<NTSTATUS(__fastcall*)(LdrDataTableEntryFull*)>(
                        data->fn_ldrp_handle_tls_data)(&entry));
#endif
            }

            // --- TLS callbacks ---
            if (tls_directory.Size)
            {
                const auto* tls = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(base + tls_directory.VirtualAddress);
                // ReSharper disable once CppTooWideScopeInitStatement
                const auto* call_backs_addr = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls->AddressOfCallBacks);
                for (; call_backs_addr && *call_backs_addr; call_backs_addr++)
                    (*call_backs_addr)(base, DLL_PROCESS_ATTACH, nullptr);
            }

#ifdef _WIN64
            // --- Exception handling (x64 unwind tables) ---
            // ReSharper disable once CppTooWideScopeInitStatement
            const auto& [VirtualAddress, Size] =
                    nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
            if (Size)
            {
                if (data->fn_rtl_insert_inverted_function_table)
                {
                    reinterpret_cast<void(NTAPI*)(PVOID, ULONG)>(data->fn_rtl_insert_inverted_function_table)(
                            base, nt_headers->OptionalHeader.SizeOfImage);
                }
                else
                {
                    data->fn_rtl_add_function_table(
                            reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(base + VirtualAddress),
                            Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), reinterpret_cast<std::uintptr_t>(base));
                }
            }
#else
            // x86: register module in the inverted function table so RtlIsValidHandler accepts
            // SEH/C++ handlers from this image. Without this, exception dispatch rejects every
            // handler in a manually-mapped DLL and unwinds straight to process termination.
            // Modern x86 ntdll passes args in ECX/EDX (__fastcall), not on the stack.
            if (data->fn_rtl_insert_inverted_function_table)
            {
                reinterpret_cast<void(__fastcall*)(PVOID, ULONG)>(data->fn_rtl_insert_inverted_function_table)(
                        base, nt_headers->OptionalHeader.SizeOfImage);
            }
#endif

            // --- Apply per-section memory protections ---
            {
                auto* section = reinterpret_cast<IMAGE_SECTION_HEADER*>(
                        reinterpret_cast<std::uint8_t*>(&nt_headers->OptionalHeader)
                        + nt_headers->FileHeader.SizeOfOptionalHeader);

                for (std::uint16_t i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section++)
                {
                    if (!section->Misc.VirtualSize)
                        continue;

                    DWORD protect = PAGE_NOACCESS;
                    const DWORD sc = section->Characteristics;

                    if (sc & IMAGE_SCN_MEM_EXECUTE)
                    {
                        if (sc & IMAGE_SCN_MEM_WRITE)
                            protect = PAGE_EXECUTE_READWRITE;
                        else if (sc & IMAGE_SCN_MEM_READ)
                            protect = PAGE_EXECUTE_READ;
                        else
                            protect = PAGE_EXECUTE;
                    }
                    else if (sc & IMAGE_SCN_MEM_WRITE)
                    {
                        if (sc & IMAGE_SCN_MEM_READ)
                            protect = PAGE_READWRITE;
                        else
                            protect = PAGE_WRITECOPY;
                    }
                    else if (sc & IMAGE_SCN_MEM_READ)
                    {
                        protect = PAGE_READONLY;
                    }

                    if (sc & IMAGE_SCN_MEM_NOT_CACHED)
                        protect |= PAGE_NOCACHE;

                    DWORD old_protect;
                    data->fn_virtual_protect(base + section->VirtualAddress, section->Misc.VirtualSize, protect,
                                             &old_protect);
                }
            }

            // --- Call entry point ---
            if (nt_headers->OptionalHeader.AddressOfEntryPoint)
            {
                if (nt_headers->FileHeader.Characteristics & IMAGE_FILE_DLL)
                {
                    const auto entry_point = reinterpret_cast<BOOL(WINAPI*)(HMODULE, DWORD, LPVOID)>(
                            base + nt_headers->OptionalHeader.AddressOfEntryPoint);
                    entry_point(reinterpret_cast<HMODULE>(base), DLL_PROCESS_ATTACH, nullptr);
                }
                else
                {
                    // EXE entry (mainCRTStartup / WinMainCRTStartup) - __cdecl, no args.
                    // When the entry returns the CRT calls exit() -> ExitProcess, terminating
                    // the host process. GetModuleHandle(NULL) still resolves to the host EXE.
                    const auto entry_point = reinterpret_cast<int(__cdecl*)()>(
                            base + nt_headers->OptionalHeader.AddressOfEntryPoint);
                    entry_point();
                }
            }

            return 0;
        }
        __declspec(noinline) __declspec(code_seg(".yail$z")) std::uint64_t remote_shellcode_end()
        {
            return 0x5941494C5348454Cull;
        }

#ifdef _MSC_VER
#pragma strict_gs_check(pop)
#pragma runtime_checks("", restore)
#pragma optimize("", on)
#endif
#endif
    } // namespace

    std::expected<void*, std::string> find_ldrp_handle_tls_data()
    {
        constexpr std::array signatures = {
#ifdef _WIN64
            "4C 8B DC 49 89 5B ? 49 89 73 ? 57 41 54 41 55 41 56 41 57 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 84 24 ? ? ? ? 48 8B F9", // Windows 11 24H2
            "48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 41 55 41 56 41 57 48 81 EC",
#else
            // x86 - patterns may need updating per Windows build
            "8B FF 55 8B EC 83 EC ? 53 56 57 8B 7D ? 89 4D",
            "8B FF 55 8B EC 51 51 53 56 57 8B F1 89 75",
            "6A ? 68 ? ? ? ? E8 ? ? ? ? 8B C1 89 45 ? 89 45",
#endif
        };

        const auto* ntdll = GetModuleHandleA("ntdll.dll");
        for (const auto* sig : signatures)
        {
            if (const auto result = omath::PePatternScanner::scan_for_pattern_in_loaded_module(ntdll, sig))
                return erase_function_pointer(reinterpret_cast<LdrpHandleTlsDataFn>(result.value()));
        }

        return std::unexpected("Failed to find LdrpHandleTlsData");
    }

    std::expected<void*, std::string> find_rtl_insert_inverted_function_table()
    {
        constexpr std::array signatures = {
#ifdef _WIN64
            "48 8B C4 48 89 58 ? 48 89 68 ? 48 89 70 ? 57 48 83 EC ? 83 60", // Windows 11 24H2
            "4C 8B DC 49 89 5B ? 49 89 73 ? 57 48 83 EC ? 8B FA"
#else
            // x86 - patterns may need updating per Windows build.
            // Win11 24H2 x86 ntdll: __fastcall convention (ECX/EDX), see typedef above.
            "8B FF 55 8B EC 83 EC ? 53 56 57 8D 45 ? 8B FA 50 8D 55", // Win11 24H2
            "8B FF 55 8B EC 51 51 53 56 57 8B 7D ? 8D 45",
            "8B FF 55 8B EC 53 56 57 8B 7D ? 8D 45",
#endif
        };

        const auto* ntdll = GetModuleHandleA("ntdll.dll");
        for (const auto* sig : signatures)
        {
            if (const auto result = omath::PePatternScanner::scan_for_pattern_in_loaded_module(ntdll, sig))
                return erase_function_pointer(reinterpret_cast<RtlInsertInvertedFunctionTableFn>(result.value()));
        }

        return std::unexpected("Failed to find RtlInsertInvertedFunctionTable");
    }
}
