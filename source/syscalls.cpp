#include <yail/detail/syscalls.hpp>
#include <yail/detail/pattern_scan.hpp>
#include <winternl.h>
#include <vector>
#include <string_view>
#include <algorithm>
#include <cwctype>
#include <cstddef>

#pragma optimize("", off) // Disable optimizations to ensure precise stack frame control

namespace yail::detail::syscalls
{
    namespace
    {
        PVOID g_veh_handle = nullptr;
        HANDLE g_thread_handle = nullptr;
        std::uintptr_t g_ntdll_base = 0;
        std::uintptr_t g_target_fn_address = 0;
        std::uintptr_t g_ret_gadget = 0;

        constexpr std::ptrdiff_t UP = -32;
        constexpr std::ptrdiff_t DOWN = 32;
        constexpr std::size_t STACK_ARGS_LENGTH = 8;
        constexpr std::size_t STACK_ARGS_RSP_OFFSET = 0x28;

        // Custom PEB structure definitions for manual parsing
        struct UNICODE_STRING_LDR {
            USHORT Length;
            USHORT MaximumLength;
            PWSTR  Buffer;
        };

        struct LDR_DATA_TABLE_ENTRY_LDR {
            LIST_ENTRY InLoadOrderLinks;
            LIST_ENTRY InMemoryOrderLinks;
            LIST_ENTRY InInitializationOrderLinks;
            PVOID DllBase;
            PVOID EntryPoint;
            ULONG SizeOfImage;
            UNICODE_STRING_LDR FullDllName;
            UNICODE_STRING_LDR BaseDllName;
        };

        struct PEB_LDR_DATA_LDR {
            ULONG Length;
            BOOLEAN Initialized;
            HANDLE SsHandle;
            LIST_ENTRY InLoadOrderModuleList;
            LIST_ENTRY InMemoryOrderModuleList;
            LIST_ENTRY InInitializationOrderModuleList;
        };

        struct PEB_LDR {
            BYTE Reserved1[2];
            BYTE BeingDebugged;
            BYTE Reserved2[21];
            PEB_LDR_DATA_LDR* Ldr;
        };

        // Case-insensitive wchar compare helper
        bool wstr_equal_case_insensitive(std::wstring_view s1, std::wstring_view s2)
        {
            if (s1.length() != s2.length())
                return false;
            return std::equal(s1.begin(), s1.end(), s2.begin(), [](wchar_t a, wchar_t b) {
                return std::towlower(a) == std::towlower(b);
            });
        }

        // Get module base address via PEB (stealthy resolution)
        std::uintptr_t get_module_base_peb(std::wstring_view module_name)
        {
#ifdef _WIN64
            auto* peb = reinterpret_cast<PEB_LDR*>(__readgsqword(0x60));
#else
            auto* peb = reinterpret_cast<PEB_LDR*>(__readfsdword(0x30));
#endif
            if (!peb || !peb->Ldr)
                return 0;

            auto* list_head = &peb->Ldr->InMemoryOrderModuleList;
            for (auto* it = list_head->Flink; it != list_head; it = it->Flink)
            {
                auto* entry = reinterpret_cast<LDR_DATA_TABLE_ENTRY_LDR*>(
                    reinterpret_cast<std::uint8_t*>(it) - offsetof(LDR_DATA_TABLE_ENTRY_LDR, InMemoryOrderLinks)
                );

                if (entry->BaseDllName.Buffer)
                {
                    std::wstring_view current_name(entry->BaseDllName.Buffer, entry->BaseDllName.Length / sizeof(wchar_t));
                    if (wstr_equal_case_insensitive(current_name, module_name))
                    {
                        return reinterpret_cast<std::uintptr_t>(entry->DllBase);
                    }
                }
            }
            return 0;
        }

        // Get function export address via PEB (stealthy resolution)
        std::uintptr_t get_symbol_address_peb(std::uintptr_t module_base, std::string_view function_name)
        {
            if (!module_base)
                return 0;

            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(module_base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                return 0;

            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(module_base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE)
                return 0;

            auto export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            if (!export_rva)
                return 0;

            auto* exports = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(module_base + export_rva);
            auto* names = reinterpret_cast<DWORD*>(module_base + exports->AddressOfNames);
            auto* ordinals = reinterpret_cast<WORD*>(module_base + exports->AddressOfNameOrdinals);
            auto* functions = reinterpret_cast<DWORD*>(module_base + exports->AddressOfFunctions);

            for (DWORD i = 0; i < exports->NumberOfNames; ++i)
            {
                const char* current_name = reinterpret_cast<const char*>(module_base + names[i]);
                if (function_name == current_name)
                {
                    return module_base + functions[ordinals[i]];
                }
            }
            return 0;
        }

        // Resolve system call number (SSN) dynamically, including HalosGate neighbor checks
        WORD find_syscall_number(std::uintptr_t function_address)
        {
            const auto* p = reinterpret_cast<const std::uint8_t*>(function_address);
            
            // Standard stub starts with:
            // mov r10, rcx (4C 8B D1)
            // mov eax, SSN (B8 XX XX XX XX)
            if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8)
            {
                return *reinterpret_cast<const WORD*>(p + 4);
            }

            // Hooked! Search neighboring stubs up/down (HalosGate)
            for (WORD idx = 1; idx <= 500; idx++)
            {
                // Check neighbor down
                const auto* p_down = reinterpret_cast<const std::uint8_t*>(function_address + idx * DOWN);
                if (p_down[0] == 0x4C && p_down[1] == 0x8B && p_down[2] == 0xD1 && p_down[3] == 0xB8)
                {
                    WORD ssn = *reinterpret_cast<const WORD*>(p_down + 4);
                    return ssn - idx;
                }

                // Check neighbor up
                const auto* p_up = reinterpret_cast<const std::uint8_t*>(function_address + idx * UP);
                if (p_up[0] == 0x4C && p_up[1] == 0x8B && p_up[2] == 0xD1 && p_up[3] == 0xB8)
                {
                    WORD ssn = *reinterpret_cast<const WORD*>(p_up + 4);
                    return ssn + idx;
                }
            }
            return 0;
        }

        // Locate "syscall; ret" (0F 05 C3) within ntdll function stub
        std::uintptr_t find_syscall_return_address(std::uintptr_t function_address)
        {
            const auto* p = reinterpret_cast<const std::uint8_t*>(function_address);
            for (WORD idx = 0; idx < 32; idx++)
            {
                if (p[idx] == 0x0F && p[idx + 1] == 0x05)
                {
                    return function_address + idx;
                }
            }
            return 0;
        }

        // Set thread context hardware breakpoint (Dr0) targeting prepare_syscall
        bool set_hwbp()
        {
            CONTEXT ctx = { 0 };
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

            if (!GetThreadContext(g_thread_handle, &ctx))
                return false;

            ctx.Dr0 = reinterpret_cast<std::uintptr_t>(&prepare_syscall);
            ctx.Dr7 |= (1 << 0);    // Enable local breakpoint 0
            ctx.Dr7 &= ~(1 << 16);  // Clear condition bits for execution break
            ctx.Dr7 &= ~(1 << 17);
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

            return SetThreadContext(g_thread_handle, &ctx) != 0;
        }

        // Clear thread context hardware breakpoint
        void clear_hwbp()
        {
            CONTEXT ctx = { 0 };
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

            if (GetThreadContext(g_thread_handle, &ctx))
            {
                ctx.Dr0 = 0;
                ctx.Dr7 &= ~(1 << 0); // Disable local breakpoint 0
                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                SetThreadContext(g_thread_handle, &ctx);
            }
        }

        // Find the "add rsp, 0x68; ret" gadget in kernel32 or kernelbase
        bool find_ret_gadget()
        {
            auto k32 = get_module_base_peb(L"kernel32.dll");
            if (auto match = scan_in_module(reinterpret_cast<void*>(k32), "48 83 C4 68 C3"))
            {
                g_ret_gadget = reinterpret_cast<std::uintptr_t>(match.value());
                return true;
            }

            auto kbase = get_module_base_peb(L"kernelbase.dll");
            if (auto match = scan_in_module(reinterpret_cast<void*>(kbase), "48 83 C4 68 C3"))
            {
                g_ret_gadget = reinterpret_cast<std::uintptr_t>(match.value());
                return true;
            }

            return false;
        }

        // VEH handler for HWBP intercepts
        LONG NTAPI HWSyscallExceptionHandler(EXCEPTION_POINTERS* exception_info)
        {
            if (exception_info->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
            {
                auto* context = exception_info->ContextRecord;

                // Step 1: Hit prepare_syscall -> resolve target ntdll function address
                if (context->Rip == reinterpret_cast<DWORD64>(&prepare_syscall))
                {
                    const char* name = reinterpret_cast<const char*>(context->Rcx);
                    g_target_fn_address = get_symbol_address_peb(g_ntdll_base, name);

                    if (g_target_fn_address)
                    {
                        context->Dr0 = g_target_fn_address;
                    }
                    else
                    {
                        context->Dr0 = reinterpret_cast<DWORD64>(&prepare_syscall);
                    }
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
                // Step 2: Hit target ntdll function entry -> spoof stack, resolve SSN, perform indirect syscall
                else if (context->Rip == g_target_fn_address)
                {
                    WORD ssn = find_syscall_number(g_target_fn_address);
                    std::uintptr_t syscall_ret = find_syscall_return_address(g_target_fn_address);

                    // Fallback to direct execution if resolver failed
                    if (ssn == 0 || syscall_ret == 0)
                    {
                        context->Dr0 = reinterpret_cast<DWORD64>(&prepare_syscall);
                        return EXCEPTION_CONTINUE_EXECUTION;
                    }

                    // Stack Spoofing:
                    // Decrement RSP by 0x70 (gadget pops 0x68, plus 0x8 for return address)
                    context->Rsp -= 0x70;
                    *reinterpret_cast<std::uintptr_t*>(context->Rsp) = g_ret_gadget;

                    // Copy stack parameters (arguments 5 and onwards) from old stack
                    // Old stack starts at new RSP + 0x70
                    for (std::size_t i = 0; i < STACK_ARGS_LENGTH; ++i)
                    {
                        const std::size_t offset = i * sizeof(std::uintptr_t) + STACK_ARGS_RSP_OFFSET;
                        *reinterpret_cast<std::uintptr_t*>(context->Rsp + offset) = 
                            *reinterpret_cast<std::uintptr_t*>(context->Rsp + offset + 0x70);
                    }

                    // Set registers for dynamic indirect syscall execution
                    context->R10 = context->Rcx;
                    context->Rax = ssn;
                    context->Rip = syscall_ret;

                    // Reset breakpoint back to prepare_syscall for future intercepts
                    context->Dr0 = reinterpret_cast<DWORD64>(&prepare_syscall);

                    return EXCEPTION_CONTINUE_EXECUTION;
                }

                // If it's single step but not our registered breakpoints, let search handle it
                return EXCEPTION_CONTINUE_SEARCH;
            }
            return EXCEPTION_CONTINUE_SEARCH;
        }
    } // namespace

    // Prevent compiler inlining & optimizing prepare_syscall function
    __declspec(noinline) std::uintptr_t prepare_syscall(const char* name)
    {
        (void)name;
        return g_target_fn_address;
    }

    bool init()
    {
#ifndef _WIN64
        // Syscall exception hook logic is only structured for x64
        return false;
#else
        if (g_veh_handle)
            return true; // Already initialized

        // Duplicate the pseudo-handle to get a real thread handle
        HANDLE pseudo_handle = GetCurrentThread();
        if (!DuplicateHandle(
            GetCurrentProcess(),
            pseudo_handle,
            GetCurrentProcess(),
            &g_thread_handle,
            0,
            FALSE,
            DUPLICATE_SAME_ACCESS))
        {
            g_thread_handle = pseudo_handle;
        }

        g_ntdll_base = get_module_base_peb(L"ntdll.dll");
        if (!g_ntdll_base)
            return false;

        if (!find_ret_gadget())
            return false;

        g_veh_handle = AddVectoredExceptionHandler(1, &HWSyscallExceptionHandler);
        if (!g_veh_handle)
            return false;

        if (!set_hwbp())
        {
            RemoveVectoredExceptionHandler(g_veh_handle);
            g_veh_handle = nullptr;
            if (g_thread_handle != pseudo_handle)
            {
                CloseHandle(g_thread_handle);
            }
            g_thread_handle = nullptr;
            return false;
        }

        return true;
#endif
    }

    void deinit()
    {
        if (g_veh_handle)
        {
            clear_hwbp();
            RemoveVectoredExceptionHandler(g_veh_handle);
            g_veh_handle = nullptr;
            
            HANDLE pseudo = GetCurrentThread();
            if (g_thread_handle && g_thread_handle != pseudo)
            {
                CloseHandle(g_thread_handle);
            }
            g_thread_handle = nullptr;
        }
    }
} // namespace yail::detail::syscalls
