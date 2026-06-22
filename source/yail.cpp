//
// Created by orange on 3/26/2026.
// Optimized by LucPrusPPi 12/07/2026.
//
#include <Windows.h>
#include <winternl.h>
#include <algorithm>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <format>
#include <fstream>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <yail/detail/native_loader.hpp>
#include <yail/detail/pe.hpp>
#include <yail/detail/process.hpp>
#include <yail/detail/shellcode.hpp>
#include <yail/detail/wow64.hpp>
#include <yail/detail/syscalls.hpp>
#include <yail/yail.hpp>

namespace yail
{
    namespace
    {
        // Helper struct to automatically manage initialization and clean up of syscalls
        struct SyscallsGuard
        {
            bool active;
            SyscallsGuard()
            {
                active = detail::syscalls::init();
            }
            ~SyscallsGuard()
            {
                if (active)
                {
                    detail::syscalls::deinit();
                }
            }
        };

        // Stealthy wrappers with fallback
        HANDLE sys_open_process(DWORD process_id, bool use_syscalls)
        {
            if (use_syscalls)
            {
                HANDLE handle = nullptr;
                OBJECT_ATTRIBUTES obj_attr;
                InitializeObjectAttributes(&obj_attr, nullptr, 0, nullptr, nullptr);
                CLIENT_ID client_id;
                client_id.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<DWORD_PTR>(process_id));
                client_id.UniqueThread = nullptr;

                NTSTATUS status = detail::syscalls::nt_open_process(
                    &handle,
                    PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION,
                    &obj_attr,
                    &client_id
                );
                if (NT_SUCCESS(status))
                    return handle;
            }
            return OpenProcess(
                PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION,
                FALSE,
                process_id
            );
        }

        LPVOID sys_virtual_alloc(HANDLE process_handle, LPVOID address, SIZE_T size, DWORD allocation_type, DWORD protect, bool use_syscalls)
        {
            if (use_syscalls)
            {
                PVOID base = address;
                SIZE_T region_size = size;
                NTSTATUS status = detail::syscalls::nt_allocate_virtual_memory(
                    process_handle,
                    &base,
                    0,
                    &region_size,
                    allocation_type,
                    protect
                );
                if (NT_SUCCESS(status))
                    return base;
            }
            return VirtualAllocEx(process_handle, address, size, allocation_type, protect);
        }

        BOOL sys_write_process_memory(HANDLE process_handle, LPVOID base_address, LPCVOID buffer, SIZE_T size, SIZE_T* number_of_bytes_written, bool use_syscalls)
        {
            if (use_syscalls)
            {
                SIZE_T written = 0;
                NTSTATUS status = detail::syscalls::nt_write_virtual_memory(
                    process_handle,
                    base_address,
                    const_cast<PVOID>(buffer),
                    size,
                    &written
                );
                if (number_of_bytes_written)
                    *number_of_bytes_written = written;
                return NT_SUCCESS(status);
            }
            return WriteProcessMemory(process_handle, base_address, buffer, size, number_of_bytes_written);
        }

        BOOL sys_virtual_free(HANDLE process_handle, LPVOID address, SIZE_T size, DWORD free_type, bool use_syscalls)
        {
            if (use_syscalls)
            {
                PVOID base = address;
                SIZE_T region_size = size;
                NTSTATUS status = detail::syscalls::nt_free_virtual_memory(
                    process_handle,
                    &base,
                    &region_size,
                    free_type
                );
                return NT_SUCCESS(status);
            }
            return VirtualFreeEx(process_handle, address, size, free_type);
        }

        HANDLE sys_create_remote_thread(HANDLE process_handle, LPTHREAD_START_ROUTINE start_routine, LPVOID parameter, bool use_syscalls)
        {
            if (use_syscalls)
            {
                HANDLE thread_handle = nullptr;
                OBJECT_ATTRIBUTES obj_attr;
                InitializeObjectAttributes(&obj_attr, nullptr, 0, nullptr, nullptr);

                NTSTATUS status = detail::syscalls::nt_create_thread_ex(
                    &thread_handle,
                    THREAD_ALL_ACCESS,
                    &obj_attr,
                    process_handle,
                    reinterpret_cast<PVOID>(start_routine),
                    parameter,
                    0,
                    0,
                    0,
                    0,
                    nullptr
                );
                if (NT_SUCCESS(status))
                    return thread_handle;
            }
            return CreateRemoteThread(process_handle, nullptr, 0, start_routine, parameter, 0, nullptr);
        }
    } // namespace

    std::expected<std::uintptr_t, std::string>
    manual_map_injection_from_raw(const std::span<const std::uint8_t>& raw_dll, const std::uintptr_t process_id)
    {
        const auto pe_machine = detail::get_pe_machine(raw_dll);
        if (!pe_machine)
            return std::unexpected("File is not in a Portable Executable format");

#ifdef _WIN64
        if (*pe_machine == IMAGE_FILE_MACHINE_I386)
            return detail::manual_map_injection_into_wow64_process(raw_dll, process_id);
        constexpr WORD expected_machine = IMAGE_FILE_MACHINE_AMD64;
#else
        constexpr WORD expected_machine = IMAGE_FILE_MACHINE_I386;
#endif

        if (*pe_machine != expected_machine)
            return std::unexpected(std::format("Unsupported PE machine 0x{:04x} for this injector", *pe_machine));

        if (const auto architecture = detail::validate_target_machine(process_id, expected_machine); !architecture)
            return std::unexpected(architecture.error());

        // Initialize and clean up syscalls via RAII guard
        SyscallsGuard syscalls_guard;
        const bool use_syscalls = syscalls_guard.active;

        // Open target process
        HANDLE process_handle = sys_open_process(static_cast<DWORD>(process_id), use_syscalls);
        if (!process_handle)
            return std::unexpected(std::format("Failed to open target process (error {})", GetLastError()));

        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(raw_dll.data());
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(raw_dll.data() + dos->e_lfanew);
        const std::size_t image_size = nt->OptionalHeader.SizeOfImage;

        // Allocate image memory in target process
        auto* remote_image = static_cast<std::uint8_t*>(
            sys_virtual_alloc(process_handle, nullptr, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE, use_syscalls)
        );

        if (!remote_image)
        {
            CloseHandle(process_handle);
            return std::unexpected(std::format("VirtualAllocEx failed for image (error {})", GetLastError()));
        }

        // Prepare local copy: headers + sections
        std::vector<std::uint8_t> local_image(image_size, 0);
        std::copy_n(raw_dll.data(), nt->OptionalHeader.SizeOfHeaders, local_image.data());

        auto* section_header = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, section_header++)
        {
            if (!section_header->SizeOfRawData)
                continue;
            std::copy_n(raw_dll.data() + section_header->PointerToRawData, section_header->SizeOfRawData,
                        local_image.data() + section_header->VirtualAddress);
        }

        // Relocate for remote base address
        if (!detail::relocate_for_base(local_image.data(), reinterpret_cast<std::uintptr_t>(remote_image)))
        {
            sys_virtual_free(process_handle, remote_image, 0, MEM_RELEASE, use_syscalls);
            CloseHandle(process_handle);
            return std::unexpected("Image requires relocation but has no relocation directory");
        }

        // Write image to target
        if (!sys_write_process_memory(process_handle, remote_image, local_image.data(), image_size, nullptr, use_syscalls))
        {
            sys_virtual_free(process_handle, remote_image, 0, MEM_RELEASE, use_syscalls);
            CloseHandle(process_handle);
            return std::unexpected("WriteProcessMemory failed for image");
        }

        // Prepare shellcode page: [RemoteLoaderData | padding | shellcode bytes]
#ifdef _WIN64
        const auto native_remote_shellcode = yail::detail::x64_remote_shellcode();
#else
        const auto native_remote_shellcode = yail::detail::x86_remote_shellcode();
#endif
        constexpr std::size_t data_aligned = (sizeof(detail::RemoteLoaderData) + 0xF) & ~0xF;
        const std::size_t total_shellcode = data_aligned + native_remote_shellcode.size();

        auto* remote_shellcode = static_cast<std::uint8_t*>(
            sys_virtual_alloc(process_handle, nullptr, total_shellcode, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE, use_syscalls)
        );

        if (!remote_shellcode)
        {
            sys_virtual_free(process_handle, remote_image, 0, MEM_RELEASE, use_syscalls);
            CloseHandle(process_handle);
            return std::unexpected("VirtualAllocEx failed for shellcode");
        }

        // Fill loader data
        const auto* local_dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(local_image.data());

        detail::RemoteLoaderData loader_data{};
        loader_data.image_base = remote_image;
        loader_data.nt_headers_rva = static_cast<DWORD>(local_dos_header->e_lfanew);
        loader_data.fn_load_library_a = LoadLibraryA;
        loader_data.fn_get_proc_address = GetProcAddress;
#ifdef _WIN64
        loader_data.fn_rtl_add_function_table = RtlAddFunctionTable;
#endif
        loader_data.fn_virtual_protect = VirtualProtect;
        const auto tls_fn = detail::find_ldrp_handle_tls_data();
        if (!tls_fn)
        {
            sys_virtual_free(process_handle, remote_shellcode, 0, MEM_RELEASE, use_syscalls);
            sys_virtual_free(process_handle, remote_image, 0, MEM_RELEASE, use_syscalls);
            CloseHandle(process_handle);
            return std::unexpected(tls_fn.error());
        }
        loader_data.fn_ldrp_handle_tls_data = tls_fn.value();
        // RtlInsertInvertedFunctionTable is required on x64 (unwind tables) but optional on
        // x86 - without it, manually-mapped DLLs that throw will crash on dispatch, but DLLs
        // that don't throw load fine. Treat lookup failure as fatal only on x64.
        if (const auto inv_fn = detail::find_rtl_insert_inverted_function_table())
        {
            loader_data.fn_rtl_insert_inverted_function_table = inv_fn.value();
        }
#ifdef _WIN64
        else
        {
            sys_virtual_free(process_handle, remote_shellcode, 0, MEM_RELEASE, use_syscalls);
            sys_virtual_free(process_handle, remote_image, 0, MEM_RELEASE, use_syscalls);
            CloseHandle(process_handle);
            return std::unexpected(inv_fn.error());
        }
#endif

        // Build local shellcode page
        std::vector<std::uint8_t> shell_code_page(total_shellcode, 0);
        std::copy_n(reinterpret_cast<const std::uint8_t*>(&loader_data), sizeof(loader_data), shell_code_page.data());
        std::ranges::copy(native_remote_shellcode,
                  shell_code_page.data() + data_aligned);

        // Write shellcode page to target
        if (!sys_write_process_memory(process_handle, remote_shellcode, shell_code_page.data(), total_shellcode, nullptr, use_syscalls))
        {
            sys_virtual_free(process_handle, remote_shellcode, 0, MEM_RELEASE, use_syscalls);
            sys_virtual_free(process_handle, remote_image, 0, MEM_RELEASE, use_syscalls);
            CloseHandle(process_handle);
            return std::unexpected("WriteProcessMemory failed for shellcode");
        }

        // Create remote thread
        HANDLE thread_handle = sys_create_remote_thread(
            process_handle,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(remote_shellcode + data_aligned),
            remote_shellcode,
            use_syscalls
        );

        if (!thread_handle)
        {
            sys_virtual_free(process_handle, remote_shellcode, 0, MEM_RELEASE, use_syscalls);
            sys_virtual_free(process_handle, remote_image, 0, MEM_RELEASE, use_syscalls);
            CloseHandle(process_handle);
            return std::unexpected(std::format("CreateRemoteThread failed (error {})", GetLastError()));
        }

        WaitForSingleObject(thread_handle, INFINITE);

        DWORD exit_code = 0;
        GetExitCodeThread(thread_handle, &exit_code);
        CloseHandle(thread_handle);

        // Free shellcode page - no longer needed after init
        sys_virtual_free(process_handle, remote_shellcode, 0, MEM_RELEASE, use_syscalls);
        CloseHandle(process_handle);

        if (exit_code != 0)
            return std::unexpected(std::format("Remote shellcode failed (exit code {})", exit_code));

        return reinterpret_cast<std::uintptr_t>(remote_image);
    }

    std::expected<std::uintptr_t, std::string>
    manual_map_injection_from_raw(const std::span<const std::uint8_t>& raw_dll, const std::string_view& process_name)
    {
        const auto pid = detail::get_process_id_by_name(process_name);

        if (!pid)
            return std::unexpected(std::format("Process \"{}\" not found", process_name));

        return manual_map_injection_from_raw(raw_dll, pid.value());
    }

    std::expected<std::uintptr_t, std::string> manual_map_injection_from_file(const std::string_view& dll_path,
                                                                              const std::uintptr_t process_id)
    {
        if (!std::filesystem::exists(dll_path))
            return std::unexpected("File does not exists.");
        std::vector<std::uint8_t> data(static_cast<std::size_t>(std::filesystem::file_size(dll_path)), 0);
        std::ifstream file(std::filesystem::path{dll_path}, std::ios::binary);
        if (!file.is_open())
            return std::unexpected("Failed to open DLL file");

        file.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));

        return manual_map_injection_from_raw({data.data(), data.size()}, process_id);
    }

    std::expected<std::uintptr_t, std::string> manual_map_injection_from_file(const std::string_view& dll_path,
                                                                              const std::string_view& process_name)
    {
        std::vector<std::uint8_t> data(static_cast<std::size_t>(std::filesystem::file_size(dll_path)), 0);
        std::ifstream file(std::filesystem::path{dll_path}, std::ios::binary);
        if (!file.is_open())
            return std::unexpected("Failed to open DLL file");

        file.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));

        return manual_map_injection_from_raw({data.data(), data.size()}, process_name);
    }
} // namespace yail

