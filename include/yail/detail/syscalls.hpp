#pragma once
#include <windows.h>
#include <winternl.h>
#include <cstdint>

namespace yail::detail::syscalls
{
    constexpr NTSTATUS STATUS_UNSUCCESSFUL = static_cast<NTSTATUS>(0xC0000001);

    // Initialize the stealthy syscall subsystem
    bool init();

    // Deinitialize the stealthy syscall subsystem
    void deinit();

    // The dummy wrapper that serves as our hardware breakpoint hook target.
    // It returns the real NT function address.
    std::uintptr_t prepare_syscall(const char* name);

    // Custom NT API type declarations and indirect wrappers
    using NtOpenProcessFn = NTSTATUS(NTAPI*)(
        PHANDLE ProcessHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PVOID ClientId
    );

    using NtAllocateVirtualMemoryFn = NTSTATUS(NTAPI*)(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protect
    );

    using NtWriteVirtualMemoryFn = NTSTATUS(NTAPI*)(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T NumberOfBytesToWrite,
        PSIZE_T NumberOfBytesWritten
    );

    using NtCreateThreadExFn = NTSTATUS(NTAPI*)(
        PHANDLE ThreadHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        HANDLE ProcessHandle,
        PVOID StartRoutine,
        PVOID Argument,
        ULONG CreateFlags,
        ULONG_PTR ZeroBits,
        SIZE_T StackSize,
        SIZE_T MaximumStackSize,
        PVOID AttributeList
    );

    using NtFreeVirtualMemoryFn = NTSTATUS(NTAPI*)(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        PSIZE_T RegionSize,
        ULONG FreeType
    );

    using NtProtectVirtualMemoryFn = NTSTATUS(NTAPI*)(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        PSIZE_T RegionSize,
        ULONG NewProtect,
        PULONG OldProtect
    );

    // Wrapper calls that direct through the HWBP handler
    inline NTSTATUS nt_open_process(
        PHANDLE process_handle,
        ACCESS_MASK desired_access,
        POBJECT_ATTRIBUTES object_attributes,
        PVOID client_id)
    {
        auto fn = reinterpret_cast<NtOpenProcessFn>(prepare_syscall("NtOpenProcess"));
        return fn(process_handle, desired_access, object_attributes, client_id);
    }

    inline NTSTATUS nt_allocate_virtual_memory(
        HANDLE process_handle,
        PVOID* base_address,
        ULONG_PTR zero_bits,
        PSIZE_T region_size,
        ULONG allocation_type,
        ULONG protect)
    {
        auto fn = reinterpret_cast<NtAllocateVirtualMemoryFn>(prepare_syscall("NtAllocateVirtualMemory"));
        return fn(process_handle, base_address, zero_bits, region_size, allocation_type, protect);
    }

    inline NTSTATUS nt_write_virtual_memory(
        HANDLE process_handle,
        PVOID base_address,
        PVOID buffer,
        SIZE_T number_of_bytes_to_write,
        PSIZE_T number_of_bytes_written)
    {
        auto fn = reinterpret_cast<NtWriteVirtualMemoryFn>(prepare_syscall("NtWriteVirtualMemory"));
        return fn(process_handle, base_address, buffer, number_of_bytes_to_write, number_of_bytes_written);
    }

    inline NTSTATUS nt_create_thread_ex(
        PHANDLE thread_handle,
        ACCESS_MASK desired_access,
        POBJECT_ATTRIBUTES object_attributes,
        HANDLE process_handle,
        PVOID start_routine,
        PVOID argument,
        ULONG create_flags,
        ULONG_PTR zero_bits,
        SIZE_T stack_size,
        SIZE_T maximum_stack_size,
        PVOID attribute_list)
    {
        auto fn = reinterpret_cast<NtCreateThreadExFn>(prepare_syscall("NtCreateThreadEx"));
        return fn(thread_handle, desired_access, object_attributes, process_handle, start_routine,
                  argument, create_flags, zero_bits, stack_size, maximum_stack_size, attribute_list);
    }

    inline NTSTATUS nt_free_virtual_memory(
        HANDLE process_handle,
        PVOID* base_address,
        PSIZE_T region_size,
        ULONG free_type)
    {
        auto fn = reinterpret_cast<NtFreeVirtualMemoryFn>(prepare_syscall("NtFreeVirtualMemory"));
        return fn(process_handle, base_address, region_size, free_type);
    }

    inline NTSTATUS nt_protect_virtual_memory(
        HANDLE process_handle,
        PVOID* base_address,
        PSIZE_T region_size,
        ULONG new_protect,
        PULONG old_protect)
    {
        auto fn = reinterpret_cast<NtProtectVirtualMemoryFn>(prepare_syscall("NtProtectVirtualMemory"));
        return fn(process_handle, base_address, region_size, new_protect, old_protect);
    }
} // namespace yail::detail::syscalls
