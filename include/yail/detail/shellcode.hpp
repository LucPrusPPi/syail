#pragma once
#include <cstdint>
#include <span>

namespace yail::detail
{
    [[nodiscard]]
    std::span<const std::uint8_t> x64_remote_shellcode();

    [[nodiscard]]
    std::span<const std::uint8_t> x86_remote_shellcode();
}
