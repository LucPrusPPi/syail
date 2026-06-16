#pragma once
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <array>
#include <span>
#include <string_view>
#include <optional>
#include <algorithm>
#include <vector>
#include <windows.h>

namespace yail::detail
{
    namespace pattern_scan_impl
    {
        // Helper to determine the number of bytes/wildcards in a pattern string at compile time
        constexpr std::size_t count_elements(std::string_view pattern)
        {
            std::size_t count = 0;
            bool const_space = true;
            for (char c : pattern)
            {
                if (c == ' ')
                {
                    const_space = true;
                }
                else
                {
                    if (const_space)
                    {
                        count++;
                        const_space = false;
                    }
                }
            }
            return count;
        }

        // Helper to convert hexadecimal character to value
        constexpr std::uint8_t hex_to_val(char c)
        {
            if (c >= '0' && c <= '9') return static_cast<std::uint8_t>(c - '0');
            if (c >= 'a' && c <= 'f') return static_cast<std::uint8_t>(c - 'a' + 10);
            if (c >= 'A' && c <= 'F') return static_cast<std::uint8_t>(c - 'A' + 10);
            return 0;
        }

        // Element representing either a concrete byte or a wildcard
        struct PatternElement
        {
            std::uint8_t value;
            bool is_wildcard;
        };

        // Parse compile-time pattern string into array
        template <std::size_t N>
        constexpr std::array<PatternElement, N> parse_pattern(std::string_view pattern)
        {
            std::array<PatternElement, N> result{};
            std::size_t index = 0;
            std::size_t i = 0;
            while (i < pattern.length() && index < N)
            {
                // Skip leading spaces
                while (i < pattern.length() && pattern[i] == ' ')
                {
                    i++;
                }
                if (i >= pattern.length())
                {
                    break;
                }

                // Check for wildcard
                if (pattern[i] == '?')
                {
                    result[index++] = {0, true};
                    i++;
                    // Skip optional second ?
                    if (i < pattern.length() && pattern[i] == '?')
                    {
                        i++;
                    }
                }
                else
                {
                    // Parse hex byte
                    std::uint8_t val = 0;
                    if (i < pattern.length())
                    {
                        val = static_cast<std::uint8_t>(hex_to_val(pattern[i]) << 4);
                        i++;
                    }
                    if (i < pattern.length() && pattern[i] != ' ')
                    {
                        val |= hex_to_val(pattern[i]);
                        i++;
                    }
                    result[index++] = {val, false};
                }
            }
            return result;
        }
    } // namespace pattern_scan_impl

    // Representation of a parsed pattern
    template <std::size_t N>
    struct CompileTimePattern
    {
        std::array<pattern_scan_impl::PatternElement, N> elements;

        constexpr explicit CompileTimePattern(std::string_view pattern)
            : elements(pattern_scan_impl::parse_pattern<N>(pattern))
        {}
    };

    // High performance pattern scanning algorithm
    template <std::size_t N>
    inline std::optional<const std::uint8_t*> scan_pattern(
        std::span<const std::uint8_t> data,
        const CompileTimePattern<N>& pattern)
    {
        if (data.size() < N)
            return std::nullopt;

        const auto* const begin = data.data();
        const auto* const end = begin + data.size() - N + 1;

        for (const auto* current = begin; current < end; ++current)
        {
            bool match = true;
            for (std::size_t i = 0; i < N; ++i)
            {
                if (!pattern.elements[i].is_wildcard && current[i] != pattern.elements[i].value)
                {
                    match = false;
                    break;
                }
            }
            if (match)
            {
                return current;
            }
        }

        return std::nullopt;
    }

    // General purpose runtime scanner using dynamically parsed string if constexpr is not desired
    inline std::optional<const std::uint8_t*> scan_pattern_dynamic(
        std::span<const std::uint8_t> data,
        std::string_view pattern_str)
    {
        // For dynamic parsing, parse to a vector and run the match
        std::vector<pattern_scan_impl::PatternElement> elements;
        std::size_t i = 0;
        while (i < pattern_str.length())
        {
            while (i < pattern_str.length() && pattern_str[i] == ' ')
            {
                i++;
            }
            if (i >= pattern_str.length())
            {
                break;
            }

            if (pattern_str[i] == '?')
            {
                elements.push_back({0, true});
                i++;
                if (i < pattern_str.length() && pattern_str[i] == '?')
                {
                    i++;
                }
            }
            else
            {
                std::uint8_t val = 0;
                val = static_cast<std::uint8_t>(pattern_scan_impl::hex_to_val(pattern_str[i]) << 4);
                i++;
                if (i < pattern_str.length() && pattern_str[i] != ' ')
                {
                    val |= pattern_scan_impl::hex_to_val(pattern_str[i]);
                    i++;
                }
                elements.push_back({val, false});
            }
        }

        if (data.size() < elements.size())
            return std::nullopt;

        const auto* const begin = data.data();
        const auto* const end = begin + data.size() - elements.size() + 1;

        for (const auto* current = begin; current < end; ++current)
        {
            bool match = true;
            for (std::size_t idx = 0; idx < elements.size(); ++idx)
            {
                if (!elements[idx].is_wildcard && current[idx] != elements[idx].value)
                {
                    match = false;
                    break;
                }
            }
            if (match)
            {
                return current;
            }
        }

        return std::nullopt;
    }

    // Scan inside loaded module by name (.text section search)
    inline std::optional<const std::uint8_t*> scan_in_module(
        const void* module_handle,
        std::string_view pattern_str)
    {
        if (!module_handle)
            return std::nullopt;

        const auto* image_base = reinterpret_cast<const std::uint8_t*>(module_handle);
        const auto* dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(image_base);
        if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
            return std::nullopt;

        const auto* nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS*>(image_base + dos_header->e_lfanew);
        if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
            return std::nullopt;

        const auto* section_header = IMAGE_FIRST_SECTION(nt_headers);
        for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section_header++)
        {
            // Search only in executable memory (.text / code section)
            if (section_header->Characteristics & IMAGE_SCN_CNT_CODE || 
                section_header->Characteristics & IMAGE_SCN_MEM_EXECUTE)
            {
                const std::uint8_t* sec_start = image_base + section_header->VirtualAddress;
                std::size_t sec_size = section_header->Misc.VirtualSize;
                if (!sec_size)
                    sec_size = section_header->SizeOfRawData;

                if (auto result = scan_pattern_dynamic({sec_start, sec_size}, pattern_str))
                {
                    return result;
                }
            }
        }

        return std::nullopt;
    }
} // namespace yail::detail
