#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <ostream>
#include <string>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#endif

namespace tenzo
{
    namespace detail
    {
        constexpr std::size_t mix_seed(std::size_t seed, std::size_t index) noexcept
        {
            return ((seed * 131u) + (index * 17u) + 23u) | 1u;
        }

        constexpr unsigned char rotate_left(unsigned char value, unsigned char shift) noexcept
        {
            shift &= 7u;
            return shift == 0
                ? value
                : static_cast<unsigned char>((value << shift) | (value >> (8u - shift)));
        }

        constexpr unsigned char rotate_right(unsigned char value, unsigned char shift) noexcept
        {
            shift &= 7u;
            return shift == 0
                ? value
                : static_cast<unsigned char>((value >> shift) | (value << (8u - shift)));
        }

        constexpr unsigned char byte_mask(std::size_t seed, std::size_t original_index, std::size_t stored_index) noexcept
        {
            const std::size_t mixed = mix_seed(seed ^ ((original_index + 1u) * 97u), stored_index + 11u);
            return static_cast<unsigned char>((mixed ^ (mixed >> 7u) ^ (mixed >> 13u)) & 0xFFu);
        }

        constexpr unsigned char byte_bias(std::size_t seed, std::size_t original_index, std::size_t stored_index) noexcept
        {
            const std::size_t mixed = mix_seed(seed + ((stored_index + 1u) * 193u), original_index + 29u);
            return static_cast<unsigned char>((mixed ^ (mixed >> 9u) ^ (mixed >> 15u)) & 0xFFu);
        }

        constexpr unsigned char rotation_amount(std::size_t seed, std::size_t original_index, std::size_t stored_index) noexcept
        {
            return static_cast<unsigned char>((mix_seed(seed + (original_index * 31u), stored_index + 7u) % 7u) + 1u);
        }

        constexpr unsigned char encode_byte(unsigned char value, std::size_t seed, std::size_t original_index, std::size_t stored_index) noexcept
        {
            const unsigned char mask = byte_mask(seed, original_index, stored_index);
            const unsigned char bias = byte_bias(seed, original_index, stored_index);
            const unsigned char rotation = rotation_amount(seed, original_index, stored_index);

            return static_cast<unsigned char>(rotate_left(static_cast<unsigned char>(value ^ mask), rotation) + bias);
        }

        constexpr unsigned char decode_byte(unsigned char value, std::size_t seed, std::size_t original_index, std::size_t stored_index) noexcept
        {
            const unsigned char mask = byte_mask(seed, original_index, stored_index);
            const unsigned char bias = byte_bias(seed, original_index, stored_index);
            const unsigned char rotation = rotation_amount(seed, original_index, stored_index);

            return static_cast<unsigned char>(rotate_right(static_cast<unsigned char>(value - bias), rotation) ^ mask);
        }

        constexpr std::size_t hash_time(const char* str, std::size_t h = 0) noexcept
        {
            return (*str == '\0') ? h : hash_time(str + 1, ((h * 131u) ^ static_cast<std::size_t>(*str)) + 7u);
        }

        inline void wipe(void* ptr, std::size_t len) noexcept
        {
#ifdef _WIN32
            SecureZeroMemory(ptr, len);
#else
            volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
            while (len--) *p++ = 0;
#endif
        }

        template <std::size_t N, std::size_t Seed>
        struct storage_holder
        {
            std::array<unsigned char, N> data;
            std::array<std::size_t, N - 1> order;
        };
    }

    template <std::size_t N, std::size_t Seed>
    class obfuscated_string
    {
    public:
        constexpr explicit obfuscated_string(const char(&text)[N]) noexcept
            : storage_()
        {
            build_order();
            shuffle_text(text);
        }

        constexpr std::size_t size() const noexcept { return N - 1; }

        char get(std::size_t index) const noexcept
        {
            if (index >= size()) return '\0';
            unsigned char decoded = detail::decode_byte(
                storage_.data[storage_.order[index]], Seed, index, storage_.order[index]);
            return static_cast<char>(decoded);
        }

        template <typename F>
        void each(F&& fn) const
        {
            unsigned char temp;
            for (std::size_t i = 0; i < size(); ++i)
            {
                temp = detail::decode_byte(
                    storage_.data[storage_.order[i]], Seed, i, storage_.order[i]);
                fn(static_cast<char>(temp));
                temp = 0;
            }
        }

        bool equals(const char* other) const
        {
            if (!other) return false;
            unsigned char temp;
            for (std::size_t i = 0; i < size(); ++i)
            {
                temp = detail::decode_byte(
                    storage_.data[storage_.order[i]], Seed, i, storage_.order[i]);
                if (static_cast<char>(temp) != other[i])
                {
                    temp = 0;
                    return false;
                }
                if (other[i] == '\0')
                {
                    temp = 0;
                    return false;
                }
                temp = 0;
            }
            return other[size()] == '\0';
        }

        void into(char* buffer, std::size_t buf_size) const
        {
            if (!buffer || buf_size <= size()) return;
            for (std::size_t i = 0; i < size(); ++i)
            {
                buffer[i] = static_cast<char>(detail::decode_byte(
                    storage_.data[storage_.order[i]], Seed, i, storage_.order[i]));
            }
            buffer[size()] = '\0';
        }

        void print(std::ostream& stream) const
        {
            each([&stream](char c) { stream.put(c); });
        }

    private:
        constexpr void build_order() noexcept
        {
            for (std::size_t i = 0; i < size(); ++i) storage_.order[i] = i;
            if (size() < 2) return;

            for (std::size_t i = size(); i > 1; --i)
            {
                const std::size_t current = i - 1;
                const std::size_t swap_with = detail::mix_seed(Seed, current) % i;
                const std::size_t temp = storage_.order[current];
                storage_.order[current] = storage_.order[swap_with];
                storage_.order[swap_with] = temp;
            }
        }

        constexpr void shuffle_text(const char(&text)[N]) noexcept
        {
            for (std::size_t i = 0; i < size(); ++i)
            {
                const std::size_t stored_index = storage_.order[i];
                storage_.data[stored_index] = detail::encode_byte(
                    static_cast<unsigned char>(text[i]), Seed, i, stored_index);
            }
            storage_.data[size()] = detail::encode_byte('\0', Seed, size(), size());
        }

        detail::storage_holder<N, Seed> storage_;
    };

    template <std::size_t Seed, std::size_t N>
    constexpr obfuscated_string<N, Seed> make_obfuscated(const char(&text)[N]) noexcept
    {
        return obfuscated_string<N, Seed>(text);
    }

    template <std::size_t N, std::size_t Seed>
    std::ostream& operator<<(std::ostream& stream, const obfuscated_string<N, Seed>& val)
    {
        val.print(stream);
        return stream;
    }
}

#define TENZO_OBFUSCATE(text) \
    ::tenzo::make_obfuscated< \
        (::tenzo::detail::hash_time(__TIME__) * 16777619u) ^ \
        (static_cast<std::size_t>(__COUNTER__) * 1103515245u) ^ \
        (static_cast<std::size_t>(__LINE__) * 214013u) \
    >(text)