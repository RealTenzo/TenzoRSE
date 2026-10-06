// TenzoRSE - MIT (c) Tenzo
// block cipher core derived from mux by Den Marche, same license terms

#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ostream>
#include <string>
#include <string_view>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace tenzo
{
    namespace detail
    {
        using u8 = std::uint8_t;
        using u32 = std::uint32_t;
        using u64 = std::uint64_t;

        constexpr u32 delta = 0x9E3779B9u;
        constexpr u32 rounds = 6u;

        constexpr u64 mix(u64 x) noexcept
        {
            x += 0x9E3779B97F4A7C15ull;
            x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ull;
            x = (x ^ (x >> 27)) * 0x94D049BB133111EBull;
            return x ^ (x >> 31);
        }

        constexpr u64 mix2(u64 x) noexcept
        {
            x ^= x >> 33;
            x *= 0xFF51AFD7ED558CCDull;
            x ^= x >> 33;
            x *= 0xC4CEB9FE1A85EC53ull;
            x ^= x >> 33;
            return x;
        }

        constexpr u32 bswap32(u32 v) noexcept
        {
            return ((v & 0x000000FFu) << 24) | ((v & 0x0000FF00u) << 8) |
                ((v & 0x00FF0000u) >> 8) | ((v & 0xFF000000u) >> 24);
        }

        constexpr u32 rol(u32 v, u32 n) noexcept
        {
            return (v << n) | (v >> (32u - n));
        }

        constexpr u32 load32(const u8* p) noexcept
        {
            return static_cast<u32>(p[0]) | (static_cast<u32>(p[1]) << 8) |
                (static_cast<u32>(p[2]) << 16) | (static_cast<u32>(p[3]) << 24);
        }

        constexpr void st32(u8* p, u32 v) noexcept
        {
            p[0] = static_cast<u8>(v);
            p[1] = static_cast<u8>(v >> 8);
            p[2] = static_cast<u8>(v >> 16);
            p[3] = static_cast<u8>(v >> 24);
        }

        struct keys { u32 k[4]; };

        constexpr keys derive(u64 seed, std::size_t n) noexcept
        {
            const u64 m0 = mix(mix2(seed ^ (static_cast<u64>(n) * 0x100000001B3ull)));
            const u64 m1 = mix(m0 + 0xD1B54A32D192ED03ull);
            return keys{{
                0x6B206574u ^ static_cast<u32>(m0),
                0x79622D32u ^ static_cast<u32>(m0 >> 32),
                0x3320646Eu ^ static_cast<u32>(m1),
                0x61707865u ^ static_cast<u32>(m1 >> 32),
            }};
        }

        constexpr keys tweak(const keys& ks, u32 idx) noexcept
        {
            const u64 m = mix((static_cast<u64>(idx) << 32) | ks.k[0]);
            return keys{{
                ks.k[0] ^ static_cast<u32>(m),
                ks.k[1] ^ static_cast<u32>(m >> 32),
                bswap32(ks.k[2] + static_cast<u32>(m >> 11)),
                bswap32(ks.k[3] - static_cast<u32>(m >> 43)),
            }};
        }

        constexpr u32 arx(u32 v, u32 k, u32 r) noexcept
        {
            u32 t = v + k + ((r + 1u) * delta);
            t ^= rol(t, 7u);
            t += k;
            t ^= rol(t, 11u);
            return t ^ (k * delta);
        }

        constexpr void blk_fwd(u8* p, const u32* k) noexcept
        {
            u32 l = load32(p) ^ k[2];
            u32 r = load32(p + 4) ^ k[3];
            for (u32 i = 0; i != rounds; ++i)
            {
                const u32 t = l ^ arx(r, k[i & 3u], i);
                l = r;
                r = t;
            }
            r ^= rol(l, 19u);
            st32(p, l + r);
            st32(p + 4, r);
        }

        constexpr void blk_inv(u8* p, const u32* k) noexcept
        {
            u32 r = load32(p + 4);
            u32 l = load32(p) - r;
            r ^= rol(l, 19u);
            for (u32 i = rounds; i-- != 0;)
            {
                const u32 t = r ^ arx(l, k[i & 3u], i);
                r = l;
                l = t;
            }
            st32(p, l ^ k[2]);
            st32(p + 4, r ^ k[3]);
        }

        constexpr u64 tick_hash(const char* s) noexcept
        {
            u64 h = 14695981039346656037ull;
            while (*s) h = (h ^ static_cast<u8>(*s++)) * 1099511628211ull;
            return h;
        }

        constexpr u64 seed_of(const char* txt, u64 line, u64 ctr, u64 tick) noexcept
        {
            u64 h = 14695981039346656037ull;
            while (*txt) h = (h ^ static_cast<u8>(*txt++)) * 1099511628211ull;
            return mix(mix2(h ^ (line * 0x9E3779B97F4A7C15ull) ^
                (ctr * 0xC2B2AE3D27D4EB4Full) ^ (tick * 0xD6E8FEB86659FD93ull)));
        }

        inline void wipe(void* ptr, std::size_t len) noexcept
        {
#ifdef _WIN32
            SecureZeroMemory(ptr, len);
#else
            volatile u8* p = static_cast<volatile u8*>(ptr);
            while (len--) *p++ = 0;
#endif
        }
    }

    inline void wipe(void* ptr, std::size_t len) noexcept
    {
        detail::wipe(ptr, len);
    }

    template <std::size_t Cap>
    class view
    {
    public:
        explicit view(const char* src) noexcept : len_(0), buf_()
        {
            for (; len_ + 1 < Cap && src[len_]; ++len_) buf_[len_] = src[len_];
            buf_[len_] = '\0';
        }

        view(const view&) = delete;
        view& operator=(const view&) = delete;

        view(view&& other) noexcept : len_(other.len_), buf_()
        {
            for (std::size_t i = 0; i < Cap; ++i) buf_[i] = other.buf_[i];
            wipe(other.buf_, Cap);
            other.buf_[0] = '\0';
            other.len_ = 0;
        }

        ~view() { wipe(buf_, sizeof(buf_)); }

        const char* c_str() const noexcept { return buf_; }
        const char* data() const noexcept { return buf_; }
        std::size_t size() const noexcept { return len_; }
        operator const char*() const noexcept { return buf_; }

    private:
        std::size_t len_;
        char buf_[Cap];
    };

    template <std::size_t N, detail::u64 Seed>
    class obfuscated_string
    {
        static_assert(N > 0, "literal needs at least a NUL");

        static constexpr std::size_t TOTAL = N + ((8u - (N & 7u)) & 7u);
        static constexpr detail::u32 BLOCKS = static_cast<detail::u32>(TOTAL / 8u);

    public:
        constexpr explicit obfuscated_string(const char (&txt)[N]) noexcept : store_()
        {
            const detail::keys ks = detail::derive(Seed, N);
            for (std::size_t i = 0; i < N; ++i)
                store_[i] = static_cast<detail::u8>(txt[i]);
            for (std::size_t i = N; i < TOTAL; ++i)
                store_[i] = static_cast<detail::u8>(
                    detail::mix(Seed ^ (i * 0x9E3779B97F4A7C15ull)) >> ((i * 5u) & 31u));
            for (detail::u32 b = 0; b != BLOCKS; ++b)
            {
                const detail::keys tk = detail::tweak(ks, b);
                detail::blk_fwd(&store_[b * 8u], tk.k);
            }
        }

        constexpr std::size_t size() const noexcept { return N - 1u; }

        constexpr char get(std::size_t i) const noexcept
        {
            if (i >= size()) return '\0';
            detail::u8 blk[8];
            dec_block(static_cast<detail::u32>(i >> 3), blk);
            return static_cast<char>(blk[i & 7u]);
        }

        constexpr char operator[](std::size_t i) const noexcept { return get(i); }

        template <typename F>
        void each(F&& fn) const
        {
            detail::u8 blk[8];
            for (detail::u32 b = 0; b != BLOCKS; ++b)
            {
                dec_block(b, blk);
                const std::size_t lo = static_cast<std::size_t>(b) * 8u;
                const std::size_t hi = lo + 8u < size() ? lo + 8u : size();
                for (std::size_t i = lo; i < hi; ++i)
                    fn(static_cast<char>(blk[i - lo]));
                wipe(blk, sizeof(blk));
            }
        }

        bool equals(std::string_view s) const noexcept
        {
            if (s.size() != size()) return false;
            const char* other = s.data();
            detail::u8 blk[8];
            detail::u32 diff = 0;
            for (detail::u32 b = 0; b != BLOCKS; ++b)
            {
                dec_block(b, blk);
                const std::size_t lo = static_cast<std::size_t>(b) * 8u;
                const std::size_t hi = lo + 8u < size() ? lo + 8u : size();
                for (std::size_t i = lo; i < hi; ++i)
                    diff |= static_cast<detail::u32>(blk[i - lo]) ^ static_cast<detail::u32>(static_cast<detail::u8>(other[i]));
                wipe(blk, sizeof(blk));
            }
            return diff == 0;
        }

        bool equals(const char* s) const noexcept
        {
            return s != nullptr && equals(std::string_view(s));
        }

        bool equals(const std::string& s) const noexcept
        {
            return equals(std::string_view(s));
        }

        void into(char* dst, std::size_t cap) const noexcept
        {
            if (dst == nullptr || cap <= size()) return;
            detail::u8 blk[8];
            for (detail::u32 b = 0; b != BLOCKS; ++b)
            {
                dec_block(b, blk);
                const std::size_t lo = static_cast<std::size_t>(b) * 8u;
                const std::size_t hi = lo + 8u < size() ? lo + 8u : size();
                for (std::size_t i = lo; i < hi; ++i)
                    dst[i] = static_cast<char>(blk[i - lo]);
                wipe(blk, sizeof(blk));
            }
            dst[size()] = '\0';
        }

        view<N> open() const
        {
            char tmp[N];
            into(tmp, N);
            view<N> out(tmp);
            wipe(tmp, sizeof(tmp));
            return out;
        }

        operator const char*() const
        {
            thread_local std::string slots[8];
            thread_local std::size_t next = 0;
            std::string& slot = slots[next];
            next = (next + 1u) & 7u;
            slot.assign(size(), '\0');
            char* dst = &slot[0];
            detail::u8 blk[8];
            for (detail::u32 b = 0; b != BLOCKS; ++b)
            {
                dec_block(b, blk);
                const std::size_t lo = static_cast<std::size_t>(b) * 8u;
                const std::size_t hi = lo + 8u < size() ? lo + 8u : size();
                for (std::size_t i = lo; i < hi; ++i)
                    dst[i] = static_cast<char>(blk[i - lo]);
                wipe(blk, sizeof(blk));
            }
            return slot.c_str();
        }

        std::string str() const
        {
            const view<N> held = open();
            return std::string(held.c_str());
        }

        detail::u64 hash() const noexcept
        {
            detail::u64 h = 14695981039346656037ull;
            each([&h](char c)
                { h = (h ^ static_cast<detail::u8>(c)) * 1099511628211ull; });
            return h;
        }

        void print(std::ostream& stream) const
        {
            each([&stream](char c) { stream.put(c); });
        }

    private:
        constexpr void dec_block(detail::u32 b, detail::u8* out) const noexcept
        {
            const detail::keys tk = detail::tweak(detail::derive(Seed, N), b);
            for (int i = 0; i < 8; ++i) out[i] = store_[b * 8u + static_cast<detail::u32>(i)];
            detail::blk_inv(out, tk.k);
        }

        detail::u8 store_[TOTAL];
    };

    template <std::size_t N, detail::u64 Seed>
    std::ostream& operator<<(std::ostream& stream, const obfuscated_string<N, Seed>& val)
    {
        val.print(stream);
        return stream;
    }

    template <std::size_t N, detail::u64 Seed>
    bool operator==(const obfuscated_string<N, Seed>& a, std::string_view b) noexcept
    {
        return a.equals(b);
    }

    template <std::size_t N, detail::u64 Seed>
    bool operator==(std::string_view a, const obfuscated_string<N, Seed>& b) noexcept
    {
        return b.equals(a);
    }

    template <std::size_t N, detail::u64 Seed>
    bool operator==(const obfuscated_string<N, Seed>& a, const std::string& b) noexcept
    {
        return a.equals(b);
    }

    template <std::size_t N, detail::u64 Seed>
    bool operator==(const std::string& a, const obfuscated_string<N, Seed>& b) noexcept
    {
        return b.equals(a);
    }

    template <std::size_t N, detail::u64 Seed>
    bool operator==(const obfuscated_string<N, Seed>& a, const char* b) noexcept
    {
        return a.equals(b);
    }

    template <std::size_t N, detail::u64 Seed>
    bool operator==(const char* a, const obfuscated_string<N, Seed>& b) noexcept
    {
        return b.equals(a);
    }

    template <std::size_t N, detail::u64 Seed>
    bool operator!=(const obfuscated_string<N, Seed>& a, std::string_view b) noexcept
    {
        return !a.equals(b);
    }

    template <std::size_t N, detail::u64 Seed>
    bool operator!=(std::string_view a, const obfuscated_string<N, Seed>& b) noexcept
    {
        return !b.equals(a);
    }

    template <std::size_t N, detail::u64 Seed>
    bool operator!=(const obfuscated_string<N, Seed>& a, const std::string& b) noexcept
    {
        return !a.equals(b);
    }

    template <std::size_t N, detail::u64 Seed>
    bool operator!=(const std::string& a, const obfuscated_string<N, Seed>& b) noexcept
    {
        return !b.equals(a);
    }

    template <std::size_t N, detail::u64 Seed>
    bool operator!=(const obfuscated_string<N, Seed>& a, const char* b) noexcept
    {
        return !a.equals(b);
    }

    template <std::size_t N, detail::u64 Seed>
    bool operator!=(const char* a, const obfuscated_string<N, Seed>& b) noexcept
    {
        return !b.equals(a);
    }

    namespace detail
    {
        template <u64 Seed, std::size_t N>
        constexpr obfuscated_string<N, Seed> seal(const char (&txt)[N]) noexcept
        {
            return obfuscated_string<N, Seed>(txt);
        }
    }

    template <detail::u64 Seed, std::size_t N>
    constexpr obfuscated_string<N, Seed> make_obfuscated(const char (&txt)[N]) noexcept
    {
        return obfuscated_string<N, Seed>(txt);
    }

    template <std::size_t N, detail::u64 Seed>
    using crypt_str = obfuscated_string<N, Seed>;
}

#define TENZO_OBFUSCATE(txt)                                                        \
    []() -> const auto& {                                                           \
        static constexpr auto tenzo_sealed = ::tenzo::detail::seal<                  \
            ::tenzo::detail::seed_of(txt, __LINE__, __COUNTER__,                    \
                ::tenzo::detail::tick_hash(__TIME__))>(txt);                        \
        return tenzo_sealed;                                                        \
    }()

#define TENZO_AUTO(txt)                                                             \
    []() -> const char* {                                                           \
        static constexpr auto tenzo_sealed = ::tenzo::detail::seal<                  \
            ::tenzo::detail::seed_of(txt, __LINE__, __COUNTER__,                    \
                ::tenzo::detail::tick_hash(__TIME__))>(txt);                        \
        return tenzo_sealed;                                                        \
    }()
