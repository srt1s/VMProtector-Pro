#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>

namespace vmp::crypto {

inline constexpr uint32_t rotl32(uint32_t v, int n) noexcept {
    return (v << n) | (v >> (32 - n));
}

inline constexpr uint64_t rotl64(uint64_t v, int n) noexcept {
    return (v << n) | (v >> (64 - n));
}

inline constexpr uint64_t rotr64(uint64_t v, int n) noexcept {
    return (v >> n) | (v << (64 - n));
}

inline uint32_t load32_le(const uint8_t* p) noexcept {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

inline void store32_le(uint8_t* p, uint32_t v) noexcept {
    p[0] = static_cast<uint8_t>(v & 0xFF);
    p[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    p[2] = static_cast<uint8_t>((v >> 16) & 0xFF);
    p[3] = static_cast<uint8_t>((v >> 24) & 0xFF);
}

inline void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) noexcept {
    a += b; d ^= a; d = rotl32(d, 16);
    c += d; b ^= c; b = rotl32(b, 12);
    a += b; d ^= a; d = rotl32(d, 8);
    c += d; b ^= c; b = rotl32(b, 7);
}

inline void chacha20_block(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12], uint8_t out[64]) noexcept {
    uint32_t s[16]{
        0x61707865u, 0x3320646Eu, 0x79622D32u, 0x6B206574u,
        load32_le(key + 0),  load32_le(key + 4),  load32_le(key + 8),  load32_le(key + 12),
        load32_le(key + 16), load32_le(key + 20), load32_le(key + 24), load32_le(key + 28),
        counter,
        load32_le(nonce + 0), load32_le(nonce + 4), load32_le(nonce + 8)
    };

    uint32_t w[16];
    for (int i = 0; i < 16; ++i) w[i] = s[i];

    for (int i = 0; i < 10; ++i) {
        quarter_round(w[0], w[4], w[8],  w[12]);
        quarter_round(w[1], w[5], w[9],  w[13]);
        quarter_round(w[2], w[6], w[10], w[14]);
        quarter_round(w[3], w[7], w[11], w[15]);
        quarter_round(w[0], w[5], w[10], w[15]);
        quarter_round(w[1], w[6], w[11], w[12]);
        quarter_round(w[2], w[7], w[8],  w[13]);
        quarter_round(w[3], w[4], w[9],  w[14]);
    }

    for (int i = 0; i < 16; ++i) {
        store32_le(out + i * 4, w[i] + s[i]);
    }
}

inline void chacha20_xor(const uint8_t key[32], const uint8_t nonce[12], uint32_t initialCounter,
                         const uint8_t* in, uint8_t* out, size_t len) noexcept {
    uint8_t keystream[64]{};
    uint32_t counter = initialCounter;
    size_t offset = 0;

    while (offset < len) {
        chacha20_block(key, counter++, nonce, keystream);
        size_t chunk = len - offset;
        if (chunk > 64) chunk = 64;
        for (size_t i = 0; i < chunk; ++i) {
            out[offset + i] = in[offset + i] ^ keystream[i];
        }
        offset += chunk;
    }

    volatile uint8_t* p = keystream;
    for (size_t i = 0; i < sizeof(keystream); ++i) p[i] = 0;
}

inline constexpr uint64_t fnv1a64(const char* s) noexcept {
    uint64_t h = 0xCBF29CE484222325ULL;
    while (*s) {
        h ^= static_cast<uint8_t>(*s++);
        h *= 0x100000001B3ULL;
    }
    return h;
}

inline constexpr uint64_t fnv1a64_icase_w(const wchar_t* s, size_t charCount) noexcept {
    uint64_t h = 0xCBF29CE484222325ULL;
    for (size_t i = 0; i < charCount; ++i) {
        wchar_t ch = s[i];
        if (ch >= L'A' && ch <= L'Z') ch += (L'a' - L'A');
        h ^= static_cast<uint8_t>(ch & 0xFF);
        h *= 0x100000001B3ULL;
    }
    return h;
}

inline uint32_t crc32_ieee(const uint8_t* data, size_t len) noexcept {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (int b = 0; b < 8; ++b) {
            uint32_t mask = static_cast<uint32_t>(-static_cast<int32_t>(crc & 1u));
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

} // namespace vmp::crypto
