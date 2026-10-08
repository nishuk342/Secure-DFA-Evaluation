#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/aes.h>
#include <openssl/rand.h>

namespace mpcdpf {

using Block = std::array<std::uint8_t, 16>;

inline Block xor_block(const Block& a, const Block& b) {
    Block r{};
    for (std::size_t i = 0; i < r.size(); ++i) r[i] = a[i] ^ b[i];
    return r;
}

inline void xor_inplace(Block& a, const Block& b) {
    for (std::size_t i = 0; i < a.size(); ++i) a[i] ^= b[i];
}

inline Block and_block(const Block& a, const Block& b) {
    Block r{};
    for (std::size_t i = 0; i < r.size(); ++i) r[i] = a[i] & b[i];
    return r;
}

inline std::uint8_t lsb(const Block& x) {
    return static_cast<std::uint8_t>(x[0] & 1U);
}

inline void set_lsb(Block& x, std::uint8_t bit) {
    x[0] = static_cast<std::uint8_t>((x[0] & 0xFEU) | (bit & 1U));
}

inline Block repeat_bit(std::uint8_t bit) {
    Block r{};
    std::memset(r.data(), bit ? 0xFF : 0x00, r.size());
    return r;
}

inline Block random_block() {
    Block r{};
    if (RAND_bytes(r.data(), static_cast<int>(r.size())) != 1)
        throw std::runtime_error("RAND_bytes failed");
    return r;
}

inline std::uint64_t random_u64() {
    std::uint64_t x = 0;
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&x), sizeof(x)) != 1)
        throw std::runtime_error("RAND_bytes failed");
    return x;
}

/*
 * Length-doubling PRG:
 *
 *   G(s) = (G_L(s), G_R(s))
 *
 * This implementation uses AES-128 in a Davies-Meyer style construction
 * with two domain-separated public input blocks. The FLORAM/DUORAM
 * algorithm only requires a secure length-doubling PRG; this concrete
 * AES instantiation is an implementation choice.
 */
inline std::pair<Block, Block> prg_expand(const Block& seed) {
    AES_KEY aes_key{};
    if (AES_set_encrypt_key(seed.data(), 128, &aes_key) != 0)
        throw std::runtime_error("AES_set_encrypt_key failed");

    Block in_l{};
    Block in_r{};
    in_r[15] = 1;

    Block out_l{};
    Block out_r{};
    AES_encrypt(in_l.data(), out_l.data(), &aes_key);
    AES_encrypt(in_r.data(), out_r.data(), &aes_key);

    for (std::size_t i = 0; i < 16; ++i) {
        out_l[i] ^= in_l[i];
        out_r[i] ^= in_r[i];
    }

    return {out_l, out_r};
}

inline std::uint8_t get_index_bit(std::uint64_t share,
                                   std::size_t level,
                                   std::size_t depth) {
    // The DPF tree consumes the target bits from MSB to LSB.
    const std::size_t shift = depth - 1 - level;
    return static_cast<std::uint8_t>((share >> shift) & 1ULL);
}

inline std::uint64_t block_to_u64(const Block& x) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
        v |= static_cast<std::uint64_t>(x[i]) << (8 * i);
    return v;
}

inline std::string hex(const Block& x) {
    static constexpr char h[] = "0123456789abcdef";
    std::string s;
    s.reserve(32);
    for (auto b : x) {
        s.push_back(h[(b >> 4) & 0xF]);
        s.push_back(h[b & 0xF]);
    }
    return s;
}

} // namespace mpcdpf
