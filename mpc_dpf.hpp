#pragma once

#include <cstdint>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "common.hpp"
#include "network.hpp"

namespace mpcdpf {

// -----------------------------------------------------------------------------
// DPF preprocessing triples
// -----------------------------------------------------------------------------

struct AndTriple {
    Block X{};
    Block Y{};
    Block Z{};
};

// Du-Atallah AND triples over {0,1}^128 used by DPF generation.
inline void helper_send_and_triples(SOCKET s1, SOCKET s2, std::size_t depth) {
    net::send_u32(s1, static_cast<std::uint32_t>(depth));
    net::send_u32(s2, static_cast<std::uint32_t>(depth));

    const std::size_t count = 2 * depth;
    for (std::size_t k = 0; k < count; ++k) {
        const Block X0 = random_block();
        const Block X1 = random_block();
        const Block Y0 = random_block();
        const Block Y1 = random_block();
        const Block T  = random_block();

        const Block Z0 = xor_block(and_block(X0, Y1), T);
        const Block Z1 = xor_block(and_block(X1, Y0), T);

        net::send_block(s1, X0);
        net::send_block(s1, Y0);
        net::send_block(s1, Z0);

        net::send_block(s2, X1);
        net::send_block(s2, Y1);
        net::send_block(s2, Z1);
    }
}

inline std::vector<AndTriple> receive_and_triples(SOCKET helper,
                                                   std::size_t depth) {
    const std::size_t count = 2 * depth;
    std::vector<AndTriple> triples(count);

    for (auto& t : triples) {
        t.X = net::recv_block(helper);
        t.Y = net::recv_block(helper);
        t.Z = net::recv_block(helper);
    }

    return triples;
}

// -----------------------------------------------------------------------------
// Arithmetic triples over Z_(2^64)
//
// These are standard additive Beaver triples:
//   X = X0 + X1, Y = Y0 + Y1, Z = X*Y = Z0 + Z1 mod 2^64.
// They are used for converting XOR-shared values (dummy index and DFA state)
// into additive shares.
// -----------------------------------------------------------------------------

struct ArithTriple64 {
    std::uint64_t X = 0;
    std::uint64_t Y = 0;
    std::uint64_t Z = 0;
};

inline void helper_send_arith_triples(SOCKET s1,
                                      SOCKET s2,
                                      std::size_t count) {
    net::send_u32(s1, static_cast<std::uint32_t>(count));
    net::send_u32(s2, static_cast<std::uint32_t>(count));

    for (std::size_t k = 0; k < count; ++k) {
        const std::uint64_t X0 = random_u64();
        const std::uint64_t X1 = random_u64();
        const std::uint64_t Y0 = random_u64();
        const std::uint64_t Y1 = random_u64();

        const std::uint64_t X = X0 + X1;
        const std::uint64_t Y = Y0 + Y1;
        const std::uint64_t Z = X * Y;

        const std::uint64_t Z0 = random_u64();
        const std::uint64_t Z1 = Z - Z0;

        net::send_u64(s1, X0);
        net::send_u64(s1, Y0);
        net::send_u64(s1, Z0);

        net::send_u64(s2, X1);
        net::send_u64(s2, Y1);
        net::send_u64(s2, Z1);
    }
}

inline std::vector<ArithTriple64>
receive_arith_triples(SOCKET helper, std::size_t count) {
    std::vector<ArithTriple64> triples(count);

    for (auto& t : triples) {
        t.X = net::recv_u64(helper);
        t.Y = net::recv_u64(helper);
        t.Z = net::recv_u64(helper);
    }

    return triples;
}

/*
 * 2-party MPC AND using the Du-Atallah-style triples above.
 * The result is reconstructed because DPF correction words must be identical
 * at both servers.
 */
class MpcAndParty {
public:
    MpcAndParty(int party_id, SOCKET peer, std::vector<AndTriple> triples)
        : party_id_(party_id), peer_(peer), triples_(std::move(triples)) {}

    Block and_bit_word_public(std::uint8_t x_share,
                              const Block& y_share,
                              std::size_t triple_index) {
        if (triple_index >= triples_.size())
            throw std::runtime_error("AND triple index out of range");

        const auto& tr = triples_[triple_index];
        const Block xb = repeat_bit(x_share);
        const Block dx = xor_block(xb, tr.X);
        const Block dy = xor_block(y_share, tr.Y);

        net::send_block(peer_, dx);
        net::send_block(peer_, dy);
        const Block dx_other = net::recv_block(peer_);
        const Block dy_other = net::recv_block(peer_);

        const Block z_share = xor_block(
            and_block(xb, xor_block(y_share, dy_other)),
            xor_block(and_block(tr.Y, dx_other), tr.Z)
        );

        net::send_block(peer_, z_share);
        const Block z_other = net::recv_block(peer_);
        return xor_block(z_share, z_other);
    }

private:
    int party_id_;
    SOCKET peer_;
    std::vector<AndTriple> triples_;
};

// Scalar multiplication over Z_(2^64) using standard Beaver triples.
class MpcArithParty64 {
public:
    MpcArithParty64(int party_id,
                    SOCKET peer,
                    std::vector<ArithTriple64> triples)
        : party_id_(party_id), peer_(peer), triples_(std::move(triples)) {}

    // x = x0 + x1, y = y0 + y1 (mod 2^64).
    // Returns z_b such that z0 + z1 = x*y (mod 2^64).
    std::uint64_t multiply(std::uint64_t x_share,
                           std::uint64_t y_share,
                           std::size_t triple_index) {
        if (triple_index >= triples_.size())
            throw std::runtime_error("arithmetic triple index out of range");

        const auto& tr = triples_[triple_index];

        // Open d = x-X and e = y-Y.
        const std::uint64_t d = x_share - tr.X;
        const std::uint64_t e = y_share - tr.Y;

        net::send_u64(peer_, d);
        net::send_u64(peer_, e);
        const std::uint64_t d_other = net::recv_u64(peer_);
        const std::uint64_t e_other = net::recv_u64(peer_);

        const std::uint64_t d_open = d + d_other;
        const std::uint64_t e_open = e + e_other;

        std::uint64_t z = tr.Z
                        + d_open * tr.Y
                        + e_open * tr.X;

        // Add the public d*e term to exactly one party's share.
        if (party_id_ == 0)
            z += d_open * e_open;

        return z;
    }

private:
    int party_id_;
    SOCKET peer_;
    std::vector<ArithTriple64> triples_;
};

// -----------------------------------------------------------------------------
// [G] MPC DPF generation
// -----------------------------------------------------------------------------

struct DpfKeyWithoutFinalCorrection {
    Block root{};
    std::vector<Block> correction_words;
    std::vector<std::uint8_t> cwt_left;
    std::vector<std::uint8_t> cwt_right;
};

// The XOR-shared target r = r1 XOR r2 is never reconstructed.
inline DpfKeyWithoutFinalCorrection
 generate_random_dpf(int party_id,
                     std::uint64_t index_share,
                     std::size_t depth,
                     SOCKET peer,
                     const std::vector<AndTriple>& triples) {
    if (depth == 0)
        throw std::runtime_error("depth must be > 0");
    if (triples.size() != 2 * depth)
        throw std::runtime_error("Need exactly 2 AND triples per DPF level");

    Block root = random_block();
    set_lsb(root, static_cast<std::uint8_t>(party_id));

    std::vector<Block> nodes{root};
    std::vector<std::uint8_t> flags{lsb(root)};

    DpfKeyWithoutFinalCorrection key;
    key.root = root;
    key.correction_words.reserve(depth);
    key.cwt_left.reserve(depth);
    key.cwt_right.reserve(depth);

    MpcAndParty and_mpc(party_id, peer, triples);

    for (std::size_t level = 0; level < depth; ++level) {
        const std::size_t node_count = nodes.size();
        std::vector<Block> next(2 * node_count);

        for (std::size_t i = 0; i < node_count; ++i) {
            const auto [left, right] = prg_expand(nodes[i]);
            next[2 * i] = left;
            next[2 * i + 1] = right;
        }

        Block L{};
        Block R{};
        for (std::size_t i = 0; i < node_count; ++i) {
            xor_inplace(L, next[2 * i]);
            xor_inplace(R, next[2 * i + 1]);
        }

        const std::uint8_t ib = get_index_bit(index_share, level, depth);

        const Block left_product =
            and_mpc.and_bit_word_public(ib, L, 2 * level);

        const std::uint8_t complement_share =
            (party_id == 0) ? static_cast<std::uint8_t>(ib ^ 1U) : ib;

        const Block right_product =
            and_mpc.and_bit_word_public(complement_share, R, 2 * level + 1);

        const Block cw = xor_block(left_product, right_product);

        const std::uint8_t cwtL_share =
            static_cast<std::uint8_t>(lsb(L) ^ ib);
        const std::uint8_t cwtR_share =
            static_cast<std::uint8_t>(lsb(R) ^ ib);

        net::send_byte(peer, cwtL_share);
        net::send_byte(peer, cwtR_share);
        const std::uint8_t cwtL_other = net::recv_byte(peer);
        const std::uint8_t cwtR_other = net::recv_byte(peer);

        const std::uint8_t cwtL =
            static_cast<std::uint8_t>(cwtL_share ^ cwtL_other ^ 1U);
        const std::uint8_t cwtR =
            static_cast<std::uint8_t>(cwtR_share ^ cwtR_other);

        std::vector<std::uint8_t> next_flags(2 * node_count);
        for (std::size_t i = 0; i < node_count; ++i) {
            next_flags[2 * i] =
                static_cast<std::uint8_t>(lsb(next[2 * i]) ^
                    (flags[i] & cwtL));
            next_flags[2 * i + 1] =
                static_cast<std::uint8_t>(lsb(next[2 * i + 1]) ^
                    (flags[i] & cwtR));
        }

        for (std::size_t i = 0; i < node_count; ++i) {
            if (flags[i]) {
                xor_inplace(next[2 * i], cw);
                xor_inplace(next[2 * i + 1], cw);
            }
        }

        key.correction_words.push_back(cw);
        key.cwt_left.push_back(cwtL);
        key.cwt_right.push_back(cwtR);

        nodes.swap(next);
        flags.swap(next_flags);
    }

    return key;
}

// -----------------------------------------------------------------------------
// [H] DPF evaluation
// -----------------------------------------------------------------------------

// FLORAM only needs the XOR-shared flag vector. The DPF labels/word sums that
// were previously used for DUORAM's XOR->additive flag conversion are removed.
struct EvaluatedDpf {
    std::vector<std::uint8_t> flags; // t_b
};

inline EvaluatedDpf evaluate_dpf(const DpfKeyWithoutFinalCorrection& key) {
    const std::size_t depth = key.correction_words.size();
    if (key.cwt_left.size() != depth || key.cwt_right.size() != depth)
        throw std::runtime_error("Malformed DPF key");

    std::vector<Block> nodes{key.root};
    std::vector<std::uint8_t> flags{lsb(key.root)};

    for (std::size_t level = 0; level < depth; ++level) {
        const std::size_t node_count = nodes.size();
        std::vector<Block> next(2 * node_count);
        std::vector<std::uint8_t> next_flags(2 * node_count);

        for (std::size_t i = 0; i < node_count; ++i) {
            const auto [left, right] = prg_expand(nodes[i]);
            next[2 * i] = left;
            next[2 * i + 1] = right;

            next_flags[2 * i] =
                static_cast<std::uint8_t>(lsb(left) ^
                    (flags[i] & key.cwt_left[level]));
            next_flags[2 * i + 1] =
                static_cast<std::uint8_t>(lsb(right) ^
                    (flags[i] & key.cwt_right[level]));

            if (flags[i]) {
                xor_inplace(next[2 * i], key.correction_words[level]);
                xor_inplace(next[2 * i + 1], key.correction_words[level]);
            }
        }

        nodes.swap(next);
        flags.swap(next_flags);
    }

    return {std::move(flags)};
}

// -----------------------------------------------------------------------------
// [I] XOR-shared dummy index -> additive-shared dummy index
// -----------------------------------------------------------------------------

struct AdditiveIndexShare {
    std::uint64_t share = 0;
};

/*
 * Convert
 *
 *       r = r1 XOR r2
 *
 * into additive shares
 *
 *       r = r1A + r2A (mod 2^64).
 *
 * For integers,
 *
 *       x XOR y = x + y - 2(x AND y)       (mod 2^64).
 *
 * The parties therefore compute the bitwise AND r1 AND r2 securely.
 * For bit k, r1[k] is supplied as an additive share (r1[k], 0) and
 * r2[k] as (0, r2[k]). The standard arithmetic Beaver multiplication
 * returns additive shares c_k = r1[k] * r2[k]. These shares are packed
 * into an additive share of C = r1 AND r2.
 *
 * Finally:
 *
 *       r1A = r1 - 2*C1
 *       r2A = r2 - 2*C2.
 *
 * No flag vector is converted to additive shares, and r itself is never
 * reconstructed.
 */
inline AdditiveIndexShare
convert_dummy_index_xor_to_additive(int party_id,
                                    std::uint64_t index_share,
                                    std::size_t depth,
                                    MpcArithParty64& arith_mpc) {
    if (depth == 0 || depth > 64)
        throw std::runtime_error("Invalid index depth");

    std::uint64_t and_share = 0;

    for (std::size_t bit = 0; bit < depth; ++bit) {
        const std::uint64_t bit_value =
            (index_share >> bit) & 1ULL;

        // r1 = local share at S1 and 0 at S2;
        // r2 = 0 at S1 and local share at S2.
        const std::uint64_t x_share =
            (party_id == 0) ? bit_value : 0ULL;
        const std::uint64_t y_share =
            (party_id == 1) ? bit_value : 0ULL;

        const std::uint64_t c_share =
            arith_mpc.multiply(x_share, y_share, bit);

        and_share += (std::uint64_t{1} << bit) * c_share;
    }

    // r = r1 + r2 - 2*(r1 & r2) mod 2^64.
    const std::uint64_t additive_share =
        index_share - 2ULL * and_share;

    return {additive_share};
}


// -----------------------------------------------------------------------------
// XOR-shared 64-bit word -> additive-shared 64-bit word
// -----------------------------------------------------------------------------

/*
 * Convert x = x0 XOR x1 into additive shares over Z_(2^64):
 *
 *     x = x0 + x1 - 2*(x0 AND x1).
 *
 * The 64 AND products are evaluated with Beaver triples.  The caller must
 * reserve 64 consecutive arithmetic triples starting at triple_base.
 * The XOR value x itself is never reconstructed.
 */
inline AdditiveIndexShare
convert_xor_u64_to_additive(int party_id,
                            std::uint64_t x_share,
                            MpcArithParty64& arith_mpc,
                            std::size_t triple_base) {
    std::uint64_t and_share = 0;

    for (std::size_t bit = 0; bit < 64; ++bit) {
        const std::uint64_t b = (x_share >> bit) & 1ULL;
        const std::uint64_t x0 = (party_id == 0) ? b : 0ULL;
        const std::uint64_t x1 = (party_id == 1) ? b : 0ULL;
        const std::uint64_t c = arith_mpc.multiply(
            x0, x1, triple_base + bit);
        and_share += (std::uint64_t{1} << bit) * c;
    }

    return {x_share - 2ULL * and_share};
}

// -----------------------------------------------------------------------------
// Debug/output helpers
// -----------------------------------------------------------------------------

inline void save_key(const std::string& filename,
                     int party_id,
                     const DpfKeyWithoutFinalCorrection& key) {
    std::ofstream out(filename, std::ios::binary);
    if (!out)
        throw std::runtime_error("Cannot open " + filename);

    const std::uint32_t magic = 0x4D445046; // MDPF
    const std::uint32_t version = 3;
    const std::uint32_t depth =
        static_cast<std::uint32_t>(key.correction_words.size());

    out.write(reinterpret_cast<const char*>(&magic), sizeof(magic));
    out.write(reinterpret_cast<const char*>(&version), sizeof(version));
    out.write(reinterpret_cast<const char*>(&party_id), sizeof(party_id));
    out.write(reinterpret_cast<const char*>(&depth), sizeof(depth));
    out.write(reinterpret_cast<const char*>(key.root.data()), key.root.size());

    for (std::size_t i = 0; i < depth; ++i) {
        out.write(reinterpret_cast<const char*>(key.correction_words[i].data()),
                  key.correction_words[i].size());
        out.write(reinterpret_cast<const char*>(&key.cwt_left[i]), 1);
        out.write(reinterpret_cast<const char*>(&key.cwt_right[i]), 1);
    }

    if (!out)
        throw std::runtime_error("Error writing " + filename);
}

inline void print_flag_vector(const std::string& name,
                              const std::vector<std::uint8_t>& flags,
                              std::size_t logical_n) {
    std::cout << name << " = [ ";
    const std::size_t n = std::min(logical_n, flags.size());
    for (std::size_t i = 0; i < n; ++i)
        std::cout << static_cast<unsigned>(flags[i])
                  << (i + 1 == n ? "" : " ");
    std::cout << " ]\n";
}

} // namespace mpcdpf
