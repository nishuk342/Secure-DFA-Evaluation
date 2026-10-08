#include <algorithm>
#include <cstdio>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "common.hpp"
#include "network.hpp"
#include "mpc_dpf.hpp"
#include "floram_mpc_aes.hpp"

using namespace mpcdpf;

static constexpr std::size_t STATE_BITS = 64;

struct ClientData {
    std::vector<std::uint64_t> blinded_db;
    std::vector<std::uint64_t> input_share;
    Block key{};
};

static void usage() {
    std::cout
        << "Usage:\n"
        << "  H : server.exe H <helper_port> <depth> <input_len>\n"
        << "  S1: server.exe S1 <s1_port> <helper_port> <client_port> <depth> <N> <alphabet_size>\n"
        << "  S2: server.exe S2 <s1_host> <s1_port> <helper_host> <helper_port> "
           "<client_port> <depth> <N> <alphabet_size>\n\n"
        << "Example (alphabet {0,1}, 8 DFA states => N=16):\n"
        << "  H 6000 4 5\n"
        << "  S1 5001 6000 7001 4 16 2\n"
        << "  S2 127.0.0.1 5001 127.0.0.1 6000 7002 4 16 2\n";
}

static ClientData receive_client_setup(SOCKET client,
                                       std::size_t expected_N,
                                       std::size_t expected_alphabet,
                                       std::size_t expected_depth) {
    if (net::recv_byte(client) != 'C')
        throw std::runtime_error("[Server] invalid client protocol marker");

    const std::size_t N = static_cast<std::size_t>(net::recv_u64(client));
    const std::size_t L = static_cast<std::size_t>(net::recv_u64(client));
    const std::size_t alphabet =
        static_cast<std::size_t>(net::recv_u64(client));

    if (N != expected_N)
        throw std::runtime_error("[Server] client N mismatch");
    if (alphabet != expected_alphabet)
        throw std::runtime_error("[Server] client alphabet size mismatch");
    if (alphabet == 0 || N % alphabet != 0)
        throw std::runtime_error("[Server] invalid N/alphabet size");

    const std::size_t domain = std::size_t{1} << expected_depth;
    if (N > domain)
        throw std::runtime_error("[Server] N exceeds DPF domain");

    ClientData data;
    data.blinded_db.resize(N);
    for (auto& x : data.blinded_db)
        x = net::recv_u64(client);

    data.key = net::recv_block(client);

    data.input_share.resize(L);
    for (auto& x : data.input_share)
        x = net::recv_u64(client);

    if (net::recv_byte(client) != 'D')
        throw std::runtime_error("[Server] client setup terminator missing");

    net::send_byte(client, 'A');
    return data;
}

static std::vector<std::uint64_t>
pad_database(const std::vector<std::uint64_t>& db, std::size_t domain) {
    std::vector<std::uint64_t> out(domain, 0);
    std::copy(db.begin(), db.end(), out.begin());
    return out;
}

static std::uint64_t open_offset(SOCKET peer, std::uint64_t my_d) {
    net::send_u64(peer, my_d);
    const std::uint64_t other_d = net::recv_u64(peer);
    return my_d + other_d;
}

static std::vector<std::uint8_t>
rotate_flag_share(const std::vector<std::uint8_t>& in,
                std::uint64_t offset) {
    if (in.empty())
        throw std::runtime_error("empty flag vector");

    const std::size_t n = in.size();
    std::vector<std::uint8_t> out(n, 0);
    const std::size_t d = static_cast<std::size_t>(offset % n);

    for (std::size_t i = 0; i < n; ++i)
        out[(i + d) % n] = in[i];

    return out;
}

// Because both servers hold the same FLORAM blinded database, each server
// locally XORs the words whose local flag share is 1. The XOR of the two
// local results is exactly DBbar[j].
static std::uint64_t pir_xor_u64(
    const std::vector<std::uint64_t>& blinded_db,
    const std::vector<std::uint8_t>& flag_share) {
    if (blinded_db.size() != flag_share.size())
        throw std::runtime_error("PIR database/flag size mismatch");

    std::uint64_t acc = 0;
    for (std::size_t i = 0; i < blinded_db.size(); ++i)
        if (flag_share[i])
            acc ^= blinded_db[i];
    return acc;
}

static void run_helper(std::uint16_t helper_port,
                       std::size_t depth,
                       std::size_t input_len) {
    SOCKET listener = net::listen_on(helper_port);
    std::cout << "[H] Listening on port " << helper_port << "\n";

    SOCKET s1 = INVALID_SOCKET;
    SOCKET s2 = INVALID_SOCKET;

    for (int i = 0; i < 2; ++i) {
        SOCKET s = net::accept_one(listener);
        const auto role = net::recv_byte(s);

        if (role == '1') s1 = s;
        else if (role == '2') s2 = s;
        else {
            net::close_socket(s);
            throw std::runtime_error("[H] invalid server role");
        }
    }

    if (s1 == INVALID_SOCKET || s2 == INVALID_SOCKET)
        throw std::runtime_error("[H] both servers did not connect");

    const std::size_t arithmetic_count =
        depth + STATE_BITS * input_len;

    constexpr std::size_t AES_ANDS_PER_AES = 10 * 16 * 32;
    constexpr std::size_t BOOL_TRIPLES_PER_STEP = 128 + 2 * AES_ANDS_PER_AES;
    const std::size_t bool_count = input_len * BOOL_TRIPLES_PER_STEP;

    std::cout << "[H] Sending " << 2 * depth
              << " DPF AND triples, " << arithmetic_count
              << " arithmetic triples, and " << bool_count
              << " secure-AES Boolean triples\n";

    helper_send_and_triples(s1, s2, depth);
    helper_send_arith_triples(s1, s2, arithmetic_count);
    floram_mpc::helper_send_boolbit_triples(s1, s2, bool_count);

    std::cout << "[H] Preprocessing complete. H never receives r1/r2.\n";

    net::close_socket(s1);
    net::close_socket(s2);
    net::close_socket(listener);
}

static void run_s1(std::uint16_t s1_port,
                   std::uint16_t helper_port,
                   std::uint16_t client_port,
                   std::size_t depth,
                   std::size_t N,
                   std::size_t alphabet_size) {
    SOCKET listener = net::listen_on(s1_port);
    SOCKET client_listener = net::listen_on(client_port);

    SOCKET helper = net::connect_retry("127.0.0.1", helper_port);
    net::send_byte(helper, '1');

    SOCKET peer = net::accept_one(listener);
    if (net::recv_byte(peer) != '2')
        throw std::runtime_error("[S1] expected S2");

    SOCKET client = net::accept_one(client_listener);
    ClientData data = receive_client_setup(
        client, N, alphabet_size, depth);

    const std::size_t L = data.input_share.size();

    const std::uint32_t h_depth = net::recv_u32(helper);
    if (h_depth != depth)
        throw std::runtime_error("[S1] depth mismatch");

    auto and_triples = receive_and_triples(helper, depth);

    const std::size_t expected_arith = depth + STATE_BITS * L;
    const std::uint32_t arith_count = net::recv_u32(helper);
    if (arith_count != expected_arith)
        throw std::runtime_error("[S1] arithmetic triple count mismatch");

    auto arith_triples = receive_arith_triples(helper, arith_count);
    auto bool_triples = floram_mpc::receive_boolbit_triples(helper);
    std::size_t bool_pos = 0;

    const std::size_t domain = std::size_t{1} << depth;
    auto blinded_db = pad_database(data.blinded_db, domain);

    const std::uint64_t r1 =
        random_u64() & static_cast<std::uint64_t>(domain - 1);

    net::send_byte(peer, 'R');
    if (net::recv_byte(peer) != 'R')
        throw std::runtime_error("[S1] S2 ready missing");

    // DPF target is r = r1 XOR r2; r is never reconstructed.
    auto key = generate_random_dpf(0, r1, depth, peer, and_triples);
    auto ev = evaluate_dpf(key);

    print_flag_vector("[S1] XOR flag share", ev.flags, domain);

    net::send_byte(peer, 'E');
    if (net::recv_byte(peer) != 'E')
        throw std::runtime_error("[S1] S2 evaluation ready missing");

    MpcArithParty64 arith(0, peer, arith_triples);

    // First 'depth' arithmetic triples are reserved for r conversion.
    const auto rA = convert_dummy_index_xor_to_additive(
        0, r1, depth, arith);

    net::send_byte(peer, 'D');
    if (net::recv_byte(peer) != 'D')
        throw std::runtime_error("[S1] S2 dummy-index conversion missing");

    // q_0 = 0 is public, so both additive state shares start at zero.
    std::uint64_t q_share = 0;

    for (std::size_t step = 0; step < L; ++step) {
        // j = |Sigma| * q + x.
        const std::uint64_t j_share =
            q_share * static_cast<std::uint64_t>(alphabet_size)
            + data.input_share[step];

        // d = j - r. d is intentionally opened for the circular rotation.
        const std::uint64_t d_share = j_share - rA.share;
        const std::uint64_t d = open_offset(peer, d_share);

        const auto rotated = rotate_flag_share(ev.flags, d);
        const std::uint64_t pir_share =
            pir_xor_u64(blinded_db, rotated);

        const std::uint64_t mask_share = floram_mpc::secure_mask_share(
            0, peer, j_share, data.key, bool_triples, bool_pos);

        // D[j] = DBbar[j] XOR M.
        const std::uint64_t next_state_xor_share =
            pir_share ^ mask_share;

        // Reserve 64 arithmetic triples per transition for this conversion.
        const std::size_t triple_base =
            depth + step * STATE_BITS;
        const auto next_state_add = convert_xor_u64_to_additive(
            0, next_state_xor_share, arith, triple_base);

        q_share = next_state_add.share;
    }

    // Final DFA state is intentionally reconstructed.
    net::send_u64(peer, q_share);
    const std::uint64_t q_other = net::recv_u64(peer);
    const std::uint64_t final_state = q_share + q_other;

    std::cout << "[S1] Final DFA state = " << final_state << "\n";

    net::close_socket(client);
    net::close_socket(peer);
    net::close_socket(helper);
    net::close_socket(client_listener);
    net::close_socket(listener);
}

static void run_s2(const std::string& s1_host,
                   std::uint16_t s1_port,
                   const std::string& helper_host,
                   std::uint16_t helper_port,
                   std::uint16_t client_port,
                   std::size_t depth,
                   std::size_t N,
                   std::size_t alphabet_size) {
    SOCKET helper = net::connect_retry(helper_host, helper_port);
    net::send_byte(helper, '2');

    SOCKET peer = net::connect_retry(s1_host, s1_port);
    net::send_byte(peer, '2');

    SOCKET client_listener = net::listen_on(client_port);
    SOCKET client = net::accept_one(client_listener);

    ClientData data = receive_client_setup(
        client, N, alphabet_size, depth);

    const std::size_t L = data.input_share.size();

    const std::uint32_t h_depth = net::recv_u32(helper);
    if (h_depth != depth)
        throw std::runtime_error("[S2] depth mismatch");

    auto and_triples = receive_and_triples(helper, depth);

    const std::size_t expected_arith = depth + STATE_BITS * L;
    const std::uint32_t arith_count = net::recv_u32(helper);
    if (arith_count != expected_arith)
        throw std::runtime_error("[S2] arithmetic triple count mismatch");

    auto arith_triples = receive_arith_triples(helper, arith_count);
    auto bool_triples = floram_mpc::receive_boolbit_triples(helper);
    std::size_t bool_pos = 0;

    const std::size_t domain = std::size_t{1} << depth;
    auto blinded_db = pad_database(data.blinded_db, domain);

    const std::uint64_t r2 =
        random_u64() & static_cast<std::uint64_t>(domain - 1);

    if (net::recv_byte(peer) != 'R')
        throw std::runtime_error("[S2] S1 ready missing");
    net::send_byte(peer, 'R');

    auto key = generate_random_dpf(1, r2, depth, peer, and_triples);
    auto ev = evaluate_dpf(key);

    print_flag_vector("[S2] XOR flag share", ev.flags, domain);

    if (net::recv_byte(peer) != 'E')
        throw std::runtime_error("[S2] S1 evaluation ready missing");
    net::send_byte(peer, 'E');

    MpcArithParty64 arith(1, peer, arith_triples);
    const auto rA = convert_dummy_index_xor_to_additive(
        1, r2, depth, arith);

    if (net::recv_byte(peer) != 'D')
        throw std::runtime_error("[S2] S1 dummy-index conversion missing");
    net::send_byte(peer, 'D');

    std::uint64_t q_share = 0;

    for (std::size_t step = 0; step < L; ++step) {
        const std::uint64_t j_share =
            q_share * static_cast<std::uint64_t>(alphabet_size)
            + data.input_share[step];

        const std::uint64_t d_share = j_share - rA.share;
        const std::uint64_t d = open_offset(peer, d_share);

        const auto rotated = rotate_flag_share(ev.flags, d);
        const std::uint64_t pir_share =
            pir_xor_u64(blinded_db, rotated);

        const std::uint64_t mask_share = floram_mpc::secure_mask_share(
            1, peer, j_share, data.key, bool_triples, bool_pos);

        const std::uint64_t next_state_xor_share =
            pir_share ^ mask_share;

        const std::size_t triple_base =
            depth + step * STATE_BITS;
        const auto next_state_add = convert_xor_u64_to_additive(
            1, next_state_xor_share, arith, triple_base);

        q_share = next_state_add.share;
    }

    net::send_u64(peer, q_share);
    const std::uint64_t q_other = net::recv_u64(peer);
    const std::uint64_t final_state = q_share + q_other;

    std::cout << "[S2] Final DFA state = " << final_state << "\n";

    net::close_socket(client);
    net::close_socket(client_listener);
    net::close_socket(peer);
    net::close_socket(helper);
}

int main(int argc, char** argv) {
    try {
        net::WinsockInit winsock;
        if (argc < 2) {
            usage();
            return 1;
        }

        const std::string role = argv[1];

        if (role == "H") {
            if (argc != 5) {
                usage();
                return 1;
            }

            run_helper(
                static_cast<std::uint16_t>(std::stoi(argv[2])),
                static_cast<std::size_t>(std::stoul(argv[3])),
                static_cast<std::size_t>(std::stoul(argv[4])));
        } else if (role == "S1") {
            if (argc != 8) {
                usage();
                return 1;
            }

            run_s1(
                static_cast<std::uint16_t>(std::stoi(argv[2])),
                static_cast<std::uint16_t>(std::stoi(argv[3])),
                static_cast<std::uint16_t>(std::stoi(argv[4])),
                static_cast<std::size_t>(std::stoul(argv[5])),
                static_cast<std::size_t>(std::stoul(argv[6])),
                static_cast<std::size_t>(std::stoul(argv[7])));
        } else if (role == "S2") {
            if (argc != 10) {
                usage();
                return 1;
            }

            run_s2(
                argv[2],
                static_cast<std::uint16_t>(std::stoi(argv[3])),
                argv[4],
                static_cast<std::uint16_t>(std::stoi(argv[5])),
                static_cast<std::uint16_t>(std::stoi(argv[6])),
                static_cast<std::size_t>(std::stoul(argv[7])),
                static_cast<std::size_t>(std::stoul(argv[8])),
                static_cast<std::size_t>(std::stoul(argv[9])));
        } else {
            usage();
            return 1;
        }

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << "\n";
        return 1;
    }
}
