#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "common.hpp"
#include "network.hpp"

using namespace mpcdpf;

static std::vector<std::uint64_t>
read_transition_table(const std::string& filename) {
    std::ifstream in(filename);
    if (!in)
        throw std::runtime_error("cannot open transition table: " + filename);

    std::vector<std::uint64_t> table;
    std::uint64_t x = 0;
    while (in >> x)
        table.push_back(x);

    if (table.empty())
        throw std::runtime_error("transition table is empty");

    return table;
}

// Must exactly match the secure Obliv-C unmasker.
//
// FLORAM's scan ROM constructs an IV whose final sizeof(size_t) bytes contain
// the block index in big-endian order. For one 64-bit DFA word we use:
//
//     IV = 0000000000000000 || BE64(index)
//     F(k,index) = first 8 bytes of AES-128_k(IV)
//
static std::uint64_t prf_u64(const Block& key, std::uint64_t index) {
    AES_KEY aes_key{};
    if (AES_set_encrypt_key(key.data(), 128, &aes_key) != 0)
        throw std::runtime_error("AES_set_encrypt_key failed");

    Block iv{};
    for (int i = 0; i < 8; ++i)
        iv[8 + i] = static_cast<std::uint8_t>(
            index >> (56 - 8 * i));

    Block out{};
    AES_encrypt(iv.data(), out.data(), &aes_key);
    return block_to_u64(out);
}

static void send_database(SOCKET s,
                          const std::vector<std::uint64_t>& db) {
    for (auto x : db)
        net::send_u64(s, x);
}

static void send_input_share(SOCKET s,
                             const std::vector<std::uint64_t>& share) {
    for (auto x : share)
        net::send_u64(s, x);
}

static void usage() {
    std::cout
        << "Usage:\n"
        << "  client.exe <s1_host> <s1_client_port> "
           "<s2_host> <s2_client_port> <transition_table.txt> "
           "<input_string> <alphabet_size>\n\n"
        << "Example:\n"
        << "  client.exe 127.0.0.1 7001 127.0.0.1 7002 "
           "transition.txt 10110 2\n";
}

int main(int argc, char** argv) {
    try {
        net::WinsockInit winsock;

        if (argc != 8) {
            usage();
            return 1;
        }

        const std::string s1_host = argv[1];
        const std::uint16_t s1_port =
            static_cast<std::uint16_t>(std::stoi(argv[2]));

        const std::string s2_host = argv[3];
        const std::uint16_t s2_port =
            static_cast<std::uint16_t>(std::stoi(argv[4]));

        const std::string table_file = argv[5];
        const std::string input = argv[6];
        const std::size_t alphabet_size =
            static_cast<std::size_t>(std::stoul(argv[7]));

        if (alphabet_size == 0)
            throw std::runtime_error("alphabet_size must be positive");

        const auto table = read_transition_table(table_file);
        if (table.size() % alphabet_size != 0)
            throw std::runtime_error(
                "transition table size must be divisible by alphabet_size");

        const std::size_t state_count = table.size() / alphabet_size;

        for (char c : input) {
            if (c < '0' || c > '9')
                throw std::runtime_error(
                    "input_string must use decimal alphabet symbols 0-9");

            const std::size_t symbol = static_cast<std::size_t>(c - '0');
            if (symbol >= alphabet_size)
                throw std::runtime_error(
                    "input symbol is outside the configured alphabet");
        }

        for (std::size_t i = 0; i < table.size(); ++i) {
            if (table[i] >= state_count)
                throw std::runtime_error(
                    "transition table contains an invalid next-state value at index " +
                    std::to_string(i));
        }

        // Two independent AES keys. S1 receives only k0; S2 receives only k1.
        const Block k0 = random_block();
        const Block k1 = random_block();

        // FLORAM-style read-only blinded database:
        //
        //   DBbar[i] = DB[i] XOR F(k0,i) XOR F(k1,i).
        std::vector<std::uint64_t> blinded_db(table.size());
        for (std::size_t i = 0; i < table.size(); ++i) {
            blinded_db[i] =
                table[i] ^ prf_u64(k0, i) ^ prf_u64(k1, i);
        }

        // Additive input sharing over Z_(2^64): x = x1 + x2.
        std::vector<std::uint64_t> input_s1(input.size());
        std::vector<std::uint64_t> input_s2(input.size());

        for (std::size_t i = 0; i < input.size(); ++i) {
            const std::uint64_t x =
                static_cast<std::uint64_t>(input[i] - '0');
            input_s1[i] = random_u64();
            input_s2[i] = x - input_s1[i];
        }

        SOCKET s1 = net::connect_retry(s1_host, s1_port);
        SOCKET s2 = net::connect_retry(s2_host, s2_port);

        // Header.
        net::send_byte(s1, 'C');
        net::send_byte(s2, 'C');

        // Public metadata.
        net::send_u64(s1, static_cast<std::uint64_t>(table.size()));
        net::send_u64(s2, static_cast<std::uint64_t>(table.size()));

        net::send_u64(s1, static_cast<std::uint64_t>(input.size()));
        net::send_u64(s2, static_cast<std::uint64_t>(input.size()));

        net::send_u64(s1, static_cast<std::uint64_t>(alphabet_size));
        net::send_u64(s2, static_cast<std::uint64_t>(alphabet_size));

        // Both servers receive the same FLORAM blinded database.
        send_database(s1, blinded_db);
        send_database(s2, blinded_db);

        // Each server receives only its own AES key.
        net::send_block(s1, k0);
        net::send_block(s2, k1);

        // Each server receives only its own additive input shares.
        send_input_share(s1, input_s1);
        send_input_share(s2, input_s2);

        net::send_byte(s1, 'D');
        net::send_byte(s2, 'D');

        if (net::recv_byte(s1) != 'A')
            throw std::runtime_error("S1 setup acknowledgement failed");
        if (net::recv_byte(s2) != 'A')
            throw std::runtime_error("S2 setup acknowledgement failed");

        net::close_socket(s1);
        net::close_socket(s2);

        std::cout << "[Client] N = " << table.size()
                  << ", states = " << state_count
                  << ", alphabet = " << alphabet_size << "\n";
        std::cout << "[Client] Sent the blinded transition database to S1/S2.\n";
        std::cout << "[Client] S1 received only k0 and x1 shares.\n";
        std::cout << "[Client] S2 received only k1 and x2 shares.\n";
        std::cout << "[Client] Setup complete.\n";

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << "\n";
        return 1;
    }
}
