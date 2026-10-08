#pragma once

#ifndef _WIN32
#error "This example is written for Windows/MSYS2/MinGW."
#endif

#include <winsock2.h>
#include <ws2tcpip.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <thread>

#include "common.hpp"

namespace net {

class WinsockInit {
public:
    WinsockInit() {
        WSADATA wsa{};
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
            throw std::runtime_error("WSAStartup failed");
    }

    ~WinsockInit() {
        WSACleanup();
    }
};

inline void close_socket(SOCKET s) {
    if (s != INVALID_SOCKET) closesocket(s);
}

inline void send_all(SOCKET s, const void* data, std::size_t len) {
    const char* p = static_cast<const char*>(data);
    while (len) {
        int n = send(s, p, static_cast<int>(len), 0);
        if (n == SOCKET_ERROR)
            throw std::runtime_error("send() failed");
        p += n;
        len -= static_cast<std::size_t>(n);
    }
}

inline void recv_all(SOCKET s, void* data, std::size_t len) {
    char* p = static_cast<char*>(data);
    while (len) {
        int n = recv(s, p, static_cast<int>(len), 0);
        if (n <= 0)
            throw std::runtime_error("recv() failed/connection closed");
        p += n;
        len -= static_cast<std::size_t>(n);
    }
}

inline void send_byte(SOCKET s, std::uint8_t x) {
    send_all(s, &x, 1);
}

inline std::uint8_t recv_byte(SOCKET s) {
    std::uint8_t x{};
    recv_all(s, &x, 1);
    return x;
}

inline void send_u32(SOCKET s, std::uint32_t x) {
    std::uint32_t n = htonl(x);
    send_all(s, &n, sizeof(n));
}

inline std::uint32_t recv_u32(SOCKET s) {
    std::uint32_t n{};
    recv_all(s, &n, sizeof(n));
    return ntohl(n);
}

inline void send_u64(SOCKET s, std::uint64_t x) {
    // This code is intended for local/normal Windows test networks.
    // Serialize as two network-order 32-bit words.
    send_u32(s, static_cast<std::uint32_t>(x >> 32));
    send_u32(s, static_cast<std::uint32_t>(x & 0xFFFFFFFFULL));
}

inline std::uint64_t recv_u64(SOCKET s) {
    const std::uint64_t hi = recv_u32(s);
    const std::uint64_t lo = recv_u32(s);
    return (hi << 32) | lo;
}

inline void send_block(SOCKET s, const mpcdpf::Block& b) {
    send_all(s, b.data(), b.size());
}

inline mpcdpf::Block recv_block(SOCKET s) {
    mpcdpf::Block b{};
    recv_all(s, b.data(), b.size());
    return b;
}

inline SOCKET listen_on(std::uint16_t port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET)
        throw std::runtime_error("socket() failed");

    BOOL yes = TRUE;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char*>(&yes), sizeof(yes));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        close_socket(s);
        throw std::runtime_error("bind() failed");
    }

    if (listen(s, 4) == SOCKET_ERROR) {
        close_socket(s);
        throw std::runtime_error("listen() failed");
    }

    return s;
}

inline SOCKET accept_one(SOCKET listener) {
    sockaddr_in client{};
    int len = sizeof(client);
    SOCKET s = accept(listener, reinterpret_cast<sockaddr*>(&client), &len);
    if (s == INVALID_SOCKET)
        throw std::runtime_error("accept() failed");
    return s;
}

inline SOCKET connect_retry(const std::string& host,
                            std::uint16_t port,
                            int attempts = 100) {
    for (int attempt = 0; attempt < attempts; ++attempt) {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET)
            throw std::runtime_error("socket() failed");

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);

        if (InetPtonA(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
            close_socket(s);
            throw std::runtime_error("Invalid IPv4 address: " + host);
        }

        if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0)
            return s;

        close_socket(s);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    throw std::runtime_error("Could not connect to " + host + ":" +
                             std::to_string(port));
}

} // namespace net
