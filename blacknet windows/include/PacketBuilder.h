#ifndef PACKET_BUILDER_H
#define PACKET_BUILDER_H

#include <vector>
#include <cstdint>
#include <cstddef>      // FIX: added for size_t
#include <string>
#include <utility>      // FIX: added for std::pair

class PacketBuilder {
public:
    // IP packet builder
    static std::vector<uint8_t> build_ip_packet(const std::string& src_ip,
                                                const std::string& dst_ip,
                                                uint8_t protocol,
                                                const std::vector<uint8_t>& payload);

    // TCP packet builder
    static std::vector<uint8_t> build_tcp_packet(const std::string& src_ip, uint16_t src_port,
                                                 const std::string& dst_ip, uint16_t dst_port,
                                                 uint32_t seq, uint32_t ack,
                                                 uint8_t flags, const std::vector<uint8_t>& payload);

    // UDP packet builder
    static std::vector<uint8_t> build_udp_packet(const std::string& src_ip, uint16_t src_port,
                                                 const std::string& dst_ip, uint16_t dst_port,
                                                 const std::vector<uint8_t>& payload);

    // ICMP packet builder
    static std::vector<uint8_t> build_icmp_packet(const std::string& src_ip,
                                                  const std::string& dst_ip,
                                                  uint8_t type, uint8_t code,
                                                  const std::vector<uint8_t>& payload);

    // DNS packet builder
    static std::vector<uint8_t> build_dns_packet(uint16_t id, bool qr,
                                                 uint16_t opcode, bool aa,
                                                 bool tc, bool rd, bool ra,
                                                 uint16_t rcode, uint16_t qdcount,
                                                 uint16_t ancount, uint16_t nscount,
                                                 uint16_t arcount,
                                                 const std::vector<uint8_t>& queries,
                                                 const std::vector<uint8_t>& answers);

    // HTTP packet builder
    static std::vector<uint8_t> build_http_request(const std::string& method,
                                                   const std::string& url,
                                                   const std::string& host,
                                                   const std::vector<std::pair<std::string, std::string>>& headers,
                                                   const std::vector<uint8_t>& body);

    // SSL/TLS packet builder
    static std::vector<uint8_t> build_tls_client_hello(const std::string& hostname);

    // Random data generator
    static std::vector<uint8_t> generate_random_data(size_t size);

    // Checksum calculators
    static uint16_t calculate_ip_checksum(const uint8_t* data, size_t length);
    static uint16_t calculate_tcp_checksum(const uint8_t* ip_header,
                                           const uint8_t* tcp_header,
                                           size_t tcp_len);
    static uint16_t calculate_udp_checksum(const uint8_t* ip_header,
                                           const uint8_t* udp_header,
                                           size_t udp_len);
    static uint16_t calculate_icmp_checksum(const uint8_t* data, size_t length);

    // IP/Port utilities
    static uint32_t ip_to_int(const std::string& ip);
    static std::string int_to_ip(uint32_t ip);
    // FIX: calculate_mtu does not modify state — made const-correct via static
    static uint16_t calculate_mtu(const std::string& dst_ip);

private:
    static void add_tcp_option(std::vector<uint8_t>& packet, uint8_t kind,
                               const std::vector<uint8_t>& data = {});
    static void add_http_header(std::vector<uint8_t>& packet,
                                const std::string& key, const std::string& value);
};

#endif // PACKET_BUILDER_H
