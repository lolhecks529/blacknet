#include "PacketBuilder.h"
#include <iostream>
#include <random>
#include <cstring>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <algorithm>

using namespace std;

vector<uint8_t> PacketBuilder::build_ip_packet(const string& src_ip, 
                                               const string& dst_ip,
                                               uint8_t protocol,
                                               const vector<uint8_t>& payload) {
    vector<uint8_t> packet;
    
    // IP header (20 bytes)
    struct iphdr ip_header;
    ip_header.ihl = 5;
    ip_header.version = 4;
    ip_header.tos = 0;
    ip_header.tot_len = htons(sizeof(struct iphdr) + payload.size());
        ip_header.id = htons(rand() % 65535);
    ip_header.frag_off = 0;
    ip_header.ttl = 64;
    ip_header.protocol = protocol;
    ip_header.check = 0;
    ip_header.saddr = ip_to_int(src_ip);
    ip_header.daddr = ip_to_int(dst_ip);
    
    // Calculate IP checksum
    ip_header.check = calculate_ip_checksum((uint8_t*)&ip_header, sizeof(struct iphdr));
    
    // Add IP header to packet
    packet.insert(packet.end(), (uint8_t*)&ip_header, (uint8_t*)&ip_header + sizeof(struct iphdr));
    
    // Add payload
    packet.insert(packet.end(), payload.begin(), payload.end());
    
    return packet;
}

vector<uint8_t> PacketBuilder::build_tcp_packet(const string& src_ip, uint16_t src_port,
                                               const string& dst_ip, uint16_t dst_port,
                                               uint32_t seq, uint32_t ack,
                                               uint8_t flags, const vector<uint8_t>& payload) {
    vector<uint8_t> packet;
    
    // TCP header (20 bytes + options)
    struct tcphdr tcp_header;
    tcp_header.source = htons(src_port);
    tcp_header.dest = htons(dst_port);
    tcp_header.seq = htonl(seq);
    tcp_header.ack_seq = htonl(ack);
    tcp_header.doff = 5; // 20 bytes, no options
    tcp_header.fin = (flags >> 0) & 1;
    tcp_header.syn = (flags >> 1) & 1;
    tcp_header.rst = (flags >> 2) & 1;
    tcp_header.psh = (flags >> 3) & 1;
    tcp_header.ack = (flags >> 4) & 1;
    tcp_header.urg = (flags >> 5) & 1;
    tcp_header.window = htons(5840); // Typical window size
    tcp_header.check = 0;
    tcp_header.urg_ptr = 0;
    
    // Build TCP pseudo-header for checksum
    struct pseudo_header {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t tcp_length;
    } pheader;
    
    pheader.src_addr = ip_to_int(src_ip);
    pheader.dst_addr = ip_to_int(dst_ip);
    pheader.zero = 0;
    pheader.protocol = IPPROTO_TCP;
    pheader.tcp_length = htons(sizeof(struct tcphdr) + payload.size());
    
    // Calculate TCP checksum
    vector<uint8_t> checksum_data;
    checksum_data.insert(checksum_data.end(), (uint8_t*)&pheader, (uint8_t*)&pheader + sizeof(pseudo_header));
    checksum_data.insert(checksum_data.end(), (uint8_t*)&tcp_header, (uint8_t*)&tcp_header + sizeof(struct tcphdr));
    checksum_data.insert(checksum_data.end(), payload.begin(), payload.end());
    
    // Pad to even length
    if (checksum_data.size() % 2 == 1) {
        checksum_data.push_back(0);
    }
    
    tcp_header.check = calculate_ip_checksum(checksum_data.data(), checksum_data.size());
    
    // Add TCP header to packet
    packet.insert(packet.end(), (uint8_t*)&tcp_header, (uint8_t*)&tcp_header + sizeof(struct tcphdr));
    
    // Add payload
    packet.insert(packet.end(), payload.begin(), payload.end());
    
    return packet;
}

vector<uint8_t> PacketBuilder::build_udp_packet(const string& src_ip, uint16_t src_port,
                                               const string& dst_ip, uint16_t dst_port,
                                               const vector<uint8_t>& payload) {
    vector<uint8_t> packet;
    
    // UDP header (8 bytes)
    struct udphdr udp_header;
    udp_header.source = htons(src_port);
    udp_header.dest = htons(dst_port);
    udp_header.len = htons(sizeof(struct udphdr) + payload.size());
    udp_header.check = 0;
    
    // Build UDP pseudo-header for checksum
    struct pseudo_header {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t udp_length;
    } pheader;
    
    pheader.src_addr = ip_to_int(src_ip);
    pheader.dst_addr = ip_to_int(dst_ip);
    pheader.zero = 0;
    pheader.protocol = IPPROTO_UDP;
    pheader.udp_length = htons(sizeof(struct udphdr) + payload.size());
    
    // Calculate UDP checksum
    vector<uint8_t> checksum_data;
    checksum_data.insert(checksum_data.end(), (uint8_t*)&pheader, (uint8_t*)&pheader + sizeof(pseudo_header));
    checksum_data.insert(checksum_data.end(), (uint8_t*)&udp_header, (uint8_t*)&udp_header + sizeof(struct udphdr));
    checksum_data.insert(checksum_data.end(), payload.begin(), payload.end());
    
    // Pad to even length
    if (checksum_data.size() % 2 == 1) {
        checksum_data.push_back(0);
    }
    
    udp_header.check = calculate_ip_checksum(checksum_data.data(), checksum_data.size());
    
    // Add UDP header to packet
    packet.insert(packet.end(), (uint8_t*)&udp_header, (uint8_t*)&udp_header + sizeof(struct udphdr));
    
    // Add payload
    packet.insert(packet.end(), payload.begin(), payload.end());
    
    return packet;
}

vector<uint8_t> PacketBuilder::build_icmp_packet(const string& src_ip,
                                                const string& dst_ip,
                                                uint8_t type, uint8_t code,
                                                const vector<uint8_t>& payload) {
    (void)src_ip;
    (void)dst_ip;
    vector<uint8_t> packet;
    
    // ICMP header (8 bytes)
    struct icmphdr icmp_header;
    icmp_header.type = type;
    icmp_header.code = code;
    icmp_header.checksum = 0;
    icmp_header.un.echo.id = htons(rand() % 65535);
    icmp_header.un.echo.sequence = htons(1);
    
    // Calculate ICMP checksum
    vector<uint8_t> checksum_data;
    checksum_data.insert(checksum_data.end(), (uint8_t*)&icmp_header, (uint8_t*)&icmp_header + sizeof(struct icmphdr));
    checksum_data.insert(checksum_data.end(), payload.begin(), payload.end());
    
    icmp_header.checksum = calculate_icmp_checksum(checksum_data.data(), checksum_data.size());
    
    // Add ICMP header to packet
    packet.insert(packet.end(), (uint8_t*)&icmp_header, (uint8_t*)&icmp_header + sizeof(struct icmphdr));
    
    // Add payload
    packet.insert(packet.end(), payload.begin(), payload.end());
    
    return packet;
}

vector<uint8_t> PacketBuilder::build_dns_packet(uint16_t id, bool qr,
                                               uint16_t opcode, bool aa,
                                               bool tc, bool rd, bool ra,
                                               uint16_t rcode, uint16_t qdcount,
                                               uint16_t ancount, uint16_t nscount,
                                               uint16_t arcount,
                                               const vector<uint8_t>& queries,
                                               const vector<uint8_t>& answers) {
    vector<uint8_t> packet;
    
    // DNS header (12 bytes)
    packet.push_back((id >> 8) & 0xFF);
    packet.push_back(id & 0xFF);
    
    // Flags
    uint16_t flags = 0;
    if (qr) flags |= 0x8000;
    flags |= (opcode & 0x0F) << 11;
    if (aa) flags |= 0x0400;
    if (tc) flags |= 0x0200;
    if (rd) flags |= 0x0100;
    if (ra) flags |= 0x0080;
    flags |= (rcode & 0x0F);
    
    packet.push_back((flags >> 8) & 0xFF);
    packet.push_back(flags & 0xFF);
    
    // Counts
    packet.push_back((qdcount >> 8) & 0xFF);
    packet.push_back(qdcount & 0xFF);
    packet.push_back((ancount >> 8) & 0xFF);
    packet.push_back(ancount & 0xFF);
    packet.push_back((nscount >> 8) & 0xFF);
    packet.push_back(nscount & 0xFF);
    packet.push_back((arcount >> 8) & 0xFF);
    packet.push_back(arcount & 0xFF);
    
    // Queries
    packet.insert(packet.end(), queries.begin(), queries.end());
    
    // Answers
    packet.insert(packet.end(), answers.begin(), answers.end());
    
    return packet;
}

vector<uint8_t> PacketBuilder::build_http_request(const string& method,
                                                 const string& url,
                                                 const string& host,
                                                 const vector<pair<string, string>>& headers,
                                                 const vector<uint8_t>& body) {
    vector<uint8_t> packet;
    string request;
    
    // Request line
    request = method + " " + url + " HTTP/1.1\r\n";
    
    // Headers
    request += "Host: " + host + "\r\n";
    request += "User-Agent: BlackNet-DDoS/1.0\r\n";
    request += "Accept: */*\r\n";
    request += "Connection: keep-alive\r\n";
    
    // Custom headers
    for (const auto& header : headers) {
        request += header.first + ": " + header.second + "\r\n";
    }
    
    // Content-Length if body exists
    if (!body.empty()) {
        request += "Content-Length: " + to_string(body.size()) + "\r\n";
    }
    
    // End of headers
    request += "\r\n";
    
    // Convert to bytes
    packet.insert(packet.end(), request.begin(), request.end());
    
    // Add body
    packet.insert(packet.end(), body.begin(), body.end());
    
    return packet;
}

vector<uint8_t> PacketBuilder::build_tls_client_hello(const string& hostname) {
    vector<uint8_t> packet;
    
    // TLS Record Layer
    packet.push_back(0x16); // Handshake
    packet.push_back(0x03); // Version TLS 1.0
    packet.push_back(0x01); // TLS 1.0
    
    // Handshake Protocol
    packet.push_back(0x01); // Client Hello
    // Length will be calculated later
    
    // ClientHello
    packet.push_back(0x03); // Version TLS 1.2
    packet.push_back(0x03);
    
    // Random (32 bytes)
    vector<uint8_t> random = generate_random_data(32);
    packet.insert(packet.end(), random.begin(), random.end());
    
    // Session ID (empty)
    packet.push_back(0x00);
    
    // Cipher Suites (2 bytes length)
    vector<uint8_t> ciphers = {
        0x00, 0x2F, // TLS_RSA_WITH_AES_128_CBC_SHA
        0x00, 0x35, // TLS_RSA_WITH_AES_256_CBC_SHA
        0x00, 0x0A  // TLS_RSA_WITH_3DES_EDE_CBC_SHA
    };
    packet.push_back((ciphers.size() >> 8) & 0xFF);
    packet.push_back(ciphers.size() & 0xFF);
    packet.insert(packet.end(), ciphers.begin(), ciphers.end());
    
    // Compression Methods (1 byte)
    packet.push_back(0x01); // Length
    packet.push_back(0x00); // NULL compression
    
    // Extensions
    vector<uint8_t> extensions;
    
    // Server Name Indication
    extensions.push_back(0x00); // server_name
    extensions.push_back(0x00);
    
    // SNI length
    uint16_t sni_len = hostname.length() + 5; // +5 for overhead
    extensions.push_back((sni_len >> 8) & 0xFF);
    extensions.push_back(sni_len & 0xFF);
    
    // Server Name List length
    uint16_t sn_list_len = hostname.length() + 3; // +3 for overhead
    extensions.push_back((sn_list_len >> 8) & 0xFF);
    extensions.push_back(sn_list_len & 0xFF);
    
    // Server Name Type (host_name)
    extensions.push_back(0x00);
    
    // Hostname length
    extensions.push_back((hostname.length() >> 8) & 0xFF);
    extensions.push_back(hostname.length() & 0xFF);
    
    // Hostname
    extensions.insert(extensions.end(), hostname.begin(), hostname.end());
    
    // Add extensions length
    packet.push_back((extensions.size() >> 8) & 0xFF);
    packet.push_back(extensions.size() & 0xFF);
    packet.insert(packet.end(), extensions.begin(), extensions.end());
    
    // Update lengths
    size_t handshake_len = packet.size() - 5; // Exclude record header
    packet[3] = (handshake_len >> 16) & 0xFF;
    packet[4] = (handshake_len >> 8) & 0xFF;
    packet[5] = handshake_len & 0xFF;
    
    size_t record_len = packet.size() - 5; // Exclude record header
    packet[3] = (record_len >> 8) & 0xFF;
    packet[4] = record_len & 0xFF;
    
    return packet;
}

vector<uint8_t> PacketBuilder::generate_random_data(size_t size) {
    vector<uint8_t> data(size);
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, 255);
    
    for (size_t i = 0; i < size; i++) {
        data[i] = dis(gen);
    }
    
    return data;
}

uint16_t PacketBuilder::calculate_ip_checksum(const uint8_t* data, size_t length) {
    uint32_t sum = 0;
    
    // Add 16-bit words
    for (size_t i = 0; i < length; i += 2) {
        if (i + 1 < length) {
            sum += (data[i] << 8) | data[i + 1];
        } else {
            sum += data[i] << 8;
        }
    }
    
    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

uint16_t PacketBuilder::calculate_tcp_checksum(const uint8_t* ip_header,
                                              const uint8_t* tcp_header,
                                              size_t tcp_len) {
    struct pseudo_header {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t tcp_length;
    } pheader;
    
    // Extract IP addresses from IP header
    const struct iphdr* ip = (const struct iphdr*)ip_header;
    pheader.src_addr = ip->saddr;
    pheader.dst_addr = ip->daddr;
    pheader.zero = 0;
    pheader.protocol = IPPROTO_TCP;
    pheader.tcp_length = htons(tcp_len);
    
    // Calculate checksum
    vector<uint8_t> data;
    data.insert(data.end(), (uint8_t*)&pheader, (uint8_t*)&pheader + sizeof(pseudo_header));
    data.insert(data.end(), tcp_header, tcp_header + tcp_len);
    
    // Pad to even length
    if (data.size() % 2 == 1) {
        data.push_back(0);
    }
    
    return calculate_ip_checksum(data.data(), data.size());
}

uint16_t PacketBuilder::calculate_udp_checksum(const uint8_t* ip_header,
                                              const uint8_t* udp_header,
                                              size_t udp_len) {
    struct pseudo_header {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t udp_length;
    } pheader;
    
    // Extract IP addresses from IP header
    const struct iphdr* ip = (const struct iphdr*)ip_header;
    pheader.src_addr = ip->saddr;
    pheader.dst_addr = ip->daddr;
    pheader.zero = 0;
    pheader.protocol = IPPROTO_UDP;
    pheader.udp_length = htons(udp_len);
    
    // Calculate checksum
    vector<uint8_t> data;
    data.insert(data.end(), (uint8_t*)&pheader, (uint8_t*)&pheader + sizeof(pseudo_header));
    data.insert(data.end(), udp_header, udp_header + udp_len);
    
    // Pad to even length
    if (data.size() % 2 == 1) {
        data.push_back(0);
    }
    
    return calculate_ip_checksum(data.data(), data.size());
}

uint16_t PacketBuilder::calculate_icmp_checksum(const uint8_t* data, size_t length) {
    return calculate_ip_checksum(data, length);
}

uint32_t PacketBuilder::ip_to_int(const string& ip) {
    struct in_addr addr;
    inet_pton(AF_INET, ip.c_str(), &addr);
    return addr.s_addr;
}

string PacketBuilder::int_to_ip(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    
    char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
    return string(ip_str);
}

uint16_t PacketBuilder::calculate_mtu(const string& dst_ip) {
    // Default MTU for Ethernet
    uint16_t mtu = 1500;
    
    // Subtract IP header (20 bytes) and TCP header (20-60 bytes)
    // For simplicity, we'll use 1460 for TCP and 1472 for UDP/ICMP
    // Real implementation would use path MTU discovery
    
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    inet_pton(AF_INET, dst_ip.c_str(), &dest_addr.sin_addr);
    
    // For now, return conservative values
    // TCP MSS = MTU - IP header - TCP header = 1500 - 20 - 20 = 1460
    // UDP/ICMP max payload = MTU - IP header = 1500 - 20 = 1480
    
    return mtu;
}
