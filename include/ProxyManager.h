#ifndef PROXY_MANAGER_H
#define PROXY_MANAGER_H

#include <string>
#include <vector>
#include <utility>      // FIX: added for std::pair
#include <random>       // for std::mt19937
#include <mutex>
// FIX: removed <fstream> — not used in this header; belongs only in .cpp

class ProxyManager {
public:
    // Proxy types — moved to public so callers can reference ProxyManager::HTTP etc.
    enum ProxyType {
        HTTP,
        HTTPS,
        SOCKS4,
        SOCKS5
    };

    ProxyManager();

    bool load_proxies(const std::string& filename);
    bool add_proxy(const std::string& ip, int port);
    bool remove_proxy(const std::string& ip, int port);

    std::pair<std::string, int> get_random_proxy();
    std::pair<std::string, int> get_best_proxy();

    void test_all_proxies();
    void clear_proxies();

    // FIX: return type changed from size_t to match standard practice;
    //      these are logically read-only so marked const
    size_t get_total_proxies()   const;
    size_t get_working_proxies() const;

    bool save_proxies(const std::string& filename);
    bool load_working_proxies(const std::string& filename);

    bool set_proxy_type(ProxyType type);

private:
    std::vector<std::pair<std::string, int>> proxies;
    std::vector<std::pair<std::string, int>> working_proxies;
    mutable std::mutex proxy_mutex;
    std::mt19937 rng;   // seeded in constructor via std::random_device

    ProxyType current_type;
    int timeout_ms;
    int max_retries;

    bool test_proxy(const std::string& ip, int port);
    bool parse_proxy_line(const std::string& line, std::string& ip, int& port);
};

#endif // PROXY_MANAGER_H
