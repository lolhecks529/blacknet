#include "ProxyManager.h"
#include <iostream>
#include <sstream>
#include <thread>
#include <chrono>
#include <atomic>
#include <curl/curl.h>
#include <regex>
#include <fstream>
#include "Utilities.h"

using namespace std;

ProxyManager::ProxyManager() : rng(random_device{}()), current_type(HTTP), timeout_ms(5000), max_retries(3) {
    // Initialize CURL globally if needed
    static bool curl_initialized = false;
    if (!curl_initialized) {
        curl_global_init(CURL_GLOBAL_ALL);
        curl_initialized = true;
    }
}

bool ProxyManager::load_proxies(const string& filename) {
    lock_guard<mutex> lock(proxy_mutex);
    
    ifstream file(filename);
    if (!file.is_open()) {
        cerr << "[-] Failed to open proxy file: " << filename << endl;
        return false;
    }
    
    proxies.clear();
    string line;
    int loaded = 0;
    
    while (getline(file, line)) {
        // Remove comments and whitespace
        size_t comment_pos = line.find('#');
        if (comment_pos != string::npos) {
            line = line.substr(0, comment_pos);
        }
        
        line = Utilities::trim(line);
        if (line.empty()) continue;
        
        string ip;
        int port;
        
        if (parse_proxy_line(line, ip, port)) {
            proxies.emplace_back(ip, port);
            loaded++;
        }
    }
    
    file.close();
    
    cout << "[+] Loaded " << loaded << " proxies from " << filename << endl;
    
    // Test all proxies in background
    thread test_thread([this]() {
        test_all_proxies();
    });
    test_thread.detach();
    
    return loaded > 0;
}

bool ProxyManager::parse_proxy_line(const string& line, string& ip, int& port) {
    // Support formats: ip:port, ip:port:user:pass, http://ip:port
    regex proxy_regex(R"((?:https?://)?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):([0-9]{1,5})(?::([^:]+):(.+))?)");
    smatch matches;
    
    if (regex_match(line, matches, proxy_regex) && matches.size() >= 3) {
        ip = matches[1].str();
        port = stoi(matches[2].str());
        
        // Validate IP
        regex ip_regex(R"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))");
        
        if (!regex_match(ip, ip_regex)) {
            return false;
        }
        
        // Validate port
        if (port < 1 || port > 65535) {
            return false;
        }
        
        return true;
    }
    
    return false;
}

bool ProxyManager::add_proxy(const string& ip, int port) {
    lock_guard<mutex> lock(proxy_mutex);
    
    // Check if proxy already exists
    for (const auto& proxy : proxies) {
        if (proxy.first == ip && proxy.second == port) {
            return false;
        }
    }
    
    proxies.emplace_back(ip, port);
    
    // Test the new proxy
    if (test_proxy(ip, port)) {
        working_proxies.emplace_back(ip, port);
    }
    
    return true;
}

bool ProxyManager::remove_proxy(const string& ip, int port) {
    lock_guard<mutex> lock(proxy_mutex);
    
    // Remove from proxies list
    auto it = remove_if(proxies.begin(), proxies.end(),
        [&](const pair<string, int>& proxy) {
            return proxy.first == ip && proxy.second == port;
        });
    
    if (it != proxies.end()) {
        proxies.erase(it, proxies.end());
        
        // Remove from working proxies list
        auto it2 = remove_if(working_proxies.begin(), working_proxies.end(),
            [&](const pair<string, int>& proxy) {
                return proxy.first == ip && proxy.second == port;
            });
        
        if (it2 != working_proxies.end()) {
            working_proxies.erase(it2, working_proxies.end());
        }
        
        return true;
    }
    
    return false;
}

pair<string, int> ProxyManager::get_random_proxy() {
    lock_guard<mutex> lock(proxy_mutex);
    
    if (working_proxies.empty()) {
        // No working proxies, try all proxies
        if (proxies.empty()) {
            return {"", 0};
        }
        
        uniform_int_distribution<size_t> dist(0, proxies.size() - 1);
        return proxies[dist(rng)];
    }
    
    uniform_int_distribution<size_t> dist(0, working_proxies.size() - 1);
    return working_proxies[dist(rng)];
}

pair<string, int> ProxyManager::get_best_proxy() {
    lock_guard<mutex> lock(proxy_mutex);
    
    if (working_proxies.empty()) {
        return get_random_proxy();
    }
    
    // For now, return first working proxy
    // In real implementation, would track latency/success rate
    return working_proxies[0];
}

bool ProxyManager::test_proxy(const string& ip, int port) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        return false;
    }
    
    string proxy_url = ip + ":" + to_string(port);
    curl_easy_setopt(curl, CURLOPT_PROXY, proxy_url.c_str());
    
    // Auto-detect proxy type based on port
    long proxy_type = CURLPROXY_HTTP;
    if (port == 1080 || port == 1085 || port == 10808)
        proxy_type = CURLPROXY_SOCKS5;
    else if (port == 1081 || port == 4145 || port == 4153)
        proxy_type = CURLPROXY_SOCKS4;
    else if (port == 443 || port == 8443)
        proxy_type = CURLPROXY_HTTPS;
    curl_easy_setopt(curl, CURLOPT_PROXYTYPE, proxy_type);
    
    // Set test URL
    curl_easy_setopt(curl, CURLOPT_URL, "http://www.google.com");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_ms);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, timeout_ms);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "BlackNet-DDoS/1.0");
    
    // Try HTTP first if SOCKS failed
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK && proxy_type != CURLPROXY_HTTP) {
        curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
        res = curl_easy_perform(curl);
    }
    
    curl_easy_cleanup(curl);
    return res == CURLE_OK;
}

void ProxyManager::test_all_proxies() {
    vector<pair<string, int>> proxies_copy;
    {
        lock_guard<mutex> lock(proxy_mutex);
        working_proxies.clear();
        proxies_copy = proxies;
    }

    cout << "[*] Testing " << proxies_copy.size() << " proxies..." << endl;

    vector<thread> test_threads;
    atomic<int> tested{0};
    int total = proxies_copy.size();

    for (const auto& proxy : proxies_copy) {
        test_threads.emplace_back([this, proxy, &tested, total]() {
            if (test_proxy(proxy.first, proxy.second)) {
                lock_guard<mutex> lock(proxy_mutex);
                working_proxies.push_back(proxy);
            }
            int done = ++tested;
            if (done % 50 == 0 || done == total) {
                cout << "\r[*] Tested " << done << "/" << total << " proxies..."
                     << flush;
            }
        });
        
        if (test_threads.size() >= 20) {
            for (auto& thread : test_threads) thread.join();
            test_threads.clear();
        }
    }
    
    for (auto& thread : test_threads) thread.join();
    
    lock_guard<mutex> lock(proxy_mutex);
    cout << "\r[+] Proxy testing complete: " << working_proxies.size()
         << "/" << proxies_copy.size() << " working" << endl;
}

void ProxyManager::clear_proxies() {
    lock_guard<mutex> lock(proxy_mutex);
    proxies.clear();
    working_proxies.clear();
}

size_t ProxyManager::get_total_proxies() const {
    lock_guard<mutex> lock(proxy_mutex);
    return proxies.size();
}

size_t ProxyManager::get_working_proxies() const {
    lock_guard<mutex> lock(proxy_mutex);
    return working_proxies.size();
}

bool ProxyManager::save_proxies(const string& filename) {
    lock_guard<mutex> lock(proxy_mutex);
    
    ofstream file(filename);
    if (!file.is_open()) {
        return false;
    }
    
    for (const auto& proxy : proxies) {
        file << proxy.first << ":" << proxy.second << endl;
    }
    
    file.close();
    return true;
}

bool ProxyManager::load_working_proxies(const string& filename) {
    lock_guard<mutex> lock(proxy_mutex);
    
    ifstream file(filename);
    if (!file.is_open()) {
        return false;
    }
    
    working_proxies.clear();
    string line;
    
    while (getline(file, line)) {
        string ip;
        int port;
        
        if (parse_proxy_line(line, ip, port)) {
            working_proxies.emplace_back(ip, port);
        }
    }
    
    file.close();
    return !working_proxies.empty();
}

bool ProxyManager::set_proxy_type(ProxyType type) {
    current_type = type;
    return true;
}
