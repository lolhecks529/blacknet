#ifndef UTILITIES_H
#define UTILITIES_H

#include <string>
#include <vector>
#include <cstdint>      // FIX: added for uint64_t
#include <random>       // for std::mt19937 (static member)
// FIX: removed <chrono>, <iomanip>, <sstream>, <cctype>, <algorithm>
//      — implementation-only headers that belong in Utilities.cpp, not here

class Utilities {
public:
    // String utilities
    static std::string to_lower(const std::string& str);
    static std::string to_upper(const std::string& str);
    static std::string trim(const std::string& str);
    static std::vector<std::string> split(const std::string& str, char delimiter);
    static bool starts_with(const std::string& str, const std::string& prefix);
    static bool ends_with(const std::string& str, const std::string& suffix);
    static bool contains(const std::string& str, const std::string& substr);
    static std::string replace(const std::string& str, const std::string& from, const std::string& to);

    // Network utilities
    static bool is_valid_ip(const std::string& ip);
    static bool is_valid_url(const std::string& url);
    static bool is_valid_port(int port);
    static std::string resolve_dns(const std::string& hostname);
    static std::vector<std::string> get_local_ips();
    static std::string get_public_ip();

    // File utilities
    static bool file_exists(const std::string& filename);
    static std::string read_file(const std::string& filename);
    static bool write_file(const std::string& filename, const std::string& content);
    static std::vector<std::string> read_lines(const std::string& filename);
    static bool append_file(const std::string& filename, const std::string& content);

    // Random utilities
    static std::string random_string(size_t length);
    static int random_int(int min, int max);
    static std::string random_ip();
    static int random_port();

    // Time utilities
    static std::string get_current_time();
    static std::string get_timestamp();
    static void sleep_ms(int milliseconds);

    // Format utilities
    static std::string format_bytes(uint64_t bytes);
    static std::string format_bps(uint64_t bps);
    static std::string format_number(uint64_t number);
    static std::string format_duration(uint64_t seconds);

    // Parse a data size string like "100MB", "2GB", "1TB" into bytes.
    // Returns 0 on invalid input. Max 5TB (5497558138880 bytes).
    static uint64_t parse_data_size(const std::string& size_str);

    // Security utilities
    static std::string md5_hash(const std::string& str);
    static std::string sha256_hash(const std::string& str);
    static std::string base64_encode(const std::string& str);
    static std::string base64_decode(const std::string& str);
    static std::string xor_encrypt(const std::string& str, const std::string& key);
    static std::string xor_decrypt(const std::string& str, const std::string& key);

    // System utilities
    static int get_cpu_cores();
    static uint64_t get_total_memory();
    static uint64_t get_available_memory();
    static std::string get_os_name();
    static bool is_root();

private:
    // FIX: static member must be defined in exactly one .cpp (Utilities.cpp)
    //      as: std::mt19937 Utilities::rng{std::random_device{}()};
    static std::mt19937 rng;
};

#endif // UTILITIES_H
