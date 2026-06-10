#include "Utilities.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <ctime>
#include <chrono>
#include <random>
#include <sys/stat.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <curl/curl.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <netdb.h>
#include <iomanip>
#include <thread>

using namespace std;

mt19937 Utilities::rng(random_device{}());

string Utilities::to_lower(const string& str) {
    string result = str;
    transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

string Utilities::to_upper(const string& str) {
    string result = str;
    transform(result.begin(), result.end(), result.begin(), ::toupper);
    return result;
}

string Utilities::trim(const string& str) {
    size_t start = str.find_first_not_of(" \t\n\r");
    size_t end = str.find_last_not_of(" \t\n\r");
    
    if (start == string::npos || end == string::npos) {
        return "";
    }
    
    return str.substr(start, end - start + 1);
}

vector<string> Utilities::split(const string& str, char delimiter) {
    vector<string> tokens;
    stringstream ss(str);
    string token;
    
    while (getline(ss, token, delimiter)) {
        tokens.push_back(trim(token));
    }
    
    return tokens;
}

bool Utilities::starts_with(const string& str, const string& prefix) {
    if (prefix.size() > str.size()) return false;
    return equal(prefix.begin(), prefix.end(), str.begin());
}

bool Utilities::ends_with(const string& str, const string& suffix) {
    if (suffix.size() > str.size()) return false;
    return equal(suffix.rbegin(), suffix.rend(), str.rbegin());
}

bool Utilities::contains(const string& str, const string& substr) {
    return str.find(substr) != string::npos;
}

string Utilities::replace(const string& str, const string& from, const string& to) {
    string result = str;
    size_t pos = 0;
    
    while ((pos = result.find(from, pos)) != string::npos) {
        result.replace(pos, from.length(), to);
        pos += to.length();
    }
    
    return result;
}

bool Utilities::is_valid_ip(const string& ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) != 0;
}

bool Utilities::is_valid_url(const string& url) {
    // Simple URL validation
        return (url.find("http://") == 0 || url.find("https://") == 0 ||
            url.find("www.") == 0 || url.find('.') != string::npos);
}

bool Utilities::is_valid_port(int port) {
    return port > 0 && port <= 65535;
}

string Utilities::resolve_dns(const string& hostname) {
    struct addrinfo hints, *res;
    char ipstr[INET_ADDRSTRLEN];
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    if (getaddrinfo(hostname.c_str(), NULL, &hints, &res) != 0) {
        return "";
    }
    
    struct sockaddr_in* ipv4 = (struct sockaddr_in*)res->ai_addr;
    inet_ntop(AF_INET, &(ipv4->sin_addr), ipstr, sizeof(ipstr));
    
    freeaddrinfo(res);
    return string(ipstr);
}

vector<string> Utilities::get_local_ips() {
    vector<string> ips;
    struct ifaddrs* ifaddr, *ifa;
    
    if (getifaddrs(&ifaddr) == -1) {
        return ips;
    }
    
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in* sa = (struct sockaddr_in*)ifa->ifa_addr;
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(sa->sin_addr), ip, INET_ADDRSTRLEN);
            
            // Skip localhost
            if (string(ip) != "127.0.0.1") {
                ips.push_back(ip);
            }
        }
    }
    
    freeifaddrs(ifaddr);
    return ips;
}

string Utilities::get_public_ip() {
    CURL* curl = curl_easy_init();
    if (!curl) {
        return "";
    }
    
    string response;
    
    curl_easy_setopt(curl, CURLOPT_URL, "https://api.ipify.org");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, [](void* ptr, size_t size, size_t nmemb, string* data) {
        data->append((char*)ptr, size * nmemb);
        return size * nmemb;
    });
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "BlackNet-DDoS/1.0");
    
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        return "";
    }
    
    return trim(response);
}

bool Utilities::file_exists(const string& filename) {
    struct stat buffer;
    return stat(filename.c_str(), &buffer) == 0;
}

string Utilities::read_file(const string& filename) {
    ifstream file(filename, ios::binary);
    if (!file.is_open()) {
        return "";
    }
    
    string content((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    file.close();
    return content;
}

bool Utilities::write_file(const string& filename, const string& content) {
    ofstream file(filename, ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    file << content;
    file.close();
    return true;
}

vector<string> Utilities::read_lines(const string& filename) {
    vector<string> lines;
    ifstream file(filename);
    
    if (!file.is_open()) {
        return lines;
    }
    
    string line;
    while (getline(file, line)) {
        lines.push_back(trim(line));
    }
    
    file.close();
    return lines;
}

bool Utilities::append_file(const string& filename, const string& content) {
    ofstream file(filename, ios::app | ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    file << content;
    file.close();
    return true;
}

string Utilities::random_string(size_t length) {
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    uniform_int_distribution<> dis(0, sizeof(charset) - 2);
    
    string result;
    result.reserve(length);
    
    for (size_t i = 0; i < length; i++) {
        result += charset[dis(rng)];
    }
    
    return result;
}

int Utilities::random_int(int min, int max) {
    uniform_int_distribution<> dis(min, max);
    return dis(rng);
}

string Utilities::random_ip() {
    uniform_int_distribution<> dis(1, 254);
    
    return to_string(dis(rng)) + "." +
           to_string(dis(rng)) + "." +
           to_string(dis(rng)) + "." +
           to_string(dis(rng));
}

int Utilities::random_port() {
    uniform_int_distribution<> dis(1024, 65535);
    return dis(rng);
}

string Utilities::get_current_time() {
    auto now = chrono::system_clock::now();
    auto time = chrono::system_clock::to_time_t(now);
    
    stringstream ss;
    ss << put_time(localtime(&time), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

string Utilities::get_timestamp() {
    auto now = chrono::system_clock::now();
    auto ms = chrono::duration_cast<chrono::milliseconds>(now.time_since_epoch()).count();
    
    return to_string(ms);
}

void Utilities::sleep_ms(int milliseconds) {
    this_thread::sleep_for(chrono::milliseconds(milliseconds));
}

string Utilities::format_bytes(uint64_t bytes) {
    const char* sizes[] = {"B", "KB", "MB", "GB", "TB"};
    int i = 0;
    double dbl_bytes = bytes;
    
    while (dbl_bytes >= 1024 && i < 4) {
        dbl_bytes /= 1024;
        i++;
    }
    
    stringstream ss;
    ss << fixed << setprecision(2) << dbl_bytes << " " << sizes[i];
    return ss.str();
}

string Utilities::format_bps(uint64_t bps) {
    const char* sizes[] = {"bps", "Kbps", "Mbps", "Gbps", "Tbps"};
    int i = 0;
    double dbl_bps = bps;
    
    while (dbl_bps >= 1000 && i < 4) {
        dbl_bps /= 1000;
        i++;
    }
    
    stringstream ss;
    ss << fixed << setprecision(2) << dbl_bps << " " << sizes[i];
    return ss.str();
}

string Utilities::format_number(uint64_t number) {
    string str = to_string(number);
    int len = str.length();
    
    for (int i = len - 3; i > 0; i -= 3) {
        str.insert(i, ",");
    }
    
    return str;
}

string Utilities::format_duration(uint64_t seconds) {
    uint64_t hours = seconds / 3600;
    uint64_t minutes = (seconds % 3600) / 60;
    uint64_t secs = seconds % 60;
    
    stringstream ss;
    
    if (hours > 0) {
        ss << hours << "h ";
    }
    if (minutes > 0 || hours > 0) {
        ss << minutes << "m ";
    }
    
    ss << secs << "s";
    return ss.str();
}

string Utilities::md5_hash(const string& str) {
    unsigned char digest[MD5_DIGEST_LENGTH];
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    MD5((unsigned char*)str.c_str(), str.length(), digest);
#pragma GCC diagnostic pop
    
    char md5_str[MD5_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(&md5_str[i * 2], "%02x", digest[i]);
    }
    
    return string(md5_str);
}

string Utilities::sha256_hash(const string& str) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)str.c_str(), str.length(), digest);
    
    char sha_str[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&sha_str[i * 2], "%02x", digest[i]);
    }
    
    return string(sha_str);
}

string Utilities::base64_encode(const string& str) {
    const char* base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    string encoded;
    int i = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    
    for (unsigned char c : str) {
        char_array_3[i++] = c;
        
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            
            for (int j = 0; j < 4; j++) {
                encoded += base64_chars[char_array_4[j]];
            }
            
            i = 0;
        }
    }
    
    if (i > 0) {
        for (int j = i; j < 3; j++) {
            char_array_3[j] = 0;
        }
        
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;
        
        for (int j = 0; j < i + 1; j++) {
            encoded += base64_chars[char_array_4[j]];
        }
        
        while (i++ < 3) {
            encoded += '=';
        }
    }
    
    return encoded;
}

string Utilities::base64_decode(const string& str) {
    const string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    string decoded;
    vector<int> char_map(256, -1);
    
    for (int i = 0; i < 64; i++) {
        char_map[base64_chars[i]] = i;
    }
    
    int i = 0;
    unsigned char char_array_4[4], char_array_3[3];
    
    for (unsigned char c : str) {
        if (c == '=') break;
        if (char_map[c] == -1) continue;
        
        char_array_4[i++] = c;
        
        if (i == 4) {
            for (int j = 0; j < 4; j++) {
                char_array_4[j] = char_map[char_array_4[j]];
            }
            
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
            
            for (int j = 0; j < 3; j++) {
                decoded += char_array_3[j];
            }
            
            i = 0;
        }
    }
    
    if (i > 0) {
        for (int j = i; j < 4; j++) {
            char_array_4[j] = 0;
        }
        
        for (int j = 0; j < 4; j++) {
            char_array_4[j] = char_map[char_array_4[j]];
        }
        
        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
        
        for (int j = 0; j < i - 1; j++) {
            decoded += char_array_3[j];
        }
    }
    
    return decoded;
}

string Utilities::xor_encrypt(const string& str, const string& key) {
    string result = str;
    
    for (size_t i = 0; i < str.length(); i++) {
        result[i] = str[i] ^ key[i % key.length()];
    }
    
    return result;
}

string Utilities::xor_decrypt(const string& str, const string& key) {
    return xor_encrypt(str, key); // XOR encryption is symmetric
}

int Utilities::get_cpu_cores() {
    return sysconf(_SC_NPROCESSORS_ONLN);
}

uint64_t Utilities::get_total_memory() {
    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGE_SIZE);
    return pages * page_size;
}

uint64_t Utilities::get_available_memory() {
    // Parse /proc/meminfo
    ifstream meminfo("/proc/meminfo");
    if (!meminfo.is_open()) {
        return 0;
    }
    
    string line;
    while (getline(meminfo, line)) {
        if (line.find("MemAvailable:") == 0) {
            size_t pos = line.find(":");
            if (pos != string::npos) {
                string value = line.substr(pos + 1);
                value = trim(value);
                pos = value.find(" ");
                if (pos != string::npos) {
                    value = value.substr(0, pos);
                }
                return stoull(value) * 1024; // Convert KB to bytes
            }
        }
    }
    
    return 0;
}

string Utilities::get_os_name() {
    ifstream os_release("/etc/os-release");
    if (os_release.is_open()) {
        string line;
        while (getline(os_release, line)) {
            if (line.find("PRETTY_NAME=") == 0) {
                string name = line.substr(13);
                name = name.substr(0, name.length() - 1);
                return name;
            }
        }
    }
    
    return "Linux";
}

bool Utilities::is_root() {
    return geteuid() == 0;
}

uint64_t Utilities::parse_data_size(const string& size_str) {
    if (size_str.empty()) return 0;

    // Separate number and unit
    size_t i = 0;
    while (i < size_str.size() && (isdigit(size_str[i]) || size_str[i] == '.')) i++;
    if (i == 0) return 0;

    string num_str = size_str.substr(0, i);
    string unit_str = size_str.substr(i);
    for (auto& c : unit_str) c = toupper(c);

    double value = stod(num_str);
    if (value < 0) return 0;

    uint64_t multiplier = 1;
    if (unit_str.empty() || unit_str == "B") {
        multiplier = 1;
    } else if (unit_str == "KB") {
        multiplier = 1024ULL;
    } else if (unit_str == "MB") {
        multiplier = 1024ULL * 1024;
    } else if (unit_str == "GB") {
        multiplier = 1024ULL * 1024 * 1024;
    } else if (unit_str == "TB") {
        multiplier = 1024ULL * 1024 * 1024 * 1024;
    } else {
        return 0;
    }

    uint64_t bytes = static_cast<uint64_t>(value * multiplier);
    uint64_t max_bytes = 5497558138880ULL; // 5TB
    if (bytes > max_bytes) bytes = max_bytes;

    return bytes;
}
