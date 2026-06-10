#include "GeoLocator.h"
#include <iostream>
#include <sstream>
#include <fstream>
#include <regex>
#include <arpa/inet.h>

// FIX: removed <json/json.h> (jsoncpp) — replaced with a self-contained
//      helper that extracts string values from flat JSON objects.
//      All usages here only need simple key→string lookups, so a full
//      JSON library is unnecessary and avoids the missing-header error.

using namespace std;

// Extract the string value for a given key from a flat JSON object.
// e.g. json_get_str("{\"country\":\"US\",\"city\":\"LA\"}", "country") → "US"
static string json_get_str(const string& json, const string& key) {
    // Match: "key":"value"  or  "key": "value"
    string pattern = "\"" + key + "\"\\s*:\\s*\"([^\"]*)\"";
    regex re(pattern);
    smatch m;
    if (regex_search(json, m, re)) {
        return m[1].str();
    }
    return "";
}

GeoLocator::GeoLocator() {
    curl = curl_easy_init();
    if (!curl) {
        cerr << "[-] Failed to initialize CURL" << endl;
    }
}

GeoLocator::~GeoLocator() {
    if (curl) {
        curl_easy_cleanup(curl);
    }
}

bool GeoLocator::set_api_key(const string& key) {
    api_key = key;
    return !api_key.empty();
}

size_t GeoLocator::write_callback(void* contents, size_t size, size_t nmemb, string* output) {
    size_t total_size = size * nmemb;
    output->append((char*)contents, total_size);
    return total_size;
}

string GeoLocator::get_ip_location(const string& ip) {
    if (!curl) return "Unknown";
    
    string url = "http://ip-api.com/json/" + ip + "?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query";
    string response;
    
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "BlackNet-DDoS/1.0");
    
    CURLcode res = curl_easy_perform(curl);
    
    if (res != CURLE_OK || response.empty()) {
        return "Unknown";
    }
    
    if (json_get_str(response, "status") != "success") {
        return "Unknown";
    }
    
    string location = json_get_str(response, "country") + ", " +
                      json_get_str(response, "city") + " (" +
                      json_get_str(response, "isp") + ")";
    
    return location;
}

string GeoLocator::get_country(const string& ip) {
    if (!curl) return "Unknown";
    
    string url = "http://ip-api.com/json/" + ip + "?fields=country";
    string response;
    
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    
    CURLcode res = curl_easy_perform(curl);
    
    if (res != CURLE_OK || response.empty()) {
        return "Unknown";
    }
    
    return json_get_str(response, "country");
}

string GeoLocator::get_city(const string& ip) {
    if (!curl) return "Unknown";
    
    string url = "http://ip-api.com/json/" + ip + "?fields=city";
    string response;
    
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    
    CURLcode res = curl_easy_perform(curl);
    
    if (res != CURLE_OK || response.empty()) {
        return "Unknown";
    }
    
    string city = json_get_str(response, "city");
    return city.empty() ? "Unknown" : city;
}

string GeoLocator::get_isp(const string& ip) {
    if (!curl) return "Unknown";
    
    string url = "http://ip-api.com/json/" + ip + "?fields=isp";
    string response;
    
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    
    CURLcode res = curl_easy_perform(curl);
    
    if (res != CURLE_OK || response.empty()) {
        return "Unknown";
    }
    
    string isp = json_get_str(response, "isp");
    return isp.empty() ? "Unknown" : isp;
}

string GeoLocator::get_country_code(const string& country_name) {
    // Map country names to ISO codes
    map<string, string> country_codes = {
        {"United States", "US"},
        {"China", "CN"},
        {"Russia", "RU"},
        {"Germany", "DE"},
        {"United Kingdom", "GB"},
        {"France", "FR"},
        {"Japan", "JP"},
        {"South Korea", "KR"},
        {"Brazil", "BR"},
        {"India", "IN"},
        {"Australia", "AU"},
        {"Canada", "CA"},
        {"Mexico", "MX"},
        {"Italy", "IT"},
        {"Spain", "ES"}
    };
    
    auto it = country_codes.find(country_name);
    if (it != country_codes.end()) {
        return it->second;
    }
    
    return country_name.substr(0, 2);
}

vector<string> GeoLocator::get_ips_by_country(const string& country) {
    // Check cache first
    if (country_cache.find(country) != country_cache.end()) {
        return country_cache[country];
    }
    
    vector<string> ips;
    string country_code = get_country_code(country);
    
    if (!curl) return ips;
    
    // Use IP ranges from Team Cymru
    string url = "https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.csv";
    string response;
    
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    
    CURLcode res = curl_easy_perform(curl);
    
    if (res != CURLE_OK || response.empty()) {
        return ips;
    }
    
    // Parse CSV for country IP ranges
    stringstream ss(response);
    string line;
    
    while (getline(ss, line)) {
        if (line.find(country_code) != string::npos) {
            // Extract IP range
            size_t pos = line.find(',');
            if (pos != string::npos) {
                string ip_range = line.substr(0, pos);
                // Convert to CIDR or IP list
                // This is simplified - real implementation would parse full range
                ips.push_back(ip_range + ".0.0.0/8");
            }
        }
    }
    
    // Cache results
    country_cache[country] = ips;
    
    return ips;
}

vector<string> GeoLocator::get_ips_by_city(const string& country, const string& city) {
    vector<string> ips;
    
    // This would require a commercial IP database
    // For free version, we'll use a simplified approach
    
    if (!curl) return ips;
    
    (void)country;
    (void)city;
    (void)curl;
    return ips;
}

vector<string> GeoLocator::generate_ip_range(const string& start_ip, const string& end_ip) {
    vector<string> ips;
    
    // Convert IPs to integers
    struct in_addr start_addr, end_addr;
    inet_pton(AF_INET, start_ip.c_str(), &start_addr);
    inet_pton(AF_INET, end_ip.c_str(), &end_addr);
    
    uint32_t start = ntohl(start_addr.s_addr);
    uint32_t end = ntohl(end_addr.s_addr);
    
    // Generate all IPs in range
    for (uint32_t ip = start; ip <= end; ip++) {
        struct in_addr addr;
        addr.s_addr = htonl(ip);
        
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
        
        ips.push_back(string(ip_str));
    }
    
    return ips;
}

bool GeoLocator::is_ip_in_range(const string& ip, const string& start_ip, const string& end_ip) {
    struct in_addr ip_addr, start_addr, end_addr;
    
    inet_pton(AF_INET, ip.c_str(), &ip_addr);
    inet_pton(AF_INET, start_ip.c_str(), &start_addr);
    inet_pton(AF_INET, end_ip.c_str(), &end_addr);
    
    uint32_t ip_val = ntohl(ip_addr.s_addr);
    uint32_t start_val = ntohl(start_addr.s_addr);
    uint32_t end_val = ntohl(end_addr.s_addr);
    
    return ip_val >= start_val && ip_val <= end_val;
}

string GeoLocator::get_asn(const string& ip) {
    if (!curl) return "Unknown";
    
    string url = "https://api.hackertarget.com/aslookup/?q=" + ip;
    string response;
    
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    
    CURLcode res = curl_easy_perform(curl);
    
    if (res != CURLE_OK || response.empty()) {
        return "Unknown";
    }
    
    // Parse ASN information
    size_t pos = response.find(",");
    if (pos != string::npos) {
        return response.substr(pos + 1);
    }
    
    return "Unknown";
}

vector<string> GeoLocator::get_ips_by_asn(const string& asn) {
    vector<string> ips;
    
    // This would require access to BGP routing tables
    // Simplified implementation using Team Cymru
    
    if (!curl) return ips;
    
    string url = "https://bgpview.io/asn/" + asn + "/prefixes";
    string response;
    
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    
    CURLcode res = curl_easy_perform(curl);
    
    if (res != CURLE_OK || response.empty()) {
        return ips;
    }
    
    // Parse HTML for IP prefixes (simplified)
    regex ip_regex(R"((\d+\.\d+\.\d+\.\d+/\d+))");
    smatch matches;
    
    string::const_iterator search_start(response.cbegin());
    while (regex_search(search_start, response.cend(), matches, ip_regex)) {
        ips.push_back(matches[1].str());
        search_start = matches.suffix().first;
    }
    
    return ips;
}

void GeoLocator::clear_cache() {
    country_cache.clear();
}

void GeoLocator::save_cache(const string& filename) {
    ofstream file(filename);
    if (!file.is_open()) return;
    
    for (const auto& entry : country_cache) {
        file << entry.first << ":";
        for (size_t i = 0; i < entry.second.size(); i++) {
            file << entry.second[i];
            if (i < entry.second.size() - 1) {
                file << ",";
            }
        }
        file << endl;
    }
    
    file.close();
}

void GeoLocator::load_cache(const string& filename) {
    ifstream file(filename);
    if (!file.is_open()) return;
    
    country_cache.clear();
    string line;
    
    while (getline(file, line)) {
        size_t colon_pos = line.find(':');
        if (colon_pos == string::npos) continue;
        
        string country = line.substr(0, colon_pos);
        string ip_list = line.substr(colon_pos + 1);
        
        vector<string> ips;
        size_t start = 0;
        size_t comma_pos = ip_list.find(',');
        
        while (comma_pos != string::npos) {
            ips.push_back(ip_list.substr(start, comma_pos - start));
            start = comma_pos + 1;
            comma_pos = ip_list.find(',', start);
        }
        
        ips.push_back(ip_list.substr(start));
        country_cache[country] = ips;
    }
    
    file.close();
}
