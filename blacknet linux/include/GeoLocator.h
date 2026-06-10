#ifndef GEOLOCATOR_H
#define GEOLOCATOR_H

#include <string>
#include <vector>
#include <map>
#include <cstddef>      // FIX: added for size_t used in write_callback
#include <curl/curl.h>

class GeoLocator {
private:
    CURL* curl;
    std::string api_key;
    std::map<std::string, std::vector<std::string>> country_cache;

    static size_t write_callback(void* contents, size_t size, size_t nmemb, std::string* output);
    std::string get_country_code(const std::string& country_name);

public:
    GeoLocator();
    ~GeoLocator();

    bool set_api_key(const std::string& key);

    // IP geolocation
    std::string get_ip_location(const std::string& ip);
    std::string get_country(const std::string& ip);
    std::string get_city(const std::string& ip);
    std::string get_isp(const std::string& ip);

    // Reverse geolocation (country to IPs)
    std::vector<std::string> get_ips_by_country(const std::string& country);
    std::vector<std::string> get_ips_by_city(const std::string& country, const std::string& city);

    // IP range utilities
    std::vector<std::string> generate_ip_range(const std::string& start_ip, const std::string& end_ip);
    bool is_ip_in_range(const std::string& ip, const std::string& start_ip, const std::string& end_ip);

    // ASN lookup
    std::string get_asn(const std::string& ip);
    std::vector<std::string> get_ips_by_asn(const std::string& asn);

    // Cache management
    void clear_cache();
    void save_cache(const std::string& filename);
    void load_cache(const std::string& filename);
};

#endif // GEOLOCATOR_H
