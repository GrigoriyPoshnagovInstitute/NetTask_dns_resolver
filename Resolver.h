#ifndef RESOLVER_H
#define RESOLVER_H

#include <string>
#include <vector>
#include <map>
#include <ctime>
#include "DnsProtocol.h"

struct CacheEntry {
    std::vector<DnsRecord> records;
    time_t expires_at;
};

class Resolver {
public:
    Resolver();
    ~Resolver();
    void SetDebug(bool debug);
    void Run(const std::string& domain, const std::string& type_str);
    void ClearCache();

private:
    bool debug_mode;
    std::map<std::string, CacheEntry> cache;
    std::vector<std::string> root_servers;
    std::vector<DnsRecord> QueryServer(const std::string& ip, const std::string& domain, uint16_t type);
    std::vector<DnsRecord> SendUdp(const std::string& ip, const std::vector<uint8_t>& packet);
    std::vector<DnsRecord> SendTcp(const std::string& ip, const std::vector<uint8_t>& packet);
    std::vector<DnsRecord> ParseResponse(const std::vector<uint8_t>& response);

    uint16_t StringToType(const std::string& type);
    std::string TypeToString(uint16_t type);
    void PrintRecords(const std::vector<DnsRecord>& records);
};

#endif