#ifndef DNS_PROTOCOL_H
#define DNS_PROTOCOL_H

#include <string>
#include <vector>
#include <cstdint>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#pragma pack(push, 1)
struct DnsHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t q_count;
    uint16_t ans_count;
    uint16_t auth_count;
    uint16_t add_count;
};
#pragma pack(pop)

enum DnsType : uint16_t {
    A = 1,
    NS = 2,
    CNAME = 5,
    AAAA = 28
};

struct DnsRecord {
    std::string name;
    uint16_t type;
    uint16_t rclass;
    uint32_t ttl;
    std::vector<uint8_t> rdata;
    std::string parsed_data;
};

void ChangeEndianness(DnsHeader* header);
std::string ParseName(const unsigned char* buffer, int& pos, int len);
void WriteName(std::vector<uint8_t>& buffer, const std::string& name);

#endif