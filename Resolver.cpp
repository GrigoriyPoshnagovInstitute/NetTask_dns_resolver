#include "Resolver.h"
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <algorithm>

Resolver::Resolver() : debug_mode(false) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    root_servers = {
        "198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.83.42",
        "192.203.230.10", "192.5.5.241", "192.112.36.4", "128.63.2.53",
        "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.91.13",
        "202.12.27.33"
    };
}

Resolver::~Resolver() {
    WSACleanup();
}

void Resolver::SetDebug(bool debug) {
    debug_mode = debug;
}

void Resolver::ClearCache() {
    cache.clear();
    std::cout << "Cache cleared." << std::endl;
}

uint16_t Resolver::StringToType(const std::string& type) {
    if (type == "A") return A;
    if (type == "NS") return NS;
    if (type == "CNAME") return CNAME;
    if (type == "AAAA") return AAAA;
    return A;
}

std::string Resolver::TypeToString(uint16_t type) {
    switch (type) {
        case A: return "A";
        case NS: return "NS";
        case CNAME: return "CNAME";
        case AAAA: return "AAAA";
        default: return std::to_string(type);
    }
}

void Resolver::Run(const std::string& domain, const std::string& type_str) {
    uint16_t qtype = StringToType(type_str);
    std::string key = domain + "_" + std::to_string(qtype);

    if (cache.count(key)) {
        if (time(nullptr) < cache[key].expires_at) {
            std::cout << "[Cache Hit]" << std::endl;
            PrintRecords(cache[key].records);
            return;
        } else {
            cache.erase(key);
        }
    }

    std::string current_ns_ip = "";
    for (const auto& root : root_servers) {
        current_ns_ip = root;
        if (debug_mode) std::cout << "Trying root server: " << root << std::endl;
        auto initial_resp = QueryServer(current_ns_ip, domain, qtype);
        if (!initial_resp.empty()) break;
    }

    std::string target_domain = domain;
    bool solved = false;

    while (!solved) {
        if (debug_mode) std::cout << "Querying " << current_ns_ip << " for " << target_domain << std::endl;
        std::vector<DnsRecord> response = QueryServer(current_ns_ip, target_domain, qtype);

        if (response.empty()) {
            std::cerr << "No response from " << current_ns_ip << std::endl;
            return;
        }

        bool found_answer = false;
        std::vector<std::string> referrals;
        std::map<std::string, std::string> glue;

        for (const auto& rec : response) {
            if (rec.type == qtype && rec.name == target_domain) {
                found_answer = true;
            }
            if (rec.type == NS) {
                referrals.push_back(rec.parsed_data);
            }
            if (rec.type == A) {
                glue[rec.name] = rec.parsed_data;
            }
        }

        if (found_answer) {
            std::vector<DnsRecord> answers;
            uint32_t min_ttl = 3600;
            for (const auto& rec : response) {
                if (rec.type == qtype) {
                    answers.push_back(rec);
                    if (rec.ttl < min_ttl) min_ttl = rec.ttl;
                }
            }
            cache[key] = {answers, time(nullptr) + min_ttl};
            PrintRecords(answers);
            solved = true;
        } else if (!referrals.empty()) {
            bool glue_found = false;
            for (const auto& ns : referrals) {
                if (glue.count(ns)) {
                    current_ns_ip = glue[ns];
                    glue_found = true;
                    break;
                }
            }
            if (!glue_found) {
                if (debug_mode) std::cout << "Resolving glue for " << referrals[0] << std::endl;
                Resolver sub_res;
                sub_res.SetDebug(debug_mode);
                sub_res.Run(referrals[0], "A");
                return;
            }
        } else {
            std::cout << "NXDOMAIN or no records found." << std::endl;
            return;
        }
    }
}

std::vector<DnsRecord> Resolver::QueryServer(const std::string& ip, const std::string& domain, uint16_t type) {
    DnsHeader header = {};
    header.id = htons((uint16_t)GetCurrentProcessId());
    header.flags = htons(0x0000);
    header.q_count = htons(1);

    std::vector<uint8_t> packet;
    uint8_t* p = (uint8_t*)&header;
    packet.insert(packet.end(), p, p + sizeof(header));
    WriteName(packet, domain);

    uint16_t t = htons(type);
    uint16_t c = htons(1);
    packet.insert(packet.end(), (uint8_t*)&t, (uint8_t*)&t + 2);
    packet.insert(packet.end(), (uint8_t*)&c, (uint8_t*)&c + 2);

    return SendUdp(ip, packet);
}

std::vector<DnsRecord> Resolver::SendUdp(const std::string& ip, const std::vector<uint8_t>& packet) {
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in srv = {};
    srv.sin_family = AF_INET;
    srv.sin_port = htons(53);
    inet_pton(AF_INET, ip.c_str(), &srv.sin_addr);

    DWORD timeout = 2000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    sendto(sock, (const char*)packet.data(), (int)packet.size(), 0, (sockaddr*)&srv, sizeof(srv));

    std::vector<uint8_t> buf(4096);
    sockaddr_in from;
    int fromlen = sizeof(from);
    int len = recvfrom(sock, (char*)buf.data(), (int)buf.size(), 0, (sockaddr*)&from, &fromlen);

    closesocket(sock);
    if (len > 0) {
        buf.resize(len);
        DnsHeader* h = (DnsHeader*)buf.data();
        if (ntohs(h->flags) & 0x0200) {
            return SendTcp(ip, packet);
        }
        return ParseResponse(buf);
    }
    return {};
}

std::vector<DnsRecord> Resolver::SendTcp(const std::string& ip, const std::vector<uint8_t>& packet) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    DWORD timeout = 2000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

    sockaddr_in srv = {};
    srv.sin_family = AF_INET;
    srv.sin_port = htons(53);
    inet_pton(AF_INET, ip.c_str(), &srv.sin_addr);

    if (connect(sock, (sockaddr*)&srv, sizeof(srv)) < 0) {
        closesocket(sock);
        return {};
    }

    uint16_t len = htons((uint16_t)packet.size());
    send(sock, (const char*)&len, 2, 0);
    send(sock, (const char*)packet.data(), (int)packet.size(), 0);

    char len_buf[2];
    int r_len = recv(sock, len_buf, 2, 0);
    if (r_len < 2) {
        closesocket(sock);
        return {};
    }
    uint16_t resp_len = ntohs(*(uint16_t*)len_buf);

    std::vector<uint8_t> buf(resp_len);
    int total = 0;
    while (total < resp_len) {
        int r = recv(sock, (char*)buf.data() + total, resp_len - total, 0);
        if (r <= 0) break;
        total += r;
    }
    closesocket(sock);
    return ParseResponse(buf);
}

std::vector<DnsRecord> Resolver::ParseResponse(const std::vector<uint8_t>& response) {
    if (response.size() < sizeof(DnsHeader)) return {};

    std::vector<DnsRecord> results;
    DnsHeader* h = (DnsHeader*)response.data();
    int pos = sizeof(DnsHeader);

    int q_count = ntohs(h->q_count);
    for(int i=0; i<q_count; ++i) {
        ParseName(response.data(), pos, (int)response.size());
        pos += 4;
    }

    int total_rr = ntohs(h->ans_count) + ntohs(h->auth_count) + ntohs(h->add_count);
    for (int i = 0; i < total_rr; ++i) {
        if (pos >= (int)response.size()) break;

        DnsRecord rec;
        rec.name = ParseName(response.data(), pos, (int)response.size());

        rec.type = (response[pos] << 8) | response[pos + 1];
        rec.rclass = (response[pos + 2] << 8) | response[pos + 3];
        rec.ttl = (response[pos + 4] << 24) | (response[pos + 5] << 16) | (response[pos + 6] << 8) | response[pos + 7];
        uint16_t rdlength = (response[pos + 8] << 8) | response[pos + 9];
        pos += 10;

        if (rec.type == A && rdlength == 4) {
            char ip[16];
            snprintf(ip, sizeof(ip), "%d.%d.%d.%d", response[pos], response[pos+1], response[pos+2], response[pos+3]);
            rec.parsed_data = ip;
        } else if (rec.type == AAAA && rdlength == 16) {
            char ip6[46];
            inet_ntop(AF_INET6, &response[pos], ip6, sizeof(ip6));
            rec.parsed_data = ip6;
        } else if (rec.type == NS || rec.type == CNAME) {
            int tmp = pos;
            rec.parsed_data = ParseName(response.data(), tmp, (int)response.size());
        }

        pos += rdlength;
        results.push_back(rec);
    }
    return results;
}

void Resolver::PrintRecords(const std::vector<DnsRecord>& records) {
    for (const auto& rec : records) {
        std::cout << rec.name << " " << rec.ttl << " " << TypeToString(rec.type) << " " << rec.parsed_data << std::endl;
    }
}