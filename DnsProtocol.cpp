#include "DnsProtocol.h"
#include <winsock2.h>
#include <iostream>

void ChangeEndianness(DnsHeader* header) {
    header->id = htons(header->id);
    header->flags = htons(header->flags);
    header->q_count = htons(header->q_count);
    header->ans_count = htons(header->ans_count);
    header->auth_count = htons(header->auth_count);
    header->add_count = htons(header->add_count);
}

std::string ParseName(const unsigned char* buffer, int& pos, int len) {
    std::string name;
    int i = pos;
    bool jumped = false;
    int next_pos = -1;

    while (i < len) {
        uint8_t len_byte = buffer[i];
        if (len_byte == 0) {
            i++;
            break;
        }

        if ((len_byte & 0xC0) == 0xC0) {
            if (!jumped) {
                next_pos = i + 2;
            }
            uint16_t offset = ((len_byte & 0x3F) << 8) | buffer[i + 1];
            i = offset;
            jumped = true;
        } else {
            i++;
            if (!name.empty()) name += ".";
            for (int j = 0; j < len_byte; j++) {
                name += (char)buffer[i + j];
            }
            i += len_byte;
        }
    }

    if (jumped) {
        pos = next_pos;
    } else {
        pos = i;
    }
    return name;
}

void WriteName(std::vector<uint8_t>& buffer, const std::string& name) {
    std::string temp = name + ".";
    size_t start = 0;
    size_t end = temp.find('.');

    while (end != std::string::npos) {
        std::string label = temp.substr(start, end - start);
        buffer.push_back((uint8_t)label.length());
        for (char c : label) {
            buffer.push_back(c);
        }
        start = end + 1;
        end = temp.find('.', start);
    }
    buffer.push_back(0);
}