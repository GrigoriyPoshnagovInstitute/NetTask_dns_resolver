cmake_minimum_required(VERSION 3.20)
project(dns_resolver)

set(CMAKE_CXX_STANDARD 17)

add_executable(dns_resolver
        main.cpp
        Resolver.cpp
        Resolver.h
        DnsProtocol.cpp
        DnsProtocol.h
)

target_link_libraries(dns_resolver ws2_32)