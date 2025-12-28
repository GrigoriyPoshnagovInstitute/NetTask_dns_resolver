#include <iostream>
#include <string>
#include <vector>
#include "Resolver.h"

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "Usage: ./dns_resolver <domain> <type> [-d]\n";
        std::cout << "Commands:\n  clear-cache : Clears local cache\n";
        return 1;
    }

    std::string arg1 = argv[1];
    Resolver res;

    if (arg1 == "clear-cache") {
        res.ClearCache();
        return 0;
    }

    std::string domain = argv[1];
    std::string type = argv[2];
    bool debug = false;

    if (argc > 3) {
        std::string flag = argv[3];
        if (flag == "-d") debug = true;
    }

    res.SetDebug(debug);
    res.Run(domain, type);

    return 0;
}