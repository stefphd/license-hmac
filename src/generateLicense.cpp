
#include "licutils.h"
#include <iostream>
#include <fstream>

#ifndef PRIVATE_KEY
#define PRIVATE_KEY "0000000000000000"
#endif

int main(int argc, char* argv[]) {
    // Get command line arguments
    std::string hostname, mac;
    switch (argc) {
        case 2:
            if (!read_mac_from_file(std::string(argv[1]), hostname, mac)) {
                std::cerr << "Unable to read MAC file " << argv[1] << std::endl;
                return 1;
            }
            if (hostname == "") {
                std::cerr << "Unable to read hostname from " << argv[1] << std::endl;
                return 1;
            }
            if (mac == "") {
                std::cerr << "Unable to read hostname from " << argv[1] << std::endl;
                return 1;
            }
            break;
        case 3:
            hostname = argv[1];
            mac = argv[2];
            break;
        default:
            std::cerr << "Usage: " << argv[0] << " <HOST_NAME> <MAC_ADDRESS>" << std::endl;
            std::cerr << "       " << argv[0] << " <MAC_ADDRESS_FILE>" << std::endl;
            // wait
            std::cout << "Press Enter to continue...";
            std::cin.get();  
            return 1;
    }
    // License filename
    std::string lic_filename = "license-" + hostname + ".txt";

    // Generate the license key
    std::cout << "Generating license key..." << std::endl;
    std::string license_key = generate_hmac(mac, PRIVATE_KEY);
    std::cout << "License key: " << license_key << std::endl;

    // Save the license key to a file
    std::ofstream outFile(lic_filename);
    if (outFile.is_open()) {
        outFile << license_key;
        outFile.close();
        std::cout << "License key saved to " << lic_filename << std::endl;
    } else {
        std::cerr << "Unable to open file to write license key" << std::endl;
    }

    // wait
    std::cout << "Press Enter to continue...";
    std::cin.get();  
    return 0;
}