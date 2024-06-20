#include "licutils.h"
#include <iostream>
#include <fstream>
#include <cstdlib>  // For getenv function
#include <cstring>  // For strcpy, strcat functions
#include <vector>

#ifndef PRIVATE_KEY
#define PRIVATE_KEY "0"
#endif

int main() {
    // get machine current hostname and MAC
    std::string hostname = get_hostname();
    std::string mac = get_mac();

    // look for minos-license-$hostname.txt
    std::string lic_filename = "license-" + hostname + ".txt";
    std::vector<std::string> search_envs = {"MINOS_LIC_DIR", 
                                            "MINOS_LICENSE_DIR", 
                                            "MINOS_LIC", 
                                            "MINOS_LICENSE",                               
                                            "USERPROFILE",
                                            "HOME",
                                            "PATH"
                                            };
    lic_filename = find_lic_file(lic_filename, search_envs);
    if (lic_filename == "") {
        std::cerr << "Unable to find license file " << lic_filename << std::endl;
        return 1;
    }
    else
        std::cout << "Found license file " << lic_filename << std::endl;

    // get license key from file
    std::string lic_key = read_lic_key(lic_filename);

    // validate license key
    if (!validate_lic(mac, PRIVATE_KEY, lic_key)) {
        std::cerr << "Unvalid license" << std::endl;
        return 1;
    }

    std::cout << "Valid license" << std::endl;
    return 0;
}