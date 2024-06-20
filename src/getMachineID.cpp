#include "licutils.h"
#include <iostream>
#include <fstream>

int main() {
    // filename
    std::string filename_prefix = "machine_ID-";

    // get machine hostname and MAC
    std::cout << "Generating machine ID..." << std::endl;
    std::string hostname = get_hostname();
    std::string mac = get_mac();
    std::cout << "Host name  : " << hostname << std::endl;
    std::cout << "MAC address: " << mac << std::endl;

    // write hostname and MAC to file
    std::string filename = filename_prefix + hostname + ".txt";
    if (write_mac_to_file(filename, hostname, mac))
        std::cout << "Machine ID saved to " << filename << std::endl;
    else 
        std::cerr << "Unable to open file: " << filename << std::endl;
    
    // wait
    std::cout << "Press Enter to continue...";
    std::cin.get();  
    return 0;
}
