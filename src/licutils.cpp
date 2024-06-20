#include "licutils.h"
#include <string>
#include <fstream>
#include <vector>
#include <sstream>
#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#include <windows.h>
#pragma comment(lib, "iphlpapi.lib")
#else
#include <unistd.h>
#include <limits.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>
#endif

#include <openssl/hmac.h>
#include <openssl/evp.h>

// Function to check if a file exists
bool file_exists(const std::string& filename) {
    std::ifstream file(filename);
    return file.good();
}

// Function to split a string by delimiter
std::vector<std::string> split_string(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::stringstream ss(str);
    std::string token;
    while (std::getline(ss, token, delimiter))
        tokens.push_back(token);
    return tokens;
}

// Get the MAC address
std::string get_mac() {
#ifdef _WIN32
    IP_ADAPTER_INFO AdapterInfo[16];
    DWORD dwBufLen = sizeof(AdapterInfo);
    DWORD dwStatus = GetAdaptersInfo(AdapterInfo, &dwBufLen);
    if (dwStatus != ERROR_SUCCESS) {
        return "";
    }

    PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
    char mac_addr[18];
    sprintf(mac_addr, "%02X:%02X:%02X:%02X:%02X:%02X",
        pAdapterInfo->Address[0],
        pAdapterInfo->Address[1],
        pAdapterInfo->Address[2],
        pAdapterInfo->Address[3],
        pAdapterInfo->Address[4],
        pAdapterInfo->Address[5]);
    return std::string(mac_addr);
#else
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return "";
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        family = ifa->ifa_addr->sa_family;

        if (family == AF_PACKET && ifa->ifa_data != NULL) {
            struct sockaddr_ll *s = (struct sockaddr_ll*)ifa->ifa_addr;
            char mac_addr[18];
            sprintf(mac_addr, "%02X:%02X:%02X:%02X:%02X:%02X",
                (s->sll_addr[0]), (s->sll_addr[1]),
                (s->sll_addr[2]), (s->sll_addr[3]),
                (s->sll_addr[4]), (s->sll_addr[5]));
            freeifaddrs(ifaddr);
            return std::string(mac_addr);
        }
    }

    freeifaddrs(ifaddr);
    return "";
#endif
}

// Generate HMAC-SHA256
std::string generate_hmac(const std::string &data, const std::string &key) {
    unsigned char* result;
    unsigned int len = 32; // SHA256 outputs 256 bits (32 bytes)
    result = (unsigned char*)malloc(sizeof(char) * len);

    HMAC_CTX* ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key.c_str(), key.length(), EVP_sha256(), NULL);
    HMAC_Update(ctx, (unsigned char*)&data[0], data.length());
    HMAC_Final(ctx, result, &len);
    HMAC_CTX_free(ctx);

    char hexstr[65];
    for (int i = 0; i < len; i++) {
        sprintf(hexstr + (i * 2), "%02x", result[i]);
    }
    hexstr[64] = 0; // null-terminate the string
    free(result);

    return std::string(hexstr);
}

std::string get_hostname() {
    char hostname[256];
#ifdef _WIN32
    DWORD size = sizeof(hostname);
    if (!GetComputerNameA(hostname, &size)) 
#else
    if (gethostname(hostname, sizeof(hostname)) != 0)
#endif
    {
        return "unknown";
    }
    return std::string(hostname);
}

// Validate license
bool validate_lic(const std::string &mac, const std::string &private_key, const std::string &license) {
    std::string lic_key = generate_hmac(mac, private_key);
    return lic_key == license;
}

std::string find_lic_file(const std::string& lic_filename, std::vector<std::string> search_envs) {

    // Check current directory
    if (file_exists(lic_filename)) {
        return lic_filename;
    }

    // Search in environment variables 'search_envs'
#ifdef _WIN32
    const char delimiter = ';'; // delimiter for multiple dirs
#else
    const char delimiter = ':'; // delimiter for multiple dirs
#endif
    for (const auto& search_env : search_envs) {
        const char* env_val = getenv(search_env.c_str());
        if (env_val == nullptr) {
            continue;
        }
        std::vector<std::string> dirs = split_string(env_val, delimiter);
        for (const auto& dir : dirs) {
            if (file_exists(std::string(dir) + "/" + lic_filename)) {
                return std::string(dir) + "/" + lic_filename;
            }
        }
    }

    // NOT found
    return "";
}

// Read lic key from file
std::string read_lic_key(const std::string &filename) {
    std::ifstream inFile(filename);
    std::string lic_key;
    if (inFile.is_open()) {
        std::getline(inFile, lic_key);
        inFile.close();
    }
    return lic_key;
}

/** Write hostname and MAC to file */
bool write_mac_to_file(const std::string &filename, const std::string &hostname, std::string &mac) {
      std::ofstream outFile(filename);
    if (!outFile.is_open()) {
        return false;
    }
    outFile << hostname << std::endl;
    outFile << mac;
    outFile.close();
    return true;
}

/** Read mac and hostname from file */
bool read_mac_from_file(const std::string &filename, std::string &hostname, std::string &mac) {
    std::ifstream inFile(filename);
    if (!inFile.is_open()) {
        hostname = "";
        mac = "";
        return false;
    }
    std::getline(inFile, hostname);
    std::getline(inFile, mac);
    return true;
}