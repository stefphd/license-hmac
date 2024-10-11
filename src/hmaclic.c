/*  File hmaclic.c
    Licensening using MAC address.
    Copyright (C) 2024 Stefano Lovato
*/

#include "hmaclic.h"
#include "sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#include <windows.h>
#pragma comment(lib, "iphlpapi.lib")
#else
#include <unistd.h>
#include <ifaddrs.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_ether.h> 
#endif

// Function to check if a file exists
int file_exists(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file) {
        fclose(file);
        return 0;
    }
    return 1;
}

// Function to split a string by delimiter
char **split_string(const char *str, char delimiter, int *count) {
    char *temp = strdup(str);  // Duplicate string for tokenization
    char *token;
    char **tokens = NULL;
    int tokens_size = 0;

    token = strtok(temp, &delimiter);
    while (token) {
        tokens = realloc(tokens, sizeof(char *) * (tokens_size + 1));
        tokens[tokens_size] = strdup(token);
        tokens_size++;
        token = strtok(NULL, &delimiter);
    }
    free(temp);
    *count = tokens_size;
    return tokens;
}

// Helper function to parse "YYYY-MM-DD" into a struct tm
int parse_date(const char *date_str, struct tm *tm_date) {
    if (sscanf(date_str, "%d-%d-%d", &tm_date->tm_year, &tm_date->tm_mon, &tm_date->tm_mday) != 3) {
        return 1;  // Invalid date format
    }
    tm_date->tm_year -= 1900;  // tm_year is years since 1900
    tm_date->tm_mon -= 1;      // tm_mon is 0-based (0 = January)
    tm_date->tm_hour = 0;
    tm_date->tm_min = 0;
    tm_date->tm_sec = 0;
    tm_date->tm_isdst = -1;    // Daylight saving time information is not used

    return 0;
}

// Function to check if the license is expired
int is_expired(const char *exp_date) {
    struct tm exp_date_tm = {0};
    if (parse_date(exp_date, &exp_date_tm) != 0) {
        return 1;  // Invalid expiration date
    }
    time_t exp_time = mktime(&exp_date_tm);
    time_t now = time(NULL);
    // Compare expiration date with current date
    return difftime(exp_time, now) < 0; // Return 1 if expired, 0 otherwise
}

// Get the MAC address
char *get_mac() {
#ifdef _WIN32
    IP_ADAPTER_INFO AdapterInfo[16];
    DWORD dwBufLen = sizeof(AdapterInfo);
    DWORD dwStatus = GetAdaptersInfo(AdapterInfo, &dwBufLen);
    if (dwStatus != ERROR_SUCCESS) {
        return NULL;
    }

    PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
    char *mac_addr = malloc(18);
    sprintf(mac_addr, "%02X:%02X:%02X:%02X:%02X:%02X",
        pAdapterInfo->Address[0],
        pAdapterInfo->Address[1],
        pAdapterInfo->Address[2],
        pAdapterInfo->Address[3],
        pAdapterInfo->Address[4],
        pAdapterInfo->Address[5]);
    return mac_addr;
#else
    struct ifaddrs *ifaddr, *ifa;
    char* mac_addr = NULL;
    int sockfd;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    // Create a socket to use with ioctl
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        freeifaddrs(ifaddr);
        exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET) {
            continue; // Only interested in AF_INET for retrieving MAC addresses
        }
        struct ifreq ifr;
        strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ-1);
        if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
            perror("ioctl");
            continue;
        }
        unsigned char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
        // skip 00:00:00:00:00:00
        if (mac[0] == 0 || mac[1] == 0 || mac[2] == 0 || mac[3] == 0 || mac[4] == 0 || mac[5] == 0) {
            continue;
        }
        // format first valid and exit
        mac_addr = malloc(18);
        sprintf(mac_addr, "%02X:%02X:%02X:%02X:%02X:%02X", 
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        break;
    }
    close(sockfd);
    freeifaddrs(ifaddr);
    return mac_addr;
#endif
}

// Generate HMAC-SHA256
char *generate_hmac(const char *mac, const char *exp_date, const char *key) {
    char data[256] = { '\0' };
    // Combine MAC and exp date as <mac>|<exp-date>
    sprintf(data, "%s|%s", mac, exp_date);

    unsigned char hmac[SHA256_BLOCK_SIZE] = { '\0' };
    hmac_sha256(key, data, hmac);

    char *hexstr = malloc(SHA256_BLOCK_SIZE * 2 + 1);
    for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++) {
        sprintf(hexstr + (i * 2), "%02x", data[i]);
    }
    hexstr[SHA256_BLOCK_SIZE * 2] = '\0'; // Null-terminate

    return hexstr;
}

// Hexadecimal conversion
char *to_hex(const unsigned char *data, size_t len) {
    char *hexstr = malloc(len * 2 + 1);
    for (size_t i = 0; i < len; i++) {
        sprintf(hexstr + (i * 2), "%02x", data[i]);
    }
    hexstr[len * 2] = '\0'; // Null-terminate
    return hexstr;
}

char *get_hostname() {
    char *hostname = malloc(HMACLIC_MAXPATH);
#ifdef _WIN32
    DWORD size = HMACLIC_MAXPATH;
    if (!GetComputerNameA(hostname, &size)) {
        free(hostname);
        return "unknown";
    }
#else
    if (gethostname(hostname, HMACLIC_MAXPATH) != 0) {
        free(hostname);
        return "unknown";
    }
#endif
    return hostname;
}

// Validate license
int validate_lic(const char *mac, const char *exp_date, const char *key, const char *license) {
    // Check if the license is expired
    if (is_expired(exp_date)) {
        return EXIT_EXPIRED;
    }
    // Validate HMAC
    char *lic_key = generate_hmac(mac, exp_date, key);
    int result = strcmp(lic_key, license);
    free(lic_key);
    if (result) {
        return EXIT_UNVALID;
    }
    return EXIT_VALID;
}

// Find license file
char *find_lic_file(const char *filename, const char **search_envs, int env_len) {
    // Check current directory
    if (!file_exists(filename)) {
        return strdup(filename);
    }
    // Search in environment variables 'search_envs'
#ifdef _WIN32
    const char delimiter = ';'; // delimiter for multiple dirs
#else
    const char delimiter = ':'; // delimiter for multiple dirs
#endif

    for (int i = 0; i < env_len; i++) {
        const char *env_val = getenv(search_envs[i]);
        if (env_val == NULL) {
            continue;
        }
        int dir_count;
        char **dirs = split_string(env_val, delimiter, &dir_count);
        for (int j = 0; j < dir_count; j++) {
            // try using dirs[j] as filename
            char full_file[HMACLIC_MAXPATH];
            sprintf(full_file, "%s", dirs[j]);
            if (!file_exists(full_file)) {
                for (int k = 0; k < dir_count; k++) {
                    free(dirs[k]);
                }
                free(dirs);
                return strdup(full_file);
            }
            // try looking for filename in dirs[j]
            char full_path[HMACLIC_MAXPATH];
            sprintf(full_path, "%s/%s", dirs[j], filename);
            if (!file_exists(full_path)) {
                for (int k = 0; k < dir_count; k++) {
                    free(dirs[k]);
                }
                free(dirs);
                return strdup(full_path);
            }
            free(dirs[j]);
        }
        free(dirs);
    }

    // NOT found
    return NULL;
}

// Read license key from file
int read_lic_key(const char *filename, char **key, char **exp_date) {
    FILE *inFile = fopen(filename, "r");
    if (!inFile) {
        return 1;
    }
    *key = malloc(HMACLIC_MAXPATH);
    *exp_date = malloc(11); // Format YYYY-MM-DD
    if (fgets(*key, HMACLIC_MAXPATH, inFile) == NULL || fgets(*exp_date, 11, inFile) == NULL) {
        free(*key);
        free(*exp_date);
        fclose(inFile);
        return 1;
    }
    fclose(inFile);
    // Remove newline characters from the key and expiration date
    size_t len = strlen(*key);
    if (len > 0 && (*key)[len - 1] == '\n') {
        (*key)[len - 1] = '\0';
    }
    len = strlen(*exp_date);
    if (len > 0 && (*exp_date)[len - 1] == '\n') {
        (*exp_date)[len - 1] = '\0';
    }
    return 0;
}

// Write license key to file
int write_lic_key(const char *filename, const char *key, const char *exp_date) {
    FILE* outFile = fopen(filename, "w");
    if (outFile != NULL) {
        fprintf(outFile, "%s\n", key);
        fprintf(outFile, "%s", exp_date);
        fclose(outFile);
        return 0;
    }
    return 1;
}

// Write hostname and MAC to file
int write_mac_to_file(const char *filename, const char *hostname, const char *mac) {
    FILE *outFile = fopen(filename, "w");
    if (!outFile) {
        return 1;
    }
    fprintf(outFile, "%s\n", hostname);
    fprintf(outFile, "%s", mac);
    fclose(outFile);
    return 0;
}

// Read MAC and hostname from file
int read_mac_from_file(const char *filename, char **hostname, char **mac) {
    FILE *inFile = fopen(filename, "r");
    if (!inFile) {
        *hostname = NULL;
        *mac = NULL;
        return 1;
    }
    *hostname = malloc(HMACLIC_MAXPATH);
    *mac = malloc(HMACLIC_MAXPATH);
    if (fgets(*hostname, HMACLIC_MAXPATH, inFile) == NULL || fgets(*mac, HMACLIC_MAXPATH, inFile) == NULL) {
        free(*hostname);
        free(*mac);
        fclose(inFile);
        return 1;
    }
    // Remove newline character from hostname
    size_t len = strlen(*hostname);
    if (len > 0 && (*hostname)[len - 1] == '\n') {
        (*hostname)[len - 1] = '\0';
    }
    // Remove newline character from MAC address
    len = strlen(*mac);
    if (len > 0 && (*mac)[len - 1] == '\n') {
        (*mac)[len - 1] = '\0';
    }
    fclose(inFile);
    return 0; // Success
}