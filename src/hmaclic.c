/*  File hmaclic.c
    Licensening using MAC address.
    Copyright (C) 2024 Stefano Lovato
*/

#include "hmaclic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
#include <arpa/inet.h>
#endif
#include <openssl/hmac.h>
#include <openssl/evp.h>

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
    char *mac_addr = NULL;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return NULL;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        if (ifa->ifa_addr->sa_family == AF_PACKET && ifa->ifa_data != NULL) {
            struct sockaddr_ll *s = (struct sockaddr_ll *)ifa->ifa_addr;
            mac_addr = malloc(18);
            sprintf(mac_addr, "%02X:%02X:%02X:%02X:%02X:%02X",
                (s->sll_addr[0]), (s->sll_addr[1]),
                (s->sll_addr[2]), (s->sll_addr[3]),
                (s->sll_addr[4]), (s->sll_addr[5]));
            break; // Exit the loop after finding the MAC address
        }
    }

    freeifaddrs(ifaddr);
    return mac_addr;
#endif
}

// Generate HMAC-SHA256
char *generate_hmac(const char *mac, const char *key) {
    unsigned char result[32]; // SHA256 outputs 256 bits (32 bytes)
    unsigned int len = 32;

    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key, strlen(key), EVP_sha256(), NULL);
    HMAC_Update(ctx, (unsigned char *)mac, strlen(mac));
    HMAC_Final(ctx, result, &len);
    HMAC_CTX_free(ctx);

    char *hexstr = malloc(65);
    for (int i = 0; i < len; i++) {
        sprintf(hexstr + (i * 2), "%02x", result[i]);
    }
    hexstr[64] = 0; // null-terminate the string
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
int validate_lic(const char *mac, const char *key, const char *license) {
    char *lic_key = generate_hmac(mac, key);
    int result = strcmp(lic_key, license);
    free(lic_key);
    return result;
}

// Find license file
char *find_lic_file(const char *filename, char **search_envs, int env_len) {
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
            char full_path[HMACLIC_MAXPATH];
            snprintf(full_path, sizeof(full_path), "%s/%s", dirs[j], filename);
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
char *read_lic_key(const char *filename) {
    FILE *inFile = fopen(filename, "r");
    if (!inFile) {
        return NULL;
    }
    char *lic_key = malloc(HMACLIC_MAXPATH);
    if (fgets(lic_key, HMACLIC_MAXPATH, inFile) == NULL) {
        free(lic_key);
        fclose(inFile);
        return NULL;
    }
    fclose(inFile);
    return lic_key;
}

// Write license key to file
int write_lic_key(const char *filename, const char *key) {
    FILE* outFile = fopen(filename, "w");
    if (outFile != NULL) {
        fprintf(outFile, "%s", key);
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