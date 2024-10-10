/** 
 * @file hmaclic.h
 * @brief Licensening using MAC address.
 * 
 * Licensening using MAC address. 
 * Typical usage is (without some checks of exit value):
 *
 * - Get the machine ID file:
 * ```c
 * // Get hostname and MAC address
 * char* hostname = get_hostname();
 * char* mac = get_mac();
 * // Write hostname and MAC address to file
 * const char* filename = "machineID.txt";
 * write_mac_to_file(filename, hostname, mac);
 * ```
 *
 * - Generate the license file from the machine ID file:
 * ```c
 * // Generate license key
 * const char* private_key = "my-super-segret-private-key-0123456789";
 * char * license_key = generate_hmac(mac, PRIVATE_KEY);
 * // Write to file
 * const char* filename = "license.lic";
 * write_lic_key(filename, license_key);
 * ```
 * 
 * - Validate the license file:
 * ```c
 * // Get hostname and MAC address
 * char* hostname = get_hostname();
 * char* mac = get_mac();
 * // Find license file
 * const char* filename = "license.lic";
 * char* search_envs[] = {"USERPROFILE",
 *                        "HOME",
 *                        "PATH"};
 * char* filename_full = find_lic_file(filename, search_envs, 3);
 * // Get license key from file
 * char* license_key = read_lic_key(filename_full);
 * // Validate license key
 * const char* private_key = "my-super-segret-private-key-0123456789";
 * int exit = validate_lic(mac, private_key, license_key);
 * ```
 *
 * Copyright (C) 2024 Stefano Lovato
 */

#ifndef _HMACLIC_H
#define _HMACLIC_H

#ifndef HMACLIC_EXPORT_API
    #ifdef _WIN32  // For Windows
        #ifdef BUILD_HMACLIC
            #define HMACLIC_EXPORT_API __declspec(dllexport)
        #else
            #define HMACLIC_EXPORT_API __declspec(dllimport)
        #endif
    #elif defined(__linux__) || defined(__APPLE__)  // For Linux and macOS
        #ifdef BUILD_HMACLIC
            #define HMACLIC_EXPORT_API __attribute__((visibility("default")))
        #else
            #define HMACLIC_EXPORT_API
        #endif
    #else
        #define HMACLIC_EXPORT_API // Fallback for other platforms
    #endif
#endif

/**
 * @brief Max path length
 * 
 * Maximum path length for C string.
 */
#define HMACLIC_MAXPATH 512 

/**
 * @brief Get hostname.
 * 
 * Get the hostname for the current user.
 * 
 * @return The hostname; "unknown" if not found.
 */
HMACLIC_EXPORT_API char* get_hostname();

/**
 * @brief Get MAC address.
 * 
 * Get the MAC address of the computer.
 * 
 * @return The MAC address; NULL if not found.
 */
HMACLIC_EXPORT_API char* get_mac();

/**
 * @brief Generate license key.
 * 
 * Generate the license key from MAC address and private key.
 * 
 * @param mac The MAC address.
 * @param key The private key.
 * @return The license key (64 chars).
 */
HMACLIC_EXPORT_API char *generate_hmac(const char *mac, const char *key);

/**
 * @brief Validate licence.
 * 
 * Validate the license for the given MAC address, private key, and license key.
 * 
 * @param mac The MAC address.
 * @param key The private key.
 * @param license The license key (64 chars).
 * @return 0 for success.
 */
HMACLIC_EXPORT_API int validate_lic(const char *mac, const char *key, const char *license);

/**
 * @brief Find license file.
 * 
 * Find the license file in current directory and in paths specified by environment variables.
 * 
 * @param filename The license file.
 * @param search_envs The environment variables to search in.
 * @param env_len The number of environment variables.
 * @return The fullpath of the license file; NULL if not found.
 */
HMACLIC_EXPORT_API char *find_lic_file(const char *filename, char **search_envs, int env_len);

/**
 * @brief Read license key.
 * 
 * Read the license key from the license file.
 * 
 * @param filename The fullpath to the license file.
 * @return The license key; NULL if failed.
 */
HMACLIC_EXPORT_API char *read_lic_key(const char *filename);

/**
 * @brief Write license key.
 * 
 * Write the license key to the license file.
 * 
 * @param filename The file to write.
 * @param key The license key.
 * @return 0 for success.
 */
HMACLIC_EXPORT_API int write_lic_key(const char *filename, const char *key);

/**
 * @brief Write hostname and MAC address.
 * 
 * Write the hostname and the MAC address to a file.
 * 
 * @param filename The file to write.
 * @param hostname The hostname.
 * @param mac The MAC address.
 * @return 0 for success.
 */
HMACLIC_EXPORT_API int write_mac_to_file(const char *filename, const char *hostname, const char *mac);

/**
 * @brief Read hostname and MAC address.
 * 
 * Rear the hostname and the MAC address from a file.
 * 
 * @param filename The file to read.
 * @param hostname The hostname.
 * @param mac The MAC address.
 * @return 0 for success.
 */
HMACLIC_EXPORT_API int read_mac_from_file(const char *filename, char **hostname, char **mac);

#endif