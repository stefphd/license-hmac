/** 
 * @file hmaclic.h
 * @brief Licensening using MAC address and expiration date.
 * 
 * Licensening using MAC address and expiration date. 
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
 * const char *mac = "01:23:45:67:89:XY"
 * const char* exp_date = "2024-12-31"
 * const char* private_key = "my-super-segret-private-key-0123456789";
 * char * license_key = generate_hmac(mac, exp_date, private_key);
 * // Write to file
 * const char* filename = "license.lic";
 * write_lic_key(filename, license_key, exp_date);
 * ```
 * 
 * - Validate the license file:
 * ```c
 * // Get hostname and MAC address
 * char* hostname = get_hostname();
 * char* mac = get_mac();
 * // Find license file
 * const char* filename = "license.lic";
 * const char* search_envs[] = {"USERPROFILE",
 *                              "HOME",
 *                              "PATH"};
 * char* filename_full = find_lic_file(filename, search_envs, 3);
 * // Get license key from file
 * char* license_key, *exp_date
 * read_lic_key(filename_full, &license_key, &exp_date);
 * // Validate license key
 * const char* private_key = "my-super-segret-private-key-0123456789";
 * int exit = validate_lic(mac, exp_date, private_key, license_key);
 * ```
 *
 * Copyright (C) 2024 Stefano Lovato
 */

#ifndef _HMACLIC_H
#define _HMACLIC_H

#ifdef __cplusplus
extern "C" {
#endif

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
 * @brief Exit for valid license.
 * 
 * Exit value for valid license.
 */
#define EXIT_VALID      0
/**
 * @brief Exit for expired license.
 * 
 * Exit value for expired license.
 */
#define EXIT_EXPIRED    1
/**
 * @brief Exit for unvalid license.
 * 
 * Exit value for unvalid license.
 */
#define EXIT_UNVALID    2

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
 * Generate the license key from MAC address, expiration date and private key.
 * 
 * @param mac The MAC address.
 * @param exp_date The expiration date.
 * @param key The private key.
 * @return The license key (64 chars).
 */
HMACLIC_EXPORT_API char *generate_hmac(const char *mac, const char *exp_date, const char *key);

/**
 * @brief Validate licence.
 * 
 * Validate the license for the given MAC address, expiration date, private key, and license key.
 * 
 * @param mac The MAC address.
 * @param exp_date The expiration date.
 * @param key The private key.
 * @param license The license key (64 chars).
 * @return EXIT_VALID for success, EXIT_EXPIRED for expired license, EXIT_UNVALID for unvalid license.
 */
HMACLIC_EXPORT_API int validate_lic(const char *mac, const char *exp_date, const char *key, const char *license);

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
HMACLIC_EXPORT_API char *find_lic_file(const char *filename, const char **search_envs, int env_len);

/**
 * @brief Read license file.
 * 
 * Read the license key and expiration date from the license file.
 * 
 * @param filename The fullpath to the license file.
 * @param key The license key.
 * @param exp_date The expiration date.
 * @return 0 for success.
 */
HMACLIC_EXPORT_API int read_lic_key(const char *filename, char **key, char **exp_date);

/**
 * @brief Write license file.
 * 
 * Write the license key and expiration date to the license file.
 * 
 * @param filename The file to write.
 * @param key The license key.
 * @param exp_date The expiration date.
 * @return 0 for success.
 */
HMACLIC_EXPORT_API int write_lic_key(const char *filename, const char *key, const char *exp_date);

/**
 * @brief Write machine ID file.
 * 
 * Write the hostname and the MAC address to the machine ID file.
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


#ifdef __cplusplus
}
#endif

#endif