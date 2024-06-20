#if !defined(DLL_EXPORT)
	#define DLL_EXPORT /* NOTHING */

	#if defined(_WIN32) || defined(_WIN64) || defined(WIN32) || defined(WIN64)
		#undef DLL_EXPORT
		#if defined(DLib_EXPORTS)
			#define DLL_EXPORT __declspec(dllexport)
		#else
			#define DLL_EXPORT __declspec(dllimport)
		#endif // defined(DLib_EXPORTS)
	#endif // defined(WIN32) || defined(WIN64)

	#if defined(__GNUC__) || defined(__APPLE__) || defined(LINUX)
		#if defined(DLib_EXPORTS)
			#undef DLL_EXPORT
			#define DLL_EXPORT __attribute__((visibility("default")))
		#endif // defined(DLib_EXPORTS)
	#endif // defined(__GNUC__) || defined(__APPLE__) || defined(LINUX)

#endif // !defined(DLL_EXPORT)

#ifndef _LICENSEUTILS_H
#define _LICENSEUTILS_H

#include <string>
#include <vector>

/* Get the hostname */
DLL_EXPORT std::string get_hostname();

/** Get the MAC address */
DLL_EXPORT std::string get_mac();

/** Generate hash for MAC */
DLL_EXPORT std::string generate_hmac(const std::string &data, const std::string &key);

/** Validate the license */
DLL_EXPORT bool validate_lic(const std::string &mac, const std::string &private_key, const std::string &license);

/** Find license file */
DLL_EXPORT std::string find_lic_file(const std::string& lic_filename, std::vector<std::string> search_envs);

/** Read license key from file */
DLL_EXPORT std::string read_lic_key(const std::string &filename);

/** Write hostname and MAC to file */
DLL_EXPORT bool write_mac_to_file(const std::string &filename, const std::string &hostname, std::string &mac);

/** Read mac and hostname from file */
DLL_EXPORT bool read_mac_from_file(const std::string &filename, std::string &hostname, std::string &mac);

#endif