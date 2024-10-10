/*  File validateLicense.c
    Example for validation of the license file.
    Copyright (C) 2024 Stefano Lovato
*/

#include "hmaclic.h"
#include <stdio.h>

#ifndef PRIVATE_KEY
#define PRIVATE_KEY "0000000000000000"
#endif

int main() {
    // get machine current hostname and MAC
    char* hostname = get_hostname();
    char* mac = get_mac();

    // look for license-<hostname>.lic in current directory + specified environment variable
    char lic_filename[HMACLIC_MAXPATH];
    sprintf(lic_filename, "license-%s.lic", hostname);
    char* search_envs[] = { "USERPROFILE",
                            "HOME",
                            "PATH"
                            };
    char* lic_filename_full = find_lic_file(lic_filename, search_envs, sizeof(search_envs)/sizeof(char*));
    if (lic_filename_full) {
        printf("Found license file %s\n", lic_filename);
    }
    else {
        fprintf(stderr, "Unable to find license file: %s\n", lic_filename);
        // wait
        printf("Press Enter to continue...");
        getchar();
        return 1;
    }

    // get license key from file
    char* lic_key = read_lic_key(lic_filename_full);

    // validate license key
    if (validate_lic(mac, PRIVATE_KEY, lic_key)) {
        fprintf(stderr, "Unvalid license\n");
        // wait
        printf("Press Enter to continue...");
        getchar();
        return 1;
    }
    printf("Valid license\n");

    // wait
    printf("Press Enter to continue...");
    getchar();
    return 0;
}