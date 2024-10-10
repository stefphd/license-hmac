/*  File validateLicense.c
    Example for validation of the license file.
    Copyright (C) 2024 Stefano Lovato
*/

#include "hmaclic.h"
#include <stdio.h>

#define DEF_PRIVATE_KEY "0000000000000000"
#define DEF_LICFILE_PREFIX "license"

int main(int argc, char* argv[]) {
    // get machine current hostname and MAC
    char* hostname = get_hostname();
    char* mac = get_mac();
    char* private_key = DEF_PRIVATE_KEY;
    char* licfile_prefix = DEF_LICFILE_PREFIX;
    // get command line arguments
    if (argc > 1) {
        private_key = argv[1];
    }
    if (argc > 2) {
        licfile_prefix = argv[2];
    }
    // look for license-<hostname>.lic in current directory + specified environment variable
    char lic_filename[HMACLIC_MAXPATH];
    sprintf(lic_filename, "%s-%s.lic", licfile_prefix, hostname);
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
        // free mem
        free(hostname); free(mac);
        // wait
        printf("Press Enter to continue...");
        getchar();
        return 1;
    }

    // get license key from file
    char* license_key, *exp_date;
    if (read_lic_key(lic_filename_full, &license_key, &exp_date)) {
        fprintf(stderr, "Failed to retrieve license from file: %s", lic_filename_full);
        return 1;
    }

    // print
    printf("Private key: %s\n", private_key);
    printf("License key: %s\n", license_key);
    printf("Exp. date  : %s\n", exp_date);

    // validate license key
    int exit = validate_lic(mac, exp_date, private_key, license_key);
    switch (exit) {
        case EXIT_VALID:
            printf("Valid license\n");
            break;
        case EXIT_EXPIRED:
            fprintf(stderr, "Expired license\n");
            break;
        case EXIT_UNVALID:
            fprintf(stderr, "Unvalid license\n");
            break;
    }

    // free mem
    free(hostname); free(mac);
    free(lic_filename_full);
    free(license_key); free(exp_date);

    // wait
    printf("Press Enter to continue...");
    getchar();
    return exit;
}