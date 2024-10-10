/*  File generateLicense.c
    Get the license file.
    Copyright (C) 2024 Stefano Lovato
*/

#include "hmaclic.h"
#include <stdio.h>

#define DEF_PRIVATE_KEY "0000000000000000"
#define DEF_LICFILE_PREFIX "license"


int main(int argc, char* argv[]) {
    // Get command line arguments
    char* hostname, *mac;
    char* private_key = DEF_PRIVATE_KEY;
    char* licfile_prefix = DEF_LICFILE_PREFIX;
    if (argc < 2) {
        printf("Usage:  %s <machine_ID-file>\n", argv[0]);
        printf("        %s <machine_ID-file> <private-key> <licfile-prefix>\n", argv[0]);
        // wait
        printf("Press Enter to continue...");
        getchar();
        return 1;
    }
    if (read_mac_from_file(argv[1], &hostname, &mac)) {
        fprintf(stderr, "Unable to read machine ID file %s\n", argv[1]);
        // wait
        printf("Press Enter to continue...");
        getchar();
        return 1;
    }
    if (!hostname) {
        fprintf(stderr, "Unable to read hostname from %s\n", argv[1]);
        // wait
        printf("Press Enter to continue...");
        getchar();
        return 1;
    }
    if (!mac) {
        fprintf(stderr, "Unable to read MAC address from %s\n", argv[1]);
        // wait
        printf("Press Enter to continue...");
        getchar();
        return 1;
    }
    if (argc > 2) {
        private_key = argv[2];
    }
    if (argc > 3) {
        licfile_prefix = argv[3];
    }

    // License filename
    char lic_filename[HMACLIC_MAXPATH];
    sprintf(lic_filename, "%s-%s.lic", licfile_prefix, hostname);

    // Generate the license key
    printf("Generating license key...\n");
    char * license_key = generate_hmac(mac, private_key);
    printf("Private key: %s\n", private_key);
    printf("License key: %s\n", license_key);

    // Save the license key to a file
    if (write_lic_key(lic_filename, license_key)) {
        // Print error message
        fprintf(stderr, "Unable to write license key to %s\n", lic_filename);
        // free mem
        free(license_key);
        // wait
        printf("Press Enter to continue...");
        getchar();
        return 1;
    } else {
        printf("License key written to %s\n", lic_filename);  
    }
    
    // free mem
    free(license_key);
    if (argc==2) {
        free(mac);
        free(hostname);
    }

    // wait
    printf("Press Enter to continue...");
    getchar();
    return 0;
}