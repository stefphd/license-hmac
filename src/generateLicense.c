/*  File generateLicense.c
    Get the license file.
    Copyright (C) 2024 Stefano Lovato
*/

#include "hmaclic.h"
#include <stdio.h>

#ifndef PRIVATE_KEY
#define PRIVATE_KEY "0000000000000000"
#endif

int main(int argc, char* argv[]) {
    // Get command line arguments
    char* hostname, *mac;
    switch (argc) {
        case 2:
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
            break;
        case 3:
            hostname = argv[1];
            mac = argv[2];
            break;
        default:
            printf("Usage:  %s <hostname> <macaddress>\n", argv[0]);
            printf("        %s <machineIDfile>\n", argv[0]);
            // wait
            printf("Press Enter to continue...");
            getchar();
            return 1;
    }

    // License filename
    char lic_filename[HMACLIC_MAXPATH];
    sprintf(lic_filename, "license-%s.lic", hostname);

    // Generate the license key
    printf("Generating license key...\n");
    char * license_key = generate_hmac(mac, PRIVATE_KEY);
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