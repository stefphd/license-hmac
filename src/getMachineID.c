/*  File getMachineID.c
    Get the Machine ID.
    Copyright (C) 2024 Stefano Lovato
*/

#include "hmaclic.h"
#include <stdio.h>

int main() {
    // filename
    const char* filename_prefix = "machine_ID-";

    // get machine hostname and MAC
    printf("Generating machine ID...\n");
    char* hostname = get_hostname();
    char* mac = get_mac();
    printf("Host name  : %s\n", hostname);
    printf("MAC address: %s\n", mac);

    // write hostname and MAC to file
    char filename[HMACLIC_MAXPATH];
    sprintf(filename, "%s%s.txt", filename_prefix, hostname);

    if (!write_mac_to_file(filename, hostname, mac)) {
        printf("Machine ID saved to %s\n", filename);
    }
    else {
        fprintf(stderr, "Unable to open file: %s\n", filename);
    }

    // wait
    printf("Press Enter to continue...");
    getchar();

    return 0;
}
