/* File sha256.h
    256-bit hash generation header.
    Copyright (C) 2024 Stefano Lovato
*/

#ifndef HMAC_SHA256_H
#define HMAC_SHA256_H

#include <stdint.h>
#include <stdlib.h>

// SHA-256 Constants
#define SHA256_BLOCK_SIZE 32
#define SHA256_DIGEST_LENGTH 32
#define SHA256_ROUNDS 64

// SHA-256 Context Structure
typedef struct {
    uint32_t state[8];
    uint64_t count;
    unsigned char buffer[64];
} SHA256_CTX;

// Function Prototypes
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const unsigned char *data, size_t len);
void sha256_transform(SHA256_CTX *ctx, const unsigned char data[]);
void sha256_final(SHA256_CTX *ctx, unsigned char hash[]);
void hmac_sha256(const char *key, const char *data, unsigned char *hmac);

#endif // HMAC_SHA256_H