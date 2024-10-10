/* File sha256.c
    256-bit hash generation.
    Copyright (C) 2024 Stefano Lovato
*/

#include "sha256.h"
#include <string.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// SHA-256 constants
static const uint32_t k[SHA256_ROUNDS] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa11, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Initialize the SHA-256 context
void sha256_init(SHA256_CTX *ctx) {
    ctx->count = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

// Perform the SHA-256 transformation on a block of data
void sha256_transform(SHA256_CTX *ctx, const unsigned char data[]) {
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t w[64];
    int t;

    for (t = 0; t < 16; t++) {
        w[t] = ((uint32_t)data[t * 4] << 24) |
               ((uint32_t)data[t * 4 + 1] << 16) |
               ((uint32_t)data[t * 4 + 2] << 8) |
               ((uint32_t)data[t * 4 + 3]);
    }
    for (t = 16; t < 64; t++) {
        w[t] = w[t - 16] + w[t - 7] +
               ((w[t - 15] >> 3) | (w[t - 15] << (32 - 3))) +
               ((w[t - 2] >> 10) | (w[t - 2] << (32 - 10)));
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (t = 0; t < 64; t++) {
        uint32_t temp1 = h + ((e >> 6) | (e << (32 - 6))) + ((e & f) ^ (~e & g)) + k[t] + w[t];
        uint32_t temp2 = ((a >> 2) | (a << (32 - 2))) + ((a & b) ^ (a & c) ^ (b & c));
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

// Update the SHA-256 context with new data
void sha256_update(SHA256_CTX *ctx, const unsigned char *data, size_t len) {
    size_t i = 0;
    size_t buffer_index = ctx->count % 64;
    ctx->count += len;

    // Handle any leftover data in the buffer
    if (buffer_index > 0) {
        size_t to_copy = 64 - buffer_index < len ? 64 - buffer_index : len;
        memcpy(ctx->buffer + buffer_index, data, to_copy);
        if (buffer_index + to_copy < 64) {
            return;
        }
        sha256_transform(ctx, ctx->buffer);
        data += to_copy;
        len -= to_copy;
    }

    // Process full blocks
    while (len >= 64) {
        sha256_transform(ctx, data);
        data += 64;
        len -= 64;
    }

    // Handle remaining data
    if (len > 0) {
        memcpy(ctx->buffer, data, len);
    }
}

// Finalize the SHA-256 computation and produce the hash
void sha256_final(SHA256_CTX *ctx, unsigned char hash[]) {
    unsigned char padding[64] = {0x80};
    size_t buffer_index = ctx->count % 64;
    size_t padding_size = (buffer_index < 56) ? (56 - buffer_index) : (120 - buffer_index);

    // Append the padding
    sha256_update(ctx, padding, padding_size);

    // Append the length
    uint64_t bit_count = ctx->count * 8;
    for (int i = 0; i < 8; i++) {
        padding[i] = (bit_count >> (56 - i * 8)) & 0xff;
    }
    sha256_update(ctx, padding, 8);

    // Output the hash
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        hash[i] = (ctx->state[i / 4] >> (24 - (i % 4) * 8)) & 0xff;
    }
}


// HMAC-SHA256 Implementation
void hmac_sha256(const char *key, const char *data, unsigned char *hmac) {
    unsigned char key_pad[64];
    unsigned char inner_hash[SHA256_BLOCK_SIZE];
    unsigned char outer_hash[SHA256_BLOCK_SIZE];
    
    // Prepare the key
    size_t key_len = strlen(key);
    if (key_len > 64) {
        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, (unsigned char *)key, key_len);
        sha256_final(&ctx, key_pad);
        key_len = SHA256_DIGEST_LENGTH;
    } else {
        memcpy(key_pad, key, key_len);
    }
    memset(key_pad + key_len, 0, 64 - key_len);

    // Inner Padding
    for (size_t i = 0; i < 64; i++) {
        key_pad[i] ^= 0x36;
    }
    
    // Compute inner hash
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, key_pad, 64);
    sha256_update(&ctx, (unsigned char *)data, strlen(data));
    sha256_final(&ctx, inner_hash);

    // Outer Padding
    for (size_t i = 0; i < 64; i++) {
        key_pad[i] ^= 0x36 ^ 0x5c;
    }

    // Compute outer hash
    sha256_init(&ctx);
    sha256_update(&ctx, key_pad, 64);
    sha256_update(&ctx, inner_hash, SHA256_BLOCK_SIZE);
    sha256_final(&ctx, outer_hash);

    // Copy result
    memcpy(hmac, outer_hash, SHA256_BLOCK_SIZE);
}
