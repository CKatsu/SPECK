#include "speck.h"
#include <string.h>

static inline uint32_t load_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static inline void store_le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}
static inline uint32_t rotr32(uint32_t x, int r) { return (x >> r) | (x << (32 - r)); }
static inline uint32_t rotl32(uint32_t x, int r) { return (x << r) | (x >> (32 - r)); }

void speck_key_schedule(const uint8_t key[SPECK_KEY_BYTES], speck_ctx_t *ctx) {
    uint32_t k0 = load_le32(key + 0);
    // l_arr perlu menampung l0,l1,l2 awal + (ROUNDS-1) nilai baru yang
    // di-append seiring iterasi (identik dengan list `l` yang tumbuh pada
    // crypto_utils._expand_key() versi Python).
    uint32_t l_arr[SPECK_ROUNDS + 3];
    l_arr[0] = load_le32(key + 4);
    l_arr[1] = load_le32(key + 8);
    l_arr[2] = load_le32(key + 12);

    ctx->rk[0] = k0;
    for (int i = 0; i < SPECK_ROUNDS - 1; i++) {
        uint32_t new_l = ctx->rk[i] + rotr32(l_arr[i], SPECK_ALPHA);
        new_l ^= (uint32_t)i;
        l_arr[i + 3] = new_l;
        ctx->rk[i + 1] = rotl32(ctx->rk[i], SPECK_BETA) ^ new_l;
    }
}

static inline void speck_round(uint32_t *x, uint32_t *y, uint32_t k) {
    *x = rotr32(*x, SPECK_ALPHA);
    *x = (uint32_t)(*x + *y);
    *x ^= k;
    *y = rotl32(*y, SPECK_BETA);
    *y ^= *x;
}

static inline void speck_round_inv(uint32_t *x, uint32_t *y, uint32_t k) {
    *y ^= *x;
    *y = rotr32(*y, SPECK_BETA);
    *x ^= k;
    *x = (uint32_t)(*x - *y);
    *x = rotl32(*x, SPECK_ALPHA);
}

void speck_encrypt_block(const speck_ctx_t *ctx, uint8_t block[SPECK_BLOCK_BYTES]) {
    // Konvensi word: byte 0-3 = word "y" (rendah), byte 4-7 = word "x"
    // (tinggi) -- identik dengan struct.pack("<2I", y, x) pada Python.
    uint32_t y = load_le32(block + 0);
    uint32_t x = load_le32(block + 4);
    for (int i = 0; i < SPECK_ROUNDS; i++) {
        speck_round(&x, &y, ctx->rk[i]);
    }
    store_le32(block + 0, y);
    store_le32(block + 4, x);
}

void speck_decrypt_block(const speck_ctx_t *ctx, uint8_t block[SPECK_BLOCK_BYTES]) {
    uint32_t y = load_le32(block + 0);
    uint32_t x = load_le32(block + 4);
    for (int i = SPECK_ROUNDS - 1; i >= 0; i--) {
        speck_round_inv(&x, &y, ctx->rk[i]);
    }
    store_le32(block + 0, y);
    store_le32(block + 4, x);
}

void speck_ctr_crypt(const speck_ctx_t *ctx, const uint8_t nonce[SPECK_NONCE_BYTES],
                      const uint8_t *in, uint8_t *out, size_t len) {
    uint64_t nonce_val = 0;
    for (int i = 0; i < 8; i++) {
        nonce_val |= ((uint64_t)nonce[i]) << (8 * i);
    }
    size_t nblocks = (len + SPECK_BLOCK_BYTES - 1) / SPECK_BLOCK_BYTES;
    for (size_t b = 0; b < nblocks; b++) {
        uint64_t ctr_val = nonce_val + (uint64_t)b;  // wrap mod 2^64 alami (uint64_t overflow)
        uint8_t block[SPECK_BLOCK_BYTES];
        for (int i = 0; i < 8; i++) {
            block[i] = (uint8_t)((ctr_val >> (8 * i)) & 0xFF);
        }
        speck_encrypt_block(ctx, block);  // block sekarang = keystream block ini

        size_t offset = b * SPECK_BLOCK_BYTES;
        size_t chunk = (len - offset < SPECK_BLOCK_BYTES) ? (len - offset) : SPECK_BLOCK_BYTES;
        for (size_t i = 0; i < chunk; i++) {
            out[offset + i] = in[offset + i] ^ block[i];
        }
    }
}

bool speck_self_test() {
    // Known Answer Test resmi SPECK64/128 (Beaulieu et al. 2015, App. C).
    // Byte array ini dibangkitkan & diverifikasi silang dari
    // benchmark-speck/crypto_utils.py (lihat _self_test() di sana) --
    // JANGAN diubah tanpa memverifikasi ulang terhadap Python.
    static const uint8_t key[SPECK_KEY_BYTES] = {
        0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0A, 0x0B,
        0x10, 0x11, 0x12, 0x13, 0x18, 0x19, 0x1A, 0x1B,
    };
    static const uint8_t pt[SPECK_BLOCK_BYTES] = {
        0x2D, 0x43, 0x75, 0x74, 0x74, 0x65, 0x72, 0x3B,
    };
    static const uint8_t expected_ct[SPECK_BLOCK_BYTES] = {
        0x8B, 0x02, 0x4E, 0x45, 0x48, 0xA5, 0x6F, 0x8C,
    };

    speck_ctx_t ctx;
    speck_key_schedule(key, &ctx);

    uint8_t block[SPECK_BLOCK_BYTES];
    memcpy(block, pt, SPECK_BLOCK_BYTES);
    speck_encrypt_block(&ctx, block);
    if (memcmp(block, expected_ct, SPECK_BLOCK_BYTES) != 0) {
        return false;
    }

    speck_decrypt_block(&ctx, block);
    if (memcmp(block, pt, SPECK_BLOCK_BYTES) != 0) {
        return false;
    }

    // Sanity check CTR round-trip (bukan bagian KAT resmi, tapi wajib lulus).
    uint8_t nonce[SPECK_NONCE_BYTES] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t msg[37];
    for (int i = 0; i < 37; i++) msg[i] = (uint8_t)(i * 7 + 3);
    uint8_t ct[37], back[37];
    speck_ctr_crypt(&ctx, nonce, msg, ct, 37);
    speck_ctr_crypt(&ctx, nonce, ct, back, 37);
    if (memcmp(msg, back, 37) != 0) {
        return false;
    }

    return true;
}
