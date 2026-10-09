#pragma once
// =============================================================================
// speck.h -- SPECK64/128 (block cipher) + mode CTR
// =============================================================================
// Port C/C++ dari benchmark-speck/crypto_utils.py, HARUS menghasilkan output
// BYTE-PERSIS SAMA dengan implementasi Python untuk key/plaintext/nonce yang
// sama (lihat speck_self_test() -- divalidasi terhadap Known Answer Test
// resmi SPECK64/128 dari Beaulieu et al. 2015 Appendix C, dan lihat
// benchmark-speck/tests/ untuk test silang Python<->C).
//
// Spesifikasi: word size 32-bit (alpha=8, beta=3), block 64-bit, key 128-bit,
// 27 round. Mode CTR: keystream block ke-i = E(key, (nonce_as_u64 + i) mod 2^64),
// little-endian -- identik dengan crypto_utils._keystream() di Python.
// =============================================================================

#include <stdint.h>
#include <stddef.h>

#define SPECK_ALPHA 8
#define SPECK_BETA 3
#define SPECK_ROUNDS 27
#define SPECK_KEY_BYTES 16
#define SPECK_BLOCK_BYTES 8
#define SPECK_NONCE_BYTES 8

typedef struct {
    uint32_t rk[SPECK_ROUNDS];
} speck_ctx_t;

// Ekspansi kunci (key schedule). Panggil SEKALI saat boot (kunci master
// tidak berubah selama runtime) -- hasilnya (round key) dipakai berulang
// untuk setiap pesan, menghindari komputasi key schedule berulang tiap kirim.
void speck_key_schedule(const uint8_t key[SPECK_KEY_BYTES], speck_ctx_t *ctx);

// Enkripsi/dekripsi satu block 8 byte in-place.
void speck_encrypt_block(const speck_ctx_t *ctx, uint8_t block[SPECK_BLOCK_BYTES]);
void speck_decrypt_block(const speck_ctx_t *ctx, uint8_t block[SPECK_BLOCK_BYTES]);

// Mode CTR (stream cipher, tanpa padding). `in`/`out` boleh menunjuk ke
// buffer yang sama (in-place). Fungsi yang sama dipakai untuk enkripsi
// maupun dekripsi (properti CTR).
void speck_ctr_crypt(const speck_ctx_t *ctx, const uint8_t nonce[SPECK_NONCE_BYTES],
                      const uint8_t *in, uint8_t *out, size_t len);

// Known Answer Test resmi (Beaulieu et al. 2015 App. C) + sanity check CTR
// round-trip. WAJIB dipanggil saat boot (lihat main.cpp) -- firmware TIDAK
// BOLEH melanjutkan ke streaming bila ini gagal (indikasi bug implementasi
// yang akan membuat SEMUA hasil benchmarking tidak valid).
bool speck_self_test();
