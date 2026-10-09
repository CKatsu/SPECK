#pragma once
// =============================================================================
// keys.h -- turunan kunci enkripsi (SPECK) & kunci MAC (HMAC) dari master key
// =============================================================================
// Identik dengan crypto_utils.KeyMaterial.from_master() di Python:
//   enc_key = SHA256(master_key || "SPECK-ENC")[:16]   -> 128-bit, dipakai SPECK64/128
//   mac_key = SHA256(master_key || "SPECK-MAC")          -> 256-bit, dipakai HMAC-SHA256
// =============================================================================
#include <stdint.h>
#include <stddef.h>

#define MASTER_KEY_LEN 32
#define ENC_KEY_LEN 16
#define MAC_KEY_LEN 32

struct KeyMaterial {
    uint8_t enc_key[ENC_KEY_LEN];
    uint8_t mac_key[MAC_KEY_LEN];
};

// Parse master key dari string hex (mis. SPECK_MASTER_KEY_HEX di config.h,
// harus 64 karakter hex = 32 byte). Return false bila panjang/format salah.
bool parse_hex_key(const char *hex, uint8_t *out, size_t out_len);

// Turunkan KeyMaterial dari master key 32-byte.
void derive_key_material(const uint8_t master_key[MASTER_KEY_LEN], KeyMaterial *km);
