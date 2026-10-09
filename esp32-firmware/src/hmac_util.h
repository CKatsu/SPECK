#pragma once
// =============================================================================
// hmac_util.h -- HMAC-SHA256 (autentikasi/tag) via mbedTLS bawaan ESP-IDF
// =============================================================================
// Konstruksi ini adalah pasangan dari crypto_utils.compute_tag()/verify_tag()
// di Python: HMAC-SHA256 dihitung atas (nonce || ciphertext), dipotong
// menjadi TAG_LEN byte (16 byte / 128 bit). Memakai mbedtls (sudah termasuk
// dalam ESP32 Arduino core, TIDAK menambah dependency baru dan tidak
// memerlukan alokasi memori dinamis tambahan di luar yang mbedtls pakai
// secara internal untuk konteks HMAC sementara).
// =============================================================================

#include <stdint.h>
#include <stddef.h>

#define HMAC_TAG_LEN 16

// mac_key: kunci HMAC (32 byte, SHA-256 output size, diturunkan sama seperti
// Python KeyMaterial.from_master()). Menulis HMAC-SHA256(nonce||ciphertext)
// terpotong ke `tag_out` (harus berukuran >= HMAC_TAG_LEN).
void hmac_compute_tag(const uint8_t *mac_key, size_t mac_key_len,
                        const uint8_t *nonce, size_t nonce_len,
                        const uint8_t *ciphertext, size_t ciphertext_len,
                        uint8_t *tag_out);

// Constant-time compare tag yang dihitung vs tag yang diklaim -- mencegah
// timing side-channel yang membocorkan informasi tag lewat waktu eksekusi.
bool hmac_verify_tag(const uint8_t *mac_key, size_t mac_key_len,
                       const uint8_t *nonce, size_t nonce_len,
                       const uint8_t *ciphertext, size_t ciphertext_len,
                       const uint8_t *tag, size_t tag_len);
