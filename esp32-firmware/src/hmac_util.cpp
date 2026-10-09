#include "hmac_util.h"
#include <mbedtls/md.h>
#include <string.h>

void hmac_compute_tag(const uint8_t *mac_key, size_t mac_key_len,
                        const uint8_t *nonce, size_t nonce_len,
                        const uint8_t *ciphertext, size_t ciphertext_len,
                        uint8_t *tag_out) {
    uint8_t full_digest[32];  // SHA-256 output = 32 byte

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_setup(&ctx, info, 1 /* hmac */);
    mbedtls_md_hmac_starts(&ctx, mac_key, mac_key_len);
    mbedtls_md_hmac_update(&ctx, nonce, nonce_len);
    mbedtls_md_hmac_update(&ctx, ciphertext, ciphertext_len);
    mbedtls_md_hmac_finish(&ctx, full_digest);
    mbedtls_md_free(&ctx);

    memcpy(tag_out, full_digest, HMAC_TAG_LEN);
}

bool hmac_verify_tag(const uint8_t *mac_key, size_t mac_key_len,
                       const uint8_t *nonce, size_t nonce_len,
                       const uint8_t *ciphertext, size_t ciphertext_len,
                       const uint8_t *tag, size_t tag_len) {
    if (tag_len != HMAC_TAG_LEN) return false;
    uint8_t expected[HMAC_TAG_LEN];
    hmac_compute_tag(mac_key, mac_key_len, nonce, nonce_len, ciphertext, ciphertext_len, expected);

    // Constant-time compare (jumlah operasi tidak bergantung pada posisi
    // byte pertama yang berbeda).
    uint8_t diff = 0;
    for (size_t i = 0; i < HMAC_TAG_LEN; i++) {
        diff |= (uint8_t)(expected[i] ^ tag[i]);
    }
    return diff == 0;
}
