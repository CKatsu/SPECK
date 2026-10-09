#include "keys.h"
#include <mbedtls/md.h>
#include <string.h>

bool parse_hex_key(const char *hex, uint8_t *out, size_t out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len != out_len * 2) return false;
    for (size_t i = 0; i < out_len; i++) {
        char hi = hex[i * 2];
        char lo = hex[i * 2 + 1];
        int hi_v, lo_v;
        if (hi >= '0' && hi <= '9') hi_v = hi - '0';
        else if (hi >= 'a' && hi <= 'f') hi_v = hi - 'a' + 10;
        else if (hi >= 'A' && hi <= 'F') hi_v = hi - 'A' + 10;
        else return false;
        if (lo >= '0' && lo <= '9') lo_v = lo - '0';
        else if (lo >= 'a' && lo <= 'f') lo_v = lo - 'a' + 10;
        else if (lo >= 'A' && lo <= 'F') lo_v = lo - 'A' + 10;
        else return false;
        out[i] = (uint8_t)((hi_v << 4) | lo_v);
    }
    return true;
}

static void sha256_concat(const uint8_t *a, size_t a_len, const char *b_str, uint8_t out[32]) {
    size_t b_len = strlen(b_str);
    uint8_t buf[MASTER_KEY_LEN + 16];  // master key (32) + label pendek ("SPECK-ENC"/"SPECK-MAC", 9 byte)
    memcpy(buf, a, a_len);
    memcpy(buf + a_len, b_str, b_len);
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md(info, buf, a_len + b_len, out);
}

void derive_key_material(const uint8_t master_key[MASTER_KEY_LEN], KeyMaterial *km) {
    uint8_t enc_full[32];
    sha256_concat(master_key, MASTER_KEY_LEN, "SPECK-ENC", enc_full);
    memcpy(km->enc_key, enc_full, ENC_KEY_LEN);

    sha256_concat(master_key, MASTER_KEY_LEN, "SPECK-MAC", km->mac_key);
}
