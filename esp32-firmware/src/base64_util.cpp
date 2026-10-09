#include "base64_util.h"
#include <mbedtls/base64.h>

size_t base64_encode_str(char *out, size_t out_capacity, const uint8_t *data, size_t data_len) {
    size_t olen = 0;
    int rc = mbedtls_base64_encode((unsigned char *)out, out_capacity, &olen, data, data_len);
    if (rc != 0) {
        return 0;  // buffer terlalu kecil (rc == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)
    }
    if (olen < out_capacity) {
        out[olen] = '\0';
    }
    return olen;
}
