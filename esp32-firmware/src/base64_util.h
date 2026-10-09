#pragma once
// Wrapper tipis di atas mbedtls_base64_encode (sudah tersedia di ESP32
// Arduino core, tidak menambah dependency). Dipakai untuk encode
// ciphertext & tag sebelum dikirim sebagai field JSON di wire envelope
// (lihat comm_channel.py -- field "ct"/"tag" berupa base64).
#include <stdint.h>
#include <stddef.h>

// Return panjang string base64 (tanpa null terminator) yang ditulis ke
// `out`, atau 0 bila `out_capacity` tidak cukup. `out` akan diberi null
// terminator (out_capacity harus menyertakan ruang untuknya).
size_t base64_encode_str(char *out, size_t out_capacity, const uint8_t *data, size_t data_len);
