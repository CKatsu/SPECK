#pragma once
// =============================================================================
// payload.h -- format payload sensor (PLAINTEXT sebelum dienkripsi)
// =============================================================================
// HARUS identik byte-per-byte dengan benchmark-speck/payload_format.py.
// Layout header (16 byte, little-endian):
//   offset  size  field         keterangan
//   0       4     seq           uint32
//   4       4     ts_ms32       uint32 (32 bit rendah dari millis(), lihat catatan di sensor.cpp)
//   8       2     temp_centi     int16,  suhu (C) x 100
//   10      2     hum_centi      uint16, kelembapan (%) x 100
//   12      2     pres_deca      uint16, tekanan (hPa) x 10
//   14      1     flags           uint8,  bit0 = 1 jika data sintetis
//   15      1     reserved        uint8,  selalu 0
// Byte setelah offset 16 = byte pengisi (0xAA) untuk mencapai ukuran target.
// =============================================================================
#include <stdint.h>
#include <stddef.h>

#define PAYLOAD_HEADER_LEN 16
#define PAYLOAD_FLAG_SYNTHETIC 0x01
#define PAYLOAD_PAD_BYTE 0xAA

struct SensorReading {
    float temp_c;
    float hum_pct;
    float pres_hpa;
    bool synthetic;
};

// Membentuk payload plaintext ke `out` (harus berkapasitas >= target_size).
// Return jumlah byte aktual yang ditulis (== target_size, kecuali
// target_size < PAYLOAD_HEADER_LEN, lihat implementasi).
size_t build_sensor_payload(uint8_t *out, size_t out_capacity, uint32_t seq, uint32_t ts_ms32,
                              const SensorReading &reading, size_t target_size);
