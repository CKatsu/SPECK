#include "payload.h"
#include <string.h>
#include <math.h>

static inline void store_le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFF); p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF); p[3] = (uint8_t)((v >> 24) & 0xFF);
}
static inline void store_le16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xFF); p[1] = (uint8_t)((v >> 8) & 0xFF);
}

static int16_t clamp_i16(long v) {
    if (v < -32768) return -32768;
    if (v > 32767) return 32767;
    return (int16_t)v;
}
static uint16_t clamp_u16(long v) {
    if (v < 0) return 0;
    if (v > 65535) return 65535;
    return (uint16_t)v;
}

size_t build_sensor_payload(uint8_t *out, size_t out_capacity, uint32_t seq, uint32_t ts_ms32,
                              const SensorReading &reading, size_t target_size) {
    int16_t temp_centi = clamp_i16(lroundf(reading.temp_c * 100.0f));
    uint16_t hum_centi = clamp_u16(lroundf(reading.hum_pct * 100.0f));
    uint16_t pres_deca = clamp_u16(lroundf(reading.pres_hpa * 10.0f));
    uint8_t flags = reading.synthetic ? PAYLOAD_FLAG_SYNTHETIC : 0x00;

    uint8_t header[PAYLOAD_HEADER_LEN];
    store_le32(header + 0, seq);
    store_le32(header + 4, ts_ms32);
    store_le16(header + 8, (uint16_t)temp_centi);  // reinterpret bits, sesuai struct "<h" Python (little-endian 2's complement)
    store_le16(header + 10, hum_centi);
    store_le16(header + 12, pres_deca);
    header[14] = flags;
    header[15] = 0;  // reserved

    if (out_capacity < PAYLOAD_HEADER_LEN) {
        return 0;  // buffer pemanggil terlalu kecil -- seharusnya tidak pernah terjadi, dicek pemanggil
    }
    memcpy(out, header, PAYLOAD_HEADER_LEN);

    if (target_size < PAYLOAD_HEADER_LEN) {
        return PAYLOAD_HEADER_LEN;  // sama seperti device_sim.py: header tidak dipangkas
    }

    size_t total = target_size;
    if (total > out_capacity) total = out_capacity;  // batasi ke kapasitas buffer (lihat MAX_PLAINTEXT_LEN)

    for (size_t i = PAYLOAD_HEADER_LEN; i < total; i++) {
        out[i] = PAYLOAD_PAD_BYTE;
    }
    return total;
}
