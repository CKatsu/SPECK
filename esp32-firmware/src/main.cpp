// =============================================================================
// main.cpp -- Firmware streaming sensor suhu terenkripsi (ESP32-S3)
// =============================================================================
// Alur: baca sensor (BME280 asli atau sintetis, lihat sensor.cpp) -> susun
// payload biner (payload.cpp) -> enkripsi SPECK64/128-CTR (speck.cpp) ->
// hitung tag HMAC-SHA256 (hmac_util.cpp) -> kirim sebagai satu baris JSON
// lewat Serial (format & framing identik dengan comm_channel.py di sisi
// Python) -> tunggu ACK dari server.py -> ulangi setiap SEND_INTERVAL_MS.
//
// Firmware ini TIDAK mengotomasi skenario S1-S4 penuh (31 pengulangan x
// beberapa tier payload x kondisi normal/tampered) -- itu peran
// device_sim.py (Python, lihat README.md di root proyek). Firmware
// menyediakan MODE STREAMING KONTINU untuk membuktikan pipeline end-to-end
// bekerja pada hardware sungguhan, dan sudah siap membaca BME280 fisik
// begitu sensor terpasang (tanpa perlu ubah kode -- lihat sensor.cpp).
// =============================================================================
#include <Arduino.h>
#include <string.h>
#include <esp_system.h>

#include "config.h"
#include "speck.h"
#include "hmac_util.h"
#include "keys.h"
#include "payload.h"
#include "sensor.h"
#include "base64_util.h"

static speck_ctx_t g_speck_ctx;
static KeyMaterial g_km;
static SensorSource g_sensor;
static uint32_t g_seq = 0;
static uint32_t g_last_send_ms = 0;

// Buffer statis (bukan alokasi dinamis) -- dialokasikan sekali di BSS,
// dipakai ulang setiap pesan.
static uint8_t g_plaintext[MAX_PLAINTEXT_LEN];
static uint8_t g_ciphertext[MAX_PLAINTEXT_LEN];
static char g_ct_b64[((MAX_PLAINTEXT_LEN + 2) / 3) * 4 + 4];
static char g_tag_b64[32];
static char g_line_buf[((MAX_PLAINTEXT_LEN + 2) / 3) * 4 + 256];

#define STR_(x) #x
#define STR(x) STR_(x)

static void fatal_halt(const char *msg) {
    // Tidak melanjutkan ke streaming bila terjadi kegagalan fatal (KAT
    // cipher gagal / master key tidak valid) -- lebih baik berhenti total
    // daripada menghasilkan data benchmarking yang tidak valid.
    while (true) {
        Serial.println(msg);
        delay(2000);
    }
}

void setup() {
    Serial.begin(SERIAL_BAUD);
    delay(1500);  // beri waktu PC/monitor serial terhubung setelah boot/reset
    Serial.println();
    Serial.println("# ================================================================");
    Serial.println("# Firmware Streaming Sensor Suhu Terenkripsi -- SPECK64/128-CTR+HMAC");
    Serial.println("# ESP32-S3 | baris berawalan 'SPK1:' adalah data protokol (lihat");
    Serial.println("# comm_channel.py) -- baris berawalan '#' adalah log, diabaikan server.");
    Serial.println("# ================================================================");

    if (!speck_self_test()) {
        fatal_halt("# [FATAL] SPECK64/128 KAT self-test GAGAL. Implementasi cipher tidak "
                    "sesuai spesifikasi resmi -- firmware DIHENTIKAN agar tidak menghasilkan "
                    "data benchmarking yang tidak valid. Periksa src/speck.cpp.");
    }
    Serial.println("# [ok] SPECK64/128 KAT self-test PASSED");

    uint8_t master_key[MASTER_KEY_LEN];
    if (!parse_hex_key(SPECK_MASTER_KEY_HEX, master_key, MASTER_KEY_LEN)) {
        fatal_halt("# [FATAL] SPECK_MASTER_KEY_HEX pada include/config.h tidak valid "
                    "(harus tepat 64 karakter hex / 32 byte). Firmware DIHENTIKAN.");
    }
    derive_key_material(master_key, &g_km);
    speck_key_schedule(g_km.enc_key, &g_speck_ctx);
    Serial.println("# [ok] Kunci enkripsi (SPECK) & kunci MAC (HMAC) diturunkan dari master key");
    Serial.println("# [!] Pastikan SPECK_MASTER_KEY_HEX ini SAMA dengan "
                    "benchmark-speck/config.py di PC, jika tidak semua pesan akan ditolak server.");

    g_sensor.begin();
    Serial.print("# [ok] Sumber data sensor: ");
    Serial.println(g_sensor.usingRealSensor() ? "BME280 FISIK terdeteksi" : "SINTETIS (BME280 belum terpasang/terdeteksi)");

    Serial.print("# [ok] Ukuran payload target: ");
    Serial.print((unsigned long)PAYLOAD_TARGET_SIZE_BYTES);
    Serial.println(" byte, interval kirim: " STR(SEND_INTERVAL_MS) " ms");
    Serial.println("# Mulai streaming...");
}

static void send_message(bool tamper_demo) {
    SensorReading reading = g_sensor.read();
    uint32_t ts_ms32 = (uint32_t)millis();

    size_t pt_len = build_sensor_payload(g_plaintext, sizeof(g_plaintext), g_seq, ts_ms32,
                                           reading, PAYLOAD_TARGET_SIZE_BYTES);
    if (pt_len == 0) {
        Serial.println("# [warn] build_sensor_payload gagal (target/buffer tidak sesuai), pesan dilewati");
        return;
    }

    // Nonce 8-byte acak per pesan (esp_random() -- hardware RNG ESP32,
    // BUKAN prosedur yang sama dengan jitter data sintetis di sensor.cpp).
    uint8_t nonce[SPECK_NONCE_BYTES];
    for (int i = 0; i < SPECK_NONCE_BYTES; i++) {
        nonce[i] = (uint8_t)(esp_random() & 0xFF);
    }

    speck_ctr_crypt(&g_speck_ctx, nonce, g_plaintext, g_ciphertext, pt_len);

    uint8_t tag[HMAC_TAG_LEN];
    hmac_compute_tag(g_km.mac_key, MAC_KEY_LEN, nonce, SPECK_NONCE_BYTES, g_ciphertext, pt_len, tag);

    const char *condition = "normal";
    if (tamper_demo) {
        // Balik satu bit ciphertext SEBELUM dikirim (setelah tag dihitung
        // dari ciphertext ASLI) -- mensimulasikan penyerang di jalur
        // komunikasi yang tidak tahu kunci. Server HARUS menolak ini.
        g_ciphertext[0] ^= 0x01;
        condition = "tampered";
        Serial.println("# [demo] Mengirim pesan TAMPERED (uji deteksi HMAC tag, lihat TAMPER_DEMO_EVERY_N_MESSAGES)");
    }

    char nonce_hex[SPECK_NONCE_BYTES * 2 + 1];
    for (int i = 0; i < SPECK_NONCE_BYTES; i++) {
        snprintf(nonce_hex + i * 2, 3, "%02x", nonce[i]);
    }

    base64_encode_str(g_ct_b64, sizeof(g_ct_b64), g_ciphertext, pt_len);
    base64_encode_str(g_tag_b64, sizeof(g_tag_b64), tag, HMAC_TAG_LEN);

    int n = snprintf(g_line_buf, sizeof(g_line_buf),
        "SPK1:{\"device_id\":\"%s\",\"seq\":%lu,\"scenario\":\"%s\",\"condition\":\"%s\","
        "\"nonce\":\"%s\",\"ct\":\"%s\",\"tag\":\"%s\"}\n",
        DEVICE_ID, (unsigned long)g_seq, STREAM_SCENARIO_TAG, condition, nonce_hex, g_ct_b64, g_tag_b64);

    if (n <= 0 || (size_t)n >= sizeof(g_line_buf)) {
        Serial.println("# [warn] Baris pesan melebihi buffer statis, pesan dilewati "
                        "(perbesar g_line_buf bila memakai payload target > 1024 byte)");
        return;
    }
    Serial.print(g_line_buf);

    // Tunggu ACK dari server.py (format: {"ack_seq":...}). Pembacaan manual
    // byte-per-byte ke buffer statis -- sengaja TIDAK memakai Arduino
    // String (menghindari alokasi heap dinamis yang tidak perlu).
    char ack_buf[64];
    size_t ack_len = 0;
    bool got_ack = false;
    unsigned long wait_start = millis();
    while (millis() - wait_start < ACK_TIMEOUT_MS && !got_ack) {
        while (Serial.available()) {
            char c = (char)Serial.read();
            if (c == '\n') {
                ack_buf[ack_len < sizeof(ack_buf) ? ack_len : sizeof(ack_buf) - 1] = '\0';
                if (strstr(ack_buf, "ack_seq") != nullptr) {
                    got_ack = true;
                }
                ack_len = 0;
                if (got_ack) break;
            } else if (ack_len < sizeof(ack_buf) - 1) {
                ack_buf[ack_len++] = c;
            }
        }
    }
    if (!got_ack) {
        Serial.println("# [warn] Tidak ada ACK dari server dalam batas waktu -- "
                        "pastikan server.py berjalan & terhubung ke port serial ini.");
    }

    g_seq++;
}

void loop() {
    uint32_t now = millis();
    if (now - g_last_send_ms >= SEND_INTERVAL_MS) {
        g_last_send_ms = now;
        bool tamper_demo = (TAMPER_DEMO_EVERY_N_MESSAGES > 0) &&
                             (((g_seq + 1) % TAMPER_DEMO_EVERY_N_MESSAGES) == 0);
        send_message(tamper_demo);
    }
}
