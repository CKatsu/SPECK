#pragma once
// =============================================================================
// config.h -- konfigurasi firmware streaming sensor suhu terenkripsi
// =============================================================================
//
// PENTING -- SINKRONISASI KUNCI:
// SPECK_MASTER_KEY_HEX di bawah HARUS SAMA PERSIS dengan SPECK_MASTER_KEY_HEX
// di benchmark-speck/config.py (Python) -- kalau tidak sama, server.py TIDAK
// akan bisa mendekripsi pesan dari firmware ini (HMAC tag akan selalu invalid
// dan semua pesan ditolak). Nilai default di bawah SUDAH disamakan dengan
// default config.py; jika kamu mengganti salah satu, ganti juga yang lain.
#define SPECK_MASTER_KEY_HEX \
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

#define DEVICE_ID "esp32s3-01"

// -----------------------------------------------------------------------------
// Jalur komunikasi (Fase 1 penelitian ini: UART/USB Serial langsung ke PC
// yang menjalankan server.py). MQTT belum diaktifkan -- lihat
// benchmark-speck/comm_channel.py untuk alasan & rencana aktivasinya.
// -----------------------------------------------------------------------------
#define SERIAL_BAUD 115200

// -----------------------------------------------------------------------------
// Pin I2C untuk BME280 -- SESUAIKAN dengan board ESP32-S3 kamu (cek
// datasheet/silkscreen modul, tidak semua devkit ESP32-S3 memakai pin yang
// sama). Nilai di bawah adalah default Wire.begin() umum pada banyak devkit
// ESP32-S3 (SDA=GPIO8, SCL=GPIO9) -- GANTI bila board kamu berbeda.
// -----------------------------------------------------------------------------
#define BME280_SDA_PIN 8
#define BME280_SCL_PIN 9
#define BME280_I2C_ADDR_PRIMARY 0x76    // alamat I2C default modul GY-BME280
#define BME280_I2C_ADDR_SECONDARY 0x77  // beberapa modul memakai 0x77 (SDO pull-up)

// -----------------------------------------------------------------------------
// Parameter data sintetis (dipakai selama BME280 belum terpasang / gagal
// baca) -- NILAI SAMA dengan benchmark-speck/config.py
// (SYNTHETIC_TEMP_BASE_C dkk.) agar data yang dihasilkan firmware dan
// device_sim.py sebanding secara kasar. Ini ASUMSI simulasi kondisi ruangan
// tropis Indonesia, BUKAN kalibrasi terhadap sensor fisik nyata.
// -----------------------------------------------------------------------------
#define SYNTHETIC_TEMP_BASE_C_LOCAL 28.0f
#define SYNTHETIC_TEMP_JITTER_C_LOCAL 1.5f
#define SYNTHETIC_HUM_BASE_LOCAL 65.0f
#define SYNTHETIC_HUM_JITTER_LOCAL 8.0f
#define SYNTHETIC_PRES_BASE_LOCAL 1009.0f
#define SYNTHETIC_PRES_JITTER_LOCAL 2.0f

// -----------------------------------------------------------------------------
// Parameter streaming (mode default firmware: streaming kontinu, BUKAN
// otomasi skenario S1-S4 penuh -- lihat README.md di root proyek untuk
// pembagian peran firmware vs device_sim.py).
// -----------------------------------------------------------------------------
#define STREAM_SCENARIO_TAG "STREAM"   // ditandai berbeda dari S1-S4 (device_sim.py)
                                          // agar tidak tercampur saat analyze.py
                                          // mengelompokkan data per skenario
#define PAYLOAD_TARGET_SIZE_BYTES 64     // ukuran payload plaintext (header 16B + padding)
#define SEND_INTERVAL_MS 1000              // interval pengiriman "streaming" (bukan burst)
#define ACK_TIMEOUT_MS 2000

// Demonstrasi S4 (normal vs tampered) opsional di hardware sungguhan: bila
// > 0, setiap N pesan, SATU bit ciphertext pesan tersebut dibalik SEBELUM
// dikirim (mensimulasikan penyerang di jalur komunikasi) untuk membuktikan
// server.py menolaknya. 0 = nonaktif (semua pesan dikirim apa adanya).
#define TAMPER_DEMO_EVERY_N_MESSAGES 0

// Buffer plaintext maksimum yang didukung firmware ini (batasi RAM -- hindari
// alokasi dinamis; lihat payload.h). Harus >= PAYLOAD_TARGET_SIZE_BYTES dan
// >= ukuran tier terbesar (1024 byte) bila ingin menguji tier besar juga.
#define MAX_PLAINTEXT_LEN 1024
