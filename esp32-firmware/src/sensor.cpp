#include "sensor.h"
#include "config.h"
#include <Arduino.h>
#include <Wire.h>
#include <Adafruit_BME280.h>
#include <esp_system.h>
#include <math.h>

static Adafruit_BME280 g_bme;

// Nilai acak float di [-range, +range] memakai esp_random() (hardware RNG
// ESP32) -- dipakai untuk jitter data sintetis, BUKAN untuk keperluan
// kriptografis (nonce enkripsi dibangkitkan terpisah di main.cpp).
static float rand_jitter(float range) {
    int32_t r = (int32_t)(esp_random() % 20001) - 10000;  // -10000..10000
    return (r / 10000.0f) * range;
}

static float clampf(float v, float lo, float hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

void SensorSource::begin() {
    Wire.begin(BME280_SDA_PIN, BME280_SCL_PIN);

    real_sensor_ok_ = g_bme.begin(BME280_I2C_ADDR_PRIMARY, &Wire);
    if (!real_sensor_ok_) {
        real_sensor_ok_ = g_bme.begin(BME280_I2C_ADDR_SECONDARY, &Wire);
    }

    if (real_sensor_ok_) {
        Serial.println("# [sensor] BME280 terdeteksi -- memakai pembacaan sensor FISIK.");
        // Oversampling standar (mode normal, filter off) -- cukup untuk
        // telemetry suhu ruangan, bukan aplikasi presisi tinggi.
        g_bme.setSampling(Adafruit_BME280::MODE_NORMAL,
                            Adafruit_BME280::SAMPLING_X2,   // suhu
                            Adafruit_BME280::SAMPLING_X16,  // tekanan
                            Adafruit_BME280::SAMPLING_X1,   // kelembapan
                            Adafruit_BME280::FILTER_OFF);
    } else {
        Serial.println("# [sensor] BME280 TIDAK terdeteksi (belum terpasang) -- "
                        "memakai data SINTETIS (random walk). Pasang sensor & reset "
                        "board untuk beralih ke pembacaan fisik secara otomatis.");
    }
}

SensorReading SensorSource::readSynthetic() {
    temp_c_ = clampf(temp_c_ + rand_jitter(0.15f),
                       SYNTHETIC_TEMP_BASE_C_LOCAL - SYNTHETIC_TEMP_JITTER_C_LOCAL,
                       SYNTHETIC_TEMP_BASE_C_LOCAL + SYNTHETIC_TEMP_JITTER_C_LOCAL);
    hum_pct_ = clampf(hum_pct_ + rand_jitter(0.8f),
                        SYNTHETIC_HUM_BASE_LOCAL - SYNTHETIC_HUM_JITTER_LOCAL,
                        SYNTHETIC_HUM_BASE_LOCAL + SYNTHETIC_HUM_JITTER_LOCAL);
    pres_hpa_ = clampf(pres_hpa_ + rand_jitter(0.1f),
                         SYNTHETIC_PRES_BASE_LOCAL - SYNTHETIC_PRES_JITTER_LOCAL,
                         SYNTHETIC_PRES_BASE_LOCAL + SYNTHETIC_PRES_JITTER_LOCAL);

    SensorReading r;
    r.temp_c = temp_c_;
    r.hum_pct = hum_pct_;
    r.pres_hpa = pres_hpa_;
    r.synthetic = true;
    return r;
}

SensorReading SensorSource::read() {
    if (real_sensor_ok_) {
        SensorReading r;
        r.temp_c = g_bme.readTemperature();
        r.hum_pct = g_bme.readHumidity();
        r.pres_hpa = g_bme.readPressure() / 100.0f;  // Pa -> hPa
        r.synthetic = false;
        if (isnan(r.temp_c) || isnan(r.hum_pct) || isnan(r.pres_hpa)) {
            // Pembacaan gagal sesaat (mis. gangguan I2C) -- turun ke sintetis
            // HANYA untuk sampel ini, ditandai synthetic=true apa adanya.
            return readSynthetic();
        }
        return r;
    }
    return readSynthetic();
}
