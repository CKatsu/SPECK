#pragma once
// =============================================================================
// sensor.h -- sumber data sensor suhu/kelembapan/tekanan: BME280 asli
// (begitu terpasang) dengan FALLBACK OTOMATIS ke data sintetis selama
// sensor fisik belum tersedia.
// =============================================================================
// Perilaku: begin() mencoba menginisialisasi BME280 lewat I2C (alamat
// 0x76 lalu 0x77). Jika GAGAL (sensor belum terpasang -- kondisi saat ini),
// firmware TIDAK berhenti/gagal boot -- otomatis beralih ke pembangkit data
// sintetis (random walk, mirip device_sim.SyntheticSensor di Python) agar
// pipeline streaming end-to-end tetap bisa diuji sekarang. Setiap pembacaan
// diberi label eksplisit `synthetic=true/false` (lihat payload.h field
// `flags`) sehingga TIDAK PERNAH ada data sintetis yang menyamar sebagai
// data sensor fisik asli pada hasil penelitian.
// =============================================================================
#include "payload.h"

class SensorSource {
public:
    void begin();
    SensorReading read();
    bool usingRealSensor() const { return real_sensor_ok_; }

private:
    bool real_sensor_ok_ = false;
    // state random-walk sintetis
    float temp_c_ = 28.0f;
    float hum_pct_ = 65.0f;
    float pres_hpa_ = 1009.0f;

    SensorReading readSynthetic();
};
