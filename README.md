# Simulasi Streaming & Benchmarking SPECK64/128 pada Perangkat IoT

Implementasi dari dokumen **"Rancangan Simulasi Benchmarking Algoritma Kriptografi
SPECK dengan Beban Kerja pada Perangkat IoT"** yang kamu unggah, disesuaikan dengan
keputusan teknis berikut (dikonfirmasi sebelum implementasi dimulai):

| Keputusan | Pilihan |
|---|---|
| Varian SPECK | **SPECK64/128** (block 64-bit, key 128-bit) -- profil rekomendasi paper asli Speck untuk IoT |
| Mode operasi & autentikasi | **SPECK-CTR + HMAC-SHA256 (truncated, encrypt-then-MAC)** -- SPECK sendiri tidak punya autentikasi bawaan |
| Jalur komunikasi (fase 1) | **UART/USB Serial** (ESP32-S3 <-> PC). MQTT disiapkan sebagai kerangka, belum diaktifkan |
| Mikrokontroler | **ESP32-S3**, dikonfigurasi lewat **PlatformIO** |
| Sensor | **GY-BME280** -- **belum terpasang secara fisik**, firmware & simulator memakai data **sintetis** dengan label eksplisit, otomatis beralih ke pembacaan asli begitu sensor dipasang |
| Dashboard | **Non-real-time** -- dimuat sekali per buka halaman / klik "Muat Ulang Data", tidak ada polling otomatis |

## Struktur proyek

```
speck-iot-benchmark/
├── benchmark-speck/        # Simulasi Python (persis mengikuti struktur dokumen rancangan)
│   ├── server.py            # penerima & baseline pengujian
│   ├── device_sim.py        # simulator perangkat IoT murni-Python (S1-S4, tanpa hardware)
│   ├── crypto_utils.py      # SPECK64/128 + CTR + HMAC (tervalidasi KAT resmi)
│   ├── payload_format.py    # format biner payload sensor (shared device_sim <-> server)
│   ├── comm_channel.py      # abstraksi UART (aktif) / MQTT (kerangka)
│   ├── attacker.py           # pembuat pesan tampered (skenario S4)
│   ├── metrics.py             # pencatat waktu, RTT, throughput, CPU/RAM
│   ├── analyze.py              # statistik (mean/std/95% CI) + grafik + dashboard JSON
│   ├── config.py                # parameter eksperimen terpusat
│   ├── dashboard/index.html      # dashboard non-real-time
│   ├── tests/test_speck_kat.py    # Known Answer Test resmi SPECK64/128
│   ├── data/, results/              # dibangkitkan saat runtime (kosong di repo ini)
│   └── requirements.txt
└── esp32-firmware/            # Proyek PlatformIO untuk ESP32-S3
    ├── platformio.ini
    ├── include/config.h        # kunci, pin I2C, parameter streaming
    └── src/
        ├── main.cpp             # loop utama: baca sensor -> enkripsi -> kirim -> ACK
        ├── speck.cpp/.h          # SPECK64/128 + CTR (port C dari crypto_utils.py)
        ├── hmac_util.cpp/.h       # HMAC-SHA256 (mbedtls bawaan ESP-IDF)
        ├── keys.cpp/.h             # turunan kunci enkripsi & MAC dari master key
        ├── payload.cpp/.h           # format payload biner (identik payload_format.py)
        ├── sensor.cpp/.h             # BME280 asli + fallback sintetis otomatis
        └── base64_util.cpp/.h         # encode base64 (mbedtls bawaan)
```

## Peran firmware ESP32-S3 vs device_sim.py -- BACA INI DULU

Karena **BME280 belum terpasang**, ada dua cara menjalankan pipeline, dan keduanya
memakai **format pesan & skema kriptografi yang identik** lewat `server.py` yang sama:

1. **`device_sim.py`** (Python, tanpa hardware sama sekali) -- menjalankan **seluruh**
   skenario S1-S4 (31 pengulangan, 3 tier payload, normal vs tampered) secara otomatis,
   persis seperti dijelaskan dokumen rancangan ("simulator dibangun dengan Python").
   **Gunakan ini untuk pengambilan data benchmarking S1-S4 yang lengkap sekarang juga**,
   tanpa menunggu ESP32-S3/BME280.
2. **Firmware `esp32-firmware/`** -- membuktikan pipeline berjalan di **hardware
   sungguhan**: ESP32-S3 membaca sensor (sintetis untuk saat ini), mengenkripsi dengan
   SPECK64/128-CTR, menghitung tag HMAC, dan **streaming** kontinu lewat USB Serial ke
   `server.py`. Ini adalah "simulasi streaming untuk cek data sensor suhu" yang kamu
   minta -- mode default-nya **streaming berkelanjutan** (bukan otomasi S1-S4 penuh),
   supaya kamu bisa langsung melihat data mengalir end-to-end di dashboard.
   Firmware ini **sudah siap** membaca BME280 fisik tanpa perlu ubah kode apa pun --
   begitu sensor terpasang & terdeteksi lewat I2C, firmware otomatis berpindah dari
   data sintetis ke data sensor asli (lihat `src/sensor.cpp`).

Kalau nanti ingin mengulang skenario S1-S4 penuh di atas hardware ESP32-S3 sungguhan
(bukan hanya streaming), firmware perlu ditambah penerima perintah dari PC (mirip
argumen `--scenario` pada `device_sim.py`) -- ini disebutkan sebagai pengembangan
lanjutan di bagian Keterbatasan, bukan bug.

## Setup

### 1. ESP32-S3 (PlatformIO)

```bash
cd esp32-firmware
pio run -t upload    # compile + flash
pio device monitor    # lihat log (baris "#...") -- Ctrl+C untuk keluar
```

Sebelum upload, periksa `esp32-firmware/include/config.h`:
- `BME280_SDA_PIN` / `BME280_SCL_PIN` -- **sesuaikan dengan datasheet/silkscreen modul
  ESP32-S3 kamu** (default GPIO8/GPIO9 adalah asumsi umum, belum tentu cocok semua board).
- `SPECK_MASTER_KEY_HEX` -- **harus identik** dengan `SPECK_MASTER_KEY_HEX` di
  `benchmark-speck/config.py`. Sudah disamakan secara default; kalau salah satu diganti,
  ganti juga yang lain, atau semua pesan akan ditolak server (`tag_valid=False`).
- `platformio.ini` memakai board generik `esp32-s3-devkitc-1` -- ganti field `board`
  bila modul ESP32-S3 kamu berbeda (cek daftar board PlatformIO Espressif32).

### 2. PC (Python)

**Linux/macOS (bash/zsh):**

```bash
cd benchmark-speck
python3 -m venv .venv && source .venv/bin/activate   # opsional tapi direkomendasikan
python3 -m pip install -r requirements.txt
python3 tests/test_speck_kat.py     # WAJIB: validasi implementasi sebelum lanjut
```

**Windows (PowerShell):**

```powershell
cd benchmark-speck
python3 -m venv .venv                # opsional tapi direkomendasikan
.venv\Scripts\Activate.ps1            # baris terpisah -- source (bash) tidak ada di PowerShell
python3 -m pip install -r requirements.txt
python3 tests/test_speck_kat.py       # WAJIB: validasi implementasi sebelum lanjut
```

> **Kenapa `python3 -m pip install ...`, bukan `pip install ...`?** Kalau di komputer
> kamu ada lebih dari satu instalasi Python (umum di Windows -- mis. satu dari
> python.org, satu dari Microsoft Store), `pip` (tanpa embel-embel) bisa saja terikat ke
> interpreter yang **berbeda** dari yang dipanggil `python3`. Akibatnya `pip install`
> "berhasil" (bahkan bilang "Requirement already satisfied") tapi `python3 analyze.py`
> tetap `ModuleNotFoundError`, karena package ter-install di site-packages interpreter
> yang lain. `python3 -m pip install ...` menjamin instalasi masuk ke interpreter yang
> sama persis dengan yang dipakai menjalankan skrip. Kalau ragu, cek dengan:
> ```powershell
> python3 -c "import sys; print(sys.executable)"
> ```
> dan pastikan hasilnya konsisten setiap kali.
>
> Juga: kalau `.venv\Scripts\Activate.ps1` ditolak dengan error terkait "execution
> policy", venv tetap boleh dilewati (opsional) -- langsung jalankan
> `python3 -m pip install -r requirements.txt` tanpa mengaktifkan venv.

Semua modul Python sudah divalidasi di lingkungan pengembangan (KAT resmi SPECK64/128,
round-trip CTR+HMAC berbagai panjang payload, deteksi tamper untuk seluruh strategi di
`attacker.py`, dan alur `device_sim.py -> server.py` end-to-end tanpa hardware).
**Firmware ESP32-S3 belum bisa dikompilasi di lingkungan pengembangan ini** (tidak ada
akses internet untuk mengunduh toolchain PlatformIO) -- sebagai gantinya, seluruh logika
inti (`speck.cpp`, turunan kunci di `keys.cpp`) sudah diverifikasi SILANG terhadap
implementasi Python (hasil byte-persis sama untuk key/nonce/plaintext yang sama) dan
lolos pengecekan sintaks C++ terhadap definisi API Arduino/ESP-IDF/mbedTLS yang
sebenarnya. **Tetap jalankan `pio run` (compile saja, tanpa upload) sebagai langkah
pertama** setelah `pio run -t upload` pertama kali di hardware kamu, untuk memastikan
tidak ada perbedaan API pada versi framework/board spesifik kamu.

## Menjalankan

### A. Full skenario S1-S4 tanpa hardware (device_sim.py)

Tanpa ESP32-S3 sama sekali, jalankan `server.py` dan `device_sim.py` sebagai dua proses
yang saling terhubung. Ada dua cara:

**A1. `--mode tcp` (direkomendasikan, cross-platform, tanpa driver apa pun)** --
loopback TCP di localhost, jalan sama persis di Windows/Linux/macOS, tidak perlu
install apa pun di luar `requirements.txt`. **Jalankan `server.py` LEBIH DULU** (dia
menunggu koneksi), baru `device_sim.py`:

```bash
# Terminal 1 (jalankan LEBIH DULU -- server menunggu koneksi)
python3 server.py --mode tcp --tcp-port 9999

# Terminal 2
python3 device_sim.py --mode tcp --tcp-port 9999 --scenario all --repeats 31
```

**A2. `--mode uart` lewat virtual serial port** -- kalau kamu punya alasan khusus ingin
lewat port serial sungguhan (bukan cuma TCP), di Linux/macOS pakai `socat`:

```bash
socat -d -d pty,raw,echo=0,link=/tmp/ttyV0 pty,raw,echo=0,link=/tmp/ttyV1 &
python3 server.py --port /tmp/ttyV0            # terminal 1
python3 device_sim.py --port /tmp/ttyV1 --scenario all --repeats 31   # terminal 2
```
Di Windows, `socat` tidak tersedia -- padanannya adalah **com0com**, tapi driver ini
sering bermasalah dengan driver signing di Windows 10/11 modern (error "Code 52") dan
perlu langkah tambahan (signature patch atau test-signing mode + nonaktifkan Secure
Boot). **Untuk kebutuhan menjalankan S1-S4 tanpa hardware, pakai opsi A1 (`--mode tcp`)
saja** -- hasilnya setara (keduanya sama-sama loopback lokal di software, bukan
transmisi UART hardware sungguhan; lihat catatan di bagian Reproducibility) tapi jauh
lebih mudah disiapkan.

> **Catatan jujur soal "UART" di sini:** baik `--mode tcp` maupun `--mode uart` lewat
> `socat`/com0com sama-sama loopback software di satu komputer -- **bukan** representasi
> timing UART hardware sungguhan (bahkan virtual serial port pun umumnya tidak
> menegakkan baud rate yang dikonfigurasi). Data "UART" yang benar-benar merepresentasikan
> hardware hanya didapat dari **opsi B** (ESP32-S3 sungguhan lewat USB). Kalau kamu
> memakai `--mode tcp` untuk mengambil data S1-S4, laporkan di skripsi sebagai "simulasi
> loopback lokal", bukan "pengukuran UART", supaya tidak overclaim.

### B. Streaming dengan ESP32-S3 sungguhan

```bash
python3 server.py --port /dev/ttyACM0   # sesuaikan port (Linux: /dev/ttyACM0 atau
                                           # /dev/ttyUSB0, macOS: /dev/cu.usbmodemXXXX,
                                           # Windows: COMx)
```
Firmware yang sudah diflash akan langsung mulai streaming begitu port dibuka.

### C. Lihat hasil (dashboard non-real-time)

```bash
python3 analyze.py                 # jalankan ULANG setiap habis sesi pengujian baru

# Linux/macOS (bash/zsh):
cd dashboard && python3 -m http.server 8000

# Windows PowerShell (5.1 bawaan Windows TIDAK mendukung "&&" sebagai
# pemisah perintah -- itu baru ada di PowerShell 7+/pwsh):
cd dashboard; python3 -m http.server 8000
# atau dua baris terpisah:
#   cd dashboard
#   python3 -m http.server 8000

# lalu buka http://localhost:8000 di browser, klik "Muat Ulang Data" untuk memuat data terbaru
```

> Begitu `python3 -m http.server 8000` jalan, terminal itu **akan ter-block** (server
> terus menunggu request, prompt tidak kembali) -- itu normal, bukan hang. Buka browser
> ke `http://localhost:8000` dari jendela lain sambil terminal ini tetap jalan, dan
> tekan `Ctrl+C` di terminal ini kalau mau menghentikan server. Setelah menjalankan
> ulang `analyze.py` untuk data baru, cukup refresh browser + klik "Muat Ulang Data" --
> tidak perlu restart `http.server`.

Dashboard membaca `dashboard/summary.json` sekali saat dibuka -- **tidak** polling
otomatis, sesuai permintaan. Grafik tambahan (siap untuk lampiran skripsi) tersimpan
sebagai PNG di `results/charts/` setelah `analyze.py` dijalankan.

## Reproducibility (dicatat sesuai kebutuhan akademik)

| Parameter | Nilai |
|---|---|
| Algoritma | SPECK64/128 (Beaulieu et al., 2015, ePrint 2013/404), 27 round, alpha=8, beta=3 |
| Mode & autentikasi | CTR (stream, tanpa padding) + HMAC-SHA256 truncated 128-bit (encrypt-then-MAC) |
| Tier payload (S2) | 64, 256, 1024 byte (header biner 16 byte + padding) |
| Pengulangan per skenario | 31 (mengikuti acuan studi benchmarking SPECK di ESP32 yang dirujuk dokumen rancangan) |
| Warmup | 10 request dibuang sebelum pencatatan (menghindari bias cold start) |
| Pengukuran waktu | `time.perf_counter()` (Python) / belum diinstrumentasi presisi tinggi di firmware C++ (lihat Keterbatasan) |
| Pengukuran CPU/RAM | `psutil`, proses `server.py` di **komputer host**, BUKAN mikrokontroler |
| Statistik | mean, sample std dev (ddof=1), 95% CI (t-distribution, `scipy.stats.t.interval`) |

**Kunci master (SPECK_MASTER_KEY_HEX)** dipakai HANYA untuk keperluan simulasi/
benchmarking akademik agar hasil dapat direproduksi antar sesi -- bukan kunci rahasia
produksi. Nilai default tercatat di `benchmark-speck/config.py` dan
`esp32-firmware/include/config.h`.

## Keterbatasan (mengikuti & memperluas bagian 8 dokumen rancangan)

1. Pengukuran CPU/RAM dilakukan pada proses `server.py` di komputer host, tidak
   merepresentasikan konsumsi sumber daya ESP32-S3 secara langsung. Untuk mengukur RAM/
   Flash firmware sesungguhnya, gunakan output `pio run` (bagian "RAM:"/"Flash:") setelah
   kompilasi -- belum diotomasi ke `metrics.py`.
2. **Sensor BME280 belum terpasang** -- seluruh pembacaan suhu/kelembapan/tekanan saat
   ini SINTETIS (random walk, bukan hasil pembacaan fisik), ditandai eksplisit
   (`synthetic: true`, kolom `is_synthetic_sensor` di SQLite) di setiap baris data,
   TIDAK PERNAH disamarkan sebagai data sensor asli.
3. Firmware ESP32-S3 belum bisa dikompilasi/diuji di lingkungan pengembangan ini (tidak
   ada akses internet untuk toolchain PlatformIO) -- lihat bagian Setup untuk langkah
   verifikasi yang sudah & belum dilakukan.
4. Firmware menjalankan mode **streaming kontinu**, bukan otomasi skenario S1-S4 penuh
   (31 pengulangan x 3 tier payload x normal/tampered) -- otomasi penuh saat ini hanya
   tersedia lewat `device_sim.py`. Mengadaptasi firmware untuk menerima perintah
   skenario dari PC (mirip argumen CLI `device_sim.py`) adalah pengembangan lanjutan
   yang wajar untuk fase berikutnya begitu BME280 terpasang dan pengujian di hardware
   asli diperlukan.
5. Jalur MQTT (skenario S3) belum diaktifkan -- lihat `comm_channel.py` untuk kerangka
   & langkah aktivasinya (broker Mosquitto, `paho-mqtt`, kredensial WiFi).
6. Pengujian keamanan dibatasi pada aspek autentikasi/deteksi tampered (HMAC tag),
   TIDAK mencakup kriptanalisis terhadap algoritma SPECK itu sendiri.
7. `TAMPER_DEMO_EVERY_N_MESSAGES` di firmware (default nonaktif) hanya demonstrasi
   sederhana satu strategi tamper (flip 1 bit ciphertext); variasi tamper lebih lengkap
   (lihat `attacker.py`: flip tag, truncate, replay nonce) saat ini hanya ada di jalur
   `device_sim.py`.
