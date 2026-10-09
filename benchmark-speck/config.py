"""
config.py
=========
Konfigurasi terpusat untuk seluruh modul simulasi (server, device_sim,
attacker, metrics, analyze). Disatukan di satu tempat agar parameter
eksperimen (kunci, ukuran payload, jumlah pengulangan, dsb.) konsisten
dan mudah didokumentasikan ulang untuk keperluan reproducibility
(lihat README.md bagian "Reproducibility").

Nilai default di bawah adalah REKOMENDASI, bukan hasil eksperimen.
Ubah sesuai kebutuhan skripsi lalu catat perubahannya.
"""

import os

# ---------------------------------------------------------------------------
# Kunci master (256-bit). SPECK enc key (128-bit) dan HMAC mac key (256-bit)
# diturunkan darinya lewat crypto_utils.KeyMaterial.from_master().
#
# PENTING: ini kunci untuk KEPERLUAN SIMULASI/BENCHMARKING AKADEMIK, dibaca
# dari environment variable agar tidak ikut ter-commit ke repository publik.
# Kunci yang sama harus dipakai di firmware ESP32-S3 (lihat
# esp32-firmware/include/config.h) supaya server bisa mendekripsi pesan
# dari perangkat.
# ---------------------------------------------------------------------------
MASTER_KEY_HEX = os.environ.get(
    "SPECK_MASTER_KEY_HEX",
    # Default HANYA untuk pengembangan/testing lokal. Ganti sebelum
    # pengambilan data final dan catat nilainya di README/lampiran skripsi
    # untuk reproducibility (kunci bukan rahasia produksi, hanya perlu
    # konsisten antar sesi pengujian).
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
)
MASTER_KEY = bytes.fromhex(MASTER_KEY_HEX)

DEVICE_ID = os.environ.get("DEVICE_ID", "esp32s3-01")

# ---------------------------------------------------------------------------
# Jalur komunikasi (Fase 1 penelitian ini: UART/USB Serial).
# comm_channel.py membaca nilai-nilai ini secara default; bisa dioverride
# lewat argumen CLI di server.py / device_sim.py.
# ---------------------------------------------------------------------------
UART_PORT = os.environ.get("SPECK_UART_PORT", "/dev/ttyUSB0")  # ganti sesuai OS,
                                                                  # Windows: "COM5" dst.
UART_BAUDRATE = int(os.environ.get("SPECK_UART_BAUDRATE", "115200"))
UART_TIMEOUT_S = 2.0

# MQTT: DISEDIAKAN SEBAGAI ANTARMUKA (comm_channel.MqttChannel) untuk fase
# berikutnya (skenario S3: perbandingan UART vs MQTT), belum diaktifkan pada
# rilis pertama ini karena BME280 belum tersedia dan fokus awal adalah jalur
# UART langsung dari ESP32-S3. Isi nilai ini ketika siap mengaktifkan MQTT.
MQTT_BROKER_HOST = os.environ.get("SPECK_MQTT_HOST", "localhost")
MQTT_BROKER_PORT = int(os.environ.get("SPECK_MQTT_PORT", "1883"))
MQTT_TOPIC = os.environ.get("SPECK_MQTT_TOPIC", "iot/sensor/suhu")

# ---------------------------------------------------------------------------
# Parameter eksperimen (Tabel 3 & Tabel 4 dokumen rancangan)
# ---------------------------------------------------------------------------
PAYLOAD_SIZES_BYTES = [64, 256, 1024]   # S2: variasi ukuran payload bertingkat
DEFAULT_PAYLOAD_SIZE_BYTES = 64          # dipakai pada S1 (pengujian dasar)

REPEATS_PER_SCENARIO = int(os.environ.get("SPECK_REPEATS", "31"))
# 31 kali pengulangan mengikuti acuan studi benchmarking SPECK di ESP32 yang
# dirujuk pada dokumen rancangan (bukan angka yang dikarang untuk penelitian
# ini -- dicatat sebagai referensi metodologis, lihat README).

WARMUP_REQUESTS = int(os.environ.get("SPECK_WARMUP", "10"))
# Jumlah request pemanasan (fase 3.2) yang dibuang dari analisis untuk
# menghindari bias cold start.

RESOURCE_SAMPLING_INTERVAL_S = 0.2  # interval psutil sampling CPU/RAM

# ---------------------------------------------------------------------------
# Lokasi file output
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
RESULTS_DIR = os.path.join(BASE_DIR, "results")
DASHBOARD_DIR = os.path.join(BASE_DIR, "dashboard")

DB_PATH = os.path.join(DATA_DIR, "db.sqlite")
SUMMARY_JSON_PATH = os.path.join(DASHBOARD_DIR, "summary.json")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)


def metrics_csv_path(role: str, scenario: str = "all") -> str:
    """`role` = "device" (dicatat device_sim.py / sisi pengirim: encrypt
    time, RTT, throughput) atau "server" (dicatat server.py / sisi
    penerima: decrypt time, CPU/RAM, status verifikasi tag). Dipisah per
    proses agar tidak ada dua proses menulis baris ke file CSV yang sama
    secara bersamaan (menghindari race condition penulisan file)."""
    return os.path.join(RESULTS_DIR, f"metrics_{role}_{scenario}.csv")

# ---------------------------------------------------------------------------
# Payload sintetis (sensor suhu belum tersedia -- lihat README pembatasan)
# ---------------------------------------------------------------------------
SYNTHETIC_TEMP_BASE_C = 28.0     # suhu ruangan dasar tropis (Indonesia)
SYNTHETIC_TEMP_JITTER_C = 1.5
SYNTHETIC_HUMIDITY_BASE_PCT = 65.0
SYNTHETIC_HUMIDITY_JITTER_PCT = 8.0
SYNTHETIC_PRESSURE_BASE_HPA = 1009.0
SYNTHETIC_PRESSURE_JITTER_HPA = 2.0
