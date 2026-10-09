"""
device_sim.py
==============
Simulator perangkat IoT (pengirim via UART / MQTT), sesuai Tabel 1 dokumen
rancangan: "Membangkitkan data sensor sintetis dengan ukuran payload
bertingkat, melakukan enkripsi SPECK, dan mengirimkan data melalui UART
maupun MQTT".

Modul ini adalah representasi PERANGKAT IoT dalam simulasi tertutup
(closed-loop simulation) yang seluruhnya berjalan sebagai proses Python di
komputer host -- TIDAK memerlukan ESP32-S3 atau sensor BME280 secara fisik.
Ini melengkapi (bukan menggantikan) firmware ESP32-S3 di folder
esp32-firmware/: keduanya mengirim payload dengan FORMAT DAN SKEMA
KRIPTOGRAFI YANG SAMA (lihat crypto_utils.py <-> esp32-firmware/src/speck.*)
lewat comm_channel.py, sehingga:
  - device_sim.py bisa dipakai SEKARANG untuk menjalankan seluruh alur
    benchmarking (S1-S4) tanpa menunggu sensor BME280 datang.
  - firmware ESP32-S3 bisa dipakai begitu sudah diflash, dan datanya
    diterima oleh server.py yang SAMA PERSIS tanpa perubahan kode.

Karena BME280 belum tersedia (lihat catatan pengguna), seluruh pembacaan
sensor pada modul ini SELALU sintetis (`"synthetic": true` pada payload)
-- sesuai batasan penelitian yang sudah didokumentasikan pada dokumen
rancangan bagian 8: "Data sensor yang digunakan bersifat sintetis dan
dibangkitkan secara terprogram, bukan hasil pembacaan sensor fisik."

Menjalankan tanpa hardware sama sekali (device_sim.py <-> server.py):
    Cara termudah & cross-platform (Windows/Linux/macOS, tanpa driver apa pun):
        python3 server.py --mode tcp --tcp-port 9999        # jalankan LEBIH DULU
        python3 device_sim.py --mode tcp --tcp-port 9999 --scenario all
    Alternatif lewat virtual serial port (socat di Linux/macOS, com0com di
    Windows -- lihat README.md untuk caveat driver signing-nya) masih
    didukung lewat --mode uart bila kamu punya alasan khusus ingin lewat
    port serial sungguhan, bukan cuma TCP loopback.

Menjalankan dengan ESP32-S3 sungguhan:
    Firmware esp32-firmware/ MENGGANTIKAN device_sim.py -- cukup jalankan
    server.py mengarah ke port USB ESP32-S3, device_sim.py tidak perlu
    dijalankan.
"""

from __future__ import annotations

import argparse
import base64
import logging
import random
import sys
import time

import attacker
import comm_channel
import config
import crypto_utils
import metrics
import payload_format as pf

logging.basicConfig(level=logging.INFO, format="%(asctime)s [device_sim] %(levelname)s %(message)s")
log = logging.getLogger("device_sim")


class SyntheticSensor:
    """Pembangkit data suhu/kelembapan/tekanan sintetis dengan pola random
    walk (bukan angka acak independen tiap kali) agar polanya menyerupai
    pembacaan sensor fisik sungguhan (perubahan bertahap, bukan lompatan
    acak antar-sampel). Rentang nilai dan titik awal mengikuti kondisi
    ruangan tropis Indonesia (lihat config.py), sebagai ASUMSI simulasi --
    BUKAN kalibrasi terhadap sensor fisik nyata, karena BME280 belum
    tersedia untuk perbandingan."""

    def __init__(self, seed: int | None = None):
        self._rng = random.Random(seed)
        self.temp_c = config.SYNTHETIC_TEMP_BASE_C
        self.hum_pct = config.SYNTHETIC_HUMIDITY_BASE_PCT
        self.pres_hpa = config.SYNTHETIC_PRESSURE_BASE_HPA

    def read(self) -> dict:
        self.temp_c += self._rng.uniform(-0.15, 0.15)
        self.temp_c = min(max(self.temp_c, config.SYNTHETIC_TEMP_BASE_C - config.SYNTHETIC_TEMP_JITTER_C),
                            config.SYNTHETIC_TEMP_BASE_C + config.SYNTHETIC_TEMP_JITTER_C)

        self.hum_pct += self._rng.uniform(-0.8, 0.8)
        self.hum_pct = min(max(self.hum_pct, config.SYNTHETIC_HUMIDITY_BASE_PCT - config.SYNTHETIC_HUMIDITY_JITTER_PCT),
                             config.SYNTHETIC_HUMIDITY_BASE_PCT + config.SYNTHETIC_HUMIDITY_JITTER_PCT)

        self.pres_hpa += self._rng.uniform(-0.1, 0.1)
        self.pres_hpa = min(max(self.pres_hpa, config.SYNTHETIC_PRESSURE_BASE_HPA - config.SYNTHETIC_PRESSURE_JITTER_HPA),
                              config.SYNTHETIC_PRESSURE_BASE_HPA + config.SYNTHETIC_PRESSURE_JITTER_HPA)

        return {
            "temp_c": round(self.temp_c, 2),
            "hum_pct": round(self.hum_pct, 2),
            "pres_hpa": round(self.pres_hpa, 2),
            "synthetic": True,
        }


def build_payload(device_id: str, seq: int, reading: dict, target_size_bytes: int) -> bytes:
    """Bentuk payload plaintext biner (lihat layout HEADER_FMT di atas) dan
    tambahkan byte pengisi agar ukuran total PERSIS sama dengan
    target_size_bytes -- diperlukan supaya skenario S2 (variasi ukuran
    payload bertingkat) memakai ukuran input yang SAMA untuk setiap
    pengulangan, sesuai prinsip fairness benchmarking pada dokumen
    rancangan.

    `device_id` tidak disertakan dalam payload terenkripsi ini karena sudah
    dikirim pada amplop pesan (wire envelope, lihat send_one()) yang tidak
    dienkripsi -- menghindari duplikasi data dan payload yang membengkak
    tanpa perlu. Lihat payload_format.py untuk layout byte lengkap."""
    temp_centi = int(round(reading["temp_c"] * 100))
    hum_centi = int(round(reading["hum_pct"] * 100))
    pres_deca = int(round(reading["pres_hpa"] * 10))
    flags = pf.FLAG_SYNTHETIC if reading.get("synthetic", True) else 0x00
    ts_ms32 = int(time.time() * 1000) & 0xFFFFFFFF

    header = pf.pack_header(seq, ts_ms32, temp_centi, hum_centi, pres_deca, flags)

    if target_size_bytes < pf.HEADER_LEN:
        log.warning(
            "target_size_bytes=%d lebih kecil dari header wajib (%d byte) -- "
            "ukuran aktual %d byte dipakai (header tidak dipangkas agar data tidak hilang).",
            target_size_bytes, pf.HEADER_LEN, pf.HEADER_LEN,
        )
        return header

    pad_needed = target_size_bytes - pf.HEADER_LEN
    return header + bytes([pf.PAD_BYTE]) * pad_needed


def send_one(channel: comm_channel.CommChannel, km: crypto_utils.KeyMaterial,
             device_id: str, seq: int, scenario: str, condition: str,
             payload_plaintext: bytes, recv_timeout_s: float,
             comm_mode: str = "uart") -> metrics.MetricRecord:
    with metrics.timed() as t_enc:
        nonce, ciphertext, tag = crypto_utils.encrypt_payload(km, payload_plaintext)
    encrypt_time_s = t_enc.elapsed_s

    wire = {
        "device_id": device_id,
        "seq": seq,
        "scenario": scenario,
        "condition": "normal",
        "nonce": nonce.hex(),
        "ct": base64.b64encode(ciphertext).decode("ascii"),
        "tag": base64.b64encode(tag).decode("ascii"),
    }

    tamper_strategy = None
    if condition == "tampered":
        wire = attacker.random_tamper(wire)
        tamper_strategy = wire.get("tamper_strategy")

    send_ts = time.time()
    wire["send_ts"] = send_ts
    channel.send(wire)
    ack = channel.receive(timeout_s=recv_timeout_s)
    recv_ts = time.time()

    rtt_s = (recv_ts - send_ts) if ack is not None else None
    accepted = bool(ack.get("accepted")) if ack is not None else False

    if not accepted and condition == "normal":
        log.warning("Pesan NORMAL ditolak server (seq=%d) -- periksa kunci/implementasi! ack=%s", seq, ack)
    if accepted and condition == "tampered":
        log.error("Pesan TAMPERED (%s) DITERIMA server (seq=%d) -- mekanisme autentikasi GAGAL mendeteksi manipulasi!",
                    tamper_strategy, seq)

    return metrics.MetricRecord(
        scenario=scenario,
        comm_mode=comm_mode,
        payload_size_bytes=len(ciphertext),
        iteration=seq,
        condition=condition,
        device_id=device_id,
        seq=seq,
        encrypt_time_s=encrypt_time_s,
        rtt_s=rtt_s,
        throughput_bps=(len(ciphertext) / encrypt_time_s) if encrypt_time_s else None,
        accepted=accepted,
        notes=tamper_strategy or "",
    )


def run_warmup(channel, km, device_id, n, payload_size, sensor):
    log.info("Fase pemanasan: mengirim %d pesan (hasil TIDAK dianalisis, menghindari bias cold start)...", n)
    for i in range(n):
        payload = build_payload(device_id, -1, sensor.read(), payload_size)
        send_one(channel, km, device_id, -1000 - i, "WARMUP", "normal", payload, recv_timeout_s=2.0)


def run_scenario(channel, km, device_id, sensor, scenario, payload_sizes, repeats, csv_logger, comm_mode="uart"):
    for size in payload_sizes:
        conditions = ["normal"] if scenario != "S4" else ["normal", "tampered"]
        for condition in conditions:
            log.info("Skenario %s | payload=%dB | kondisi=%s | %d pengulangan",
                      scenario, size, condition, repeats)
            for i in range(repeats):
                payload = build_payload(device_id, i, sensor.read(), size)
                record = send_one(channel, km, device_id, i, scenario, condition, payload,
                                    recv_timeout_s=2.0, comm_mode=comm_mode)
                csv_logger.log(record)
    log.info("Skenario %s selesai.", scenario)


SCENARIO_PAYLOAD_SIZES = {
    "S1": [config.DEFAULT_PAYLOAD_SIZE_BYTES],
    "S2": config.PAYLOAD_SIZES_BYTES,
    "S3": [config.DEFAULT_PAYLOAD_SIZE_BYTES],  # leg UART; leg MQTT lihat catatan di bawah
    "S4": [config.DEFAULT_PAYLOAD_SIZE_BYTES],
}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--mode", choices=["uart", "tcp", "mqtt"], default="uart",
                    help="'uart' = hardware ESP32-S3 sungguhan; 'tcp' = loopback lokal "
                         "tanpa hardware/driver, connect ke server.py --mode tcp (lihat README)")
    p.add_argument("--port", default=config.UART_PORT, help="Port serial (mode uart)")
    p.add_argument("--baud", type=int, default=config.UART_BAUDRATE)
    p.add_argument("--tcp-port", type=int, default=9999, help="Port TCP loopback (mode tcp), harus sama dengan server.py")
    p.add_argument("--device-id", default=config.DEVICE_ID)
    p.add_argument("--scenario", choices=["S1", "S2", "S3", "S4", "all"], default="S1")
    p.add_argument("--repeats", type=int, default=config.REPEATS_PER_SCENARIO)
    p.add_argument("--warmup", type=int, default=config.WARMUP_REQUESTS)
    p.add_argument("--seed", type=int, default=None, help="Seed RNG sensor sintetis (untuk reproducibility)")
    args = p.parse_args(argv)

    if args.mode == "mqtt":
        log.error("Mode MQTT belum diaktifkan pada rilis ini (lihat comm_channel.MqttChannel). "
                    "Gunakan --mode uart (hardware) atau --mode tcp (loopback tanpa hardware).")
        sys.exit(1)

    km = crypto_utils.KeyMaterial.from_master(config.MASTER_KEY)
    sensor = SyntheticSensor(seed=args.seed)
    if args.mode == "tcp":
        log.info("Mode tcp: menyambung ke server.py di 127.0.0.1:%d ...", args.tcp_port)
        channel = comm_channel.make_channel("tcp", role="client", tcp_port=args.tcp_port)
    else:
        channel = comm_channel.make_channel("uart", port=args.port, baudrate=args.baud)

    scenarios = ["S1", "S2", "S3", "S4"] if args.scenario == "all" else [args.scenario]
    if "S3" in scenarios:
        log.warning(
            "S3 (perbandingan UART vs MQTT) pada rilis ini hanya menjalankan leg UART "
            "(MQTT belum diaktifkan). Data yang dihasilkan hanya mewakili separuh S3."
        )

    with channel:
        run_warmup(channel, km, args.device_id, args.warmup,
                    config.DEFAULT_PAYLOAD_SIZE_BYTES, sensor)
        for scen in scenarios:
            csv_path = config.metrics_csv_path("device", scen)
            csv_logger = metrics.MetricsLogger(csv_path)
            run_scenario(channel, km, args.device_id, sensor, scen,
                          SCENARIO_PAYLOAD_SIZES[scen], args.repeats, csv_logger, comm_mode=args.mode)
            log.info("Hasil skenario %s (sisi pengirim) tersimpan di %s", scen, csv_path)


if __name__ == "__main__":
    main()
