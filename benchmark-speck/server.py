"""
server.py
=========
Modul penerima (endpoint) & baseline pengujian. Menerima payload terenkripsi
dari device_sim.py ATAU firmware ESP32-S3 sungguhan (keduanya memakai
framing/format pesan yang sama lewat comm_channel.py), melakukan dekripsi,
verifikasi keutuhan pesan (HMAC tag), penyimpanan ke SQLite, pencatatan log
CSV lewat metrics.py, dan mengirim balik ACK (dipakai pengirim untuk
menghitung RTT).

Format satu pesan (setelah dilucuti prefix protokol oleh comm_channel.py):
{
  "device_id": "esp32s3-01",
  "seq": 42,
  "scenario": "S1",            # kode skenario pengujian, lihat dokumen rancangan
  "condition": "normal",         # "normal" | "tampered" (khusus S4, lihat attacker.py)
  "nonce": "<16 hex char>",       # 8 byte, hex
  "ct": "<base64>",                # ciphertext (SPECK64/128-CTR)
  "tag": "<base64>"                 # HMAC-SHA256 truncated
}
Field "send_ts" (bila ada, dikirim device_sim.py) TIDAK dibaca server --
RTT dihitung sepenuhnya di sisi pengirim (lokal, sebelum kirim vs setelah
ACK diterima), jadi tidak perlu di-roundtrip lewat pesan.

ACK yang dikirim balik ke pengirim:
{"ack_seq": 42, "accepted": true, "server_ts": 1234567.912}

Jalankan:
    python server.py --mode uart --port /dev/ttyUSB0 --baud 115200
"""

from __future__ import annotations

import argparse
import base64
import logging
import sqlite3
import struct
import sys
import time

import comm_channel
import config
import crypto_utils
import metrics
import payload_format as pf

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [server] %(levelname)s %(message)s",
)
log = logging.getLogger("server")


def init_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sensor_readings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            seq INTEGER NOT NULL,
            scenario TEXT,
            received_at_unix REAL NOT NULL,
            temp_c REAL,
            hum_pct REAL,
            pres_hpa REAL,
            is_synthetic_sensor INTEGER,
            payload_size_bytes INTEGER
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS rejected_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT,
            seq INTEGER,
            scenario TEXT,
            condition TEXT,
            reason TEXT,
            received_at_unix REAL NOT NULL
        )
        """
    )
    conn.commit()
    return conn


def process_message(msg: dict, km: crypto_utils.KeyMaterial, conn: sqlite3.Connection,
                     logger_csv: metrics.MetricsLogger, monitor: "metrics.ResourceMonitor | None",
                     iteration_counter: dict, comm_mode: str = "uart") -> dict:
    """Proses satu pesan diterima -> return dict ACK yang harus dikirim balik."""
    device_id = msg.get("device_id", "unknown")
    seq = msg.get("seq", -1)
    scenario = msg.get("scenario", "UNSPEC")
    condition = msg.get("condition", "normal")

    try:
        nonce = bytes.fromhex(msg["nonce"])
        ciphertext = base64.b64decode(msg["ct"])
        tag = base64.b64decode(msg["tag"])
    except (KeyError, ValueError) as exc:
        log.warning("Malformed message from %s seq=%s: %s", device_id, seq, exc)
        return {"ack_seq": seq, "accepted": False, "server_ts": time.time()}

    payload_size = len(ciphertext)
    accepted = False
    tag_valid = False
    decrypt_time_s = None
    plaintext = None

    with metrics.timed() as t:
        try:
            plaintext = crypto_utils.decrypt_payload(km, nonce, ciphertext, tag)
            tag_valid = True
            accepted = True
        except ValueError as exc:
            tag_valid = False
            accepted = False
            log.info("Message REJECTED (device=%s seq=%s condition=%s): %s",
                      device_id, seq, condition, exc)
    decrypt_time_s = t.elapsed_s

    if scenario == "WARMUP":
        # Fase pemanasan (device_sim.py run_warmup()): pesan tetap didekripsi
        # & diverifikasi (supaya error kunci/implementasi tetap kelihatan
        # sejak dini), TAPI TIDAK ditulis ke CSV metrics maupun disimpan ke
        # SQLite -- konsisten dengan tujuan warmup: hasilnya tidak
        # diikutsertakan dalam analisis (menghindari bias cold start).
        return {"ack_seq": seq, "accepted": accepted, "server_ts": time.time()}

    cpu, ram = monitor.latest() if monitor is not None else (0.0, 0.0)

    key = (scenario, payload_size)
    iteration = iteration_counter.get(key, 0)
    iteration_counter[key] = iteration + 1

    record = metrics.MetricRecord(
        scenario=scenario,
        comm_mode=comm_mode,
        payload_size_bytes=payload_size,
        iteration=iteration,
        condition=condition,
        device_id=device_id,
        seq=seq,
        decrypt_time_s=decrypt_time_s,
        rtt_s=None,  # RTT diukur & dicatat di sisi pengirim (device_sim.py)
        throughput_bps=(payload_size / decrypt_time_s) if decrypt_time_s else None,
        cpu_percent=cpu,
        ram_mb=ram,
        tag_valid=tag_valid,
        accepted=accepted,
    )

    if accepted and plaintext is not None:
        try:
            sensor = pf.unpack_header(plaintext)
        except struct.error as exc:
            log.warning("Decrypted but plaintext too short for header format (device=%s seq=%s): %s",
                        device_id, seq, exc)
            record.accepted = False
            record.notes = f"plaintext_decode_error: {exc}"
            logger_csv.log(record)
            conn.execute(
                "INSERT INTO rejected_messages (device_id, seq, scenario, condition, reason, received_at_unix)"
                " VALUES (?,?,?,?,?,?)",
                (device_id, seq, scenario, condition, "plaintext_decode_error", time.time()),
            )
            conn.commit()
            return {"ack_seq": seq, "accepted": False, "server_ts": time.time()}

        conn.execute(
            "INSERT INTO sensor_readings "
            "(device_id, seq, scenario, received_at_unix, temp_c, hum_pct, pres_hpa, "
            " is_synthetic_sensor, payload_size_bytes) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                device_id, seq, scenario, time.time(),
                sensor.get("temp_c"), sensor.get("hum_pct"), sensor.get("pres_hpa"),
                1 if sensor.get("synthetic", True) else 0,
                payload_size,
            ),
        )
        conn.commit()
        record.is_synthetic_sensor = bool(sensor.get("synthetic", True))
        log.info(
            "Pesan diterima: device=%s seq=%s scenario=%s payload=%dB "
            "temp=%.2fC hum=%.1f%% pres=%.1fhPa%s",
            device_id, seq, scenario, payload_size,
            sensor.get("temp_c", float("nan")), sensor.get("hum_pct", float("nan")),
            sensor.get("pres_hpa", float("nan")),
            " [SINTETIS]" if sensor.get("synthetic", True) else "",
        )
    else:
        conn.execute(
            "INSERT INTO rejected_messages (device_id, seq, scenario, condition, reason, received_at_unix)"
            " VALUES (?,?,?,?,?,?)",
            (device_id, seq, scenario, condition,
             "hmac_tag_invalid" if not tag_valid else "unknown", time.time()),
        )
        conn.commit()

    logger_csv.log(record)
    return {"ack_seq": seq, "accepted": accepted, "server_ts": time.time()}


def run(args):
    km = crypto_utils.KeyMaterial.from_master(config.MASTER_KEY)
    conn = init_db(args.db_path)

    monitor = None
    if args.monitor_resources:
        monitor = metrics.ResourceMonitor(interval_s=config.RESOURCE_SAMPLING_INTERVAL_S)
        monitor.start()
        log.info("Resource monitor (CPU/RAM proses server, psutil) aktif.")

    csv_path = args.csv_path or config.metrics_csv_path("server", "all")
    logger_csv = metrics.MetricsLogger(csv_path)

    channel = comm_channel.make_channel(
        args.mode, port=args.port, baudrate=args.baud,
        host=config.MQTT_BROKER_HOST, topic=config.MQTT_TOPIC,
        role="server", tcp_port=args.tcp_port,
    )

    iteration_counter: dict = {}
    processed = 0
    if args.mode == "tcp":
        log.info("server.py siap. Mode=tcp (loopback, tanpa hardware) Port=127.0.0.1:%d DB=%s CSV=%s",
                  args.tcp_port, args.db_path, csv_path)
        log.info("Menunggu device_sim.py connect ke 127.0.0.1:%d ...", args.tcp_port)
    else:
        log.info("server.py siap. Mode=%s Port=%s Baud=%s DB=%s CSV=%s",
                  args.mode, args.port, args.baud, args.db_path, csv_path)
        log.info("Menunggu pesan... (Ctrl+C untuk berhenti%s)",
                  f", atau otomatis berhenti setelah {args.max_messages} pesan" if args.max_messages else "")

    try:
        with channel:
            while True:
                msg = channel.receive(timeout_s=args.recv_timeout)
                if msg is None:
                    continue
                ack = process_message(msg, km, conn, logger_csv, monitor, iteration_counter, comm_mode=args.mode)
                try:
                    channel.send(ack)
                except Exception as exc:  # noqa: BLE001
                    log.warning("Gagal mengirim ACK: %s", exc)
                processed += 1
                if args.max_messages and processed >= args.max_messages:
                    log.info("Mencapai batas %d pesan, berhenti.", args.max_messages)
                    break
    except KeyboardInterrupt:
        log.info("Dihentikan oleh pengguna (Ctrl+C).")
    finally:
        if monitor is not None:
            monitor.stop()
        conn.close()
        log.info("Total pesan diproses: %d. Data tersimpan di %s", processed, args.db_path)


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--mode", choices=["uart", "tcp", "mqtt"], default="uart",
                    help="'uart' = hardware ESP32-S3 sungguhan; 'tcp' = loopback lokal "
                         "tanpa hardware/driver (pengganti socat/com0com, lihat README)")
    p.add_argument("--port", default=config.UART_PORT, help="Port serial (mode uart), mis. /dev/ttyUSB0 atau COM5")
    p.add_argument("--baud", type=int, default=config.UART_BAUDRATE)
    p.add_argument("--tcp-port", type=int, default=9999, help="Port TCP loopback (mode tcp saja)")
    p.add_argument("--recv-timeout", type=float, default=1.0, help="Timeout tiap polling receive() (detik)")
    p.add_argument("--db-path", default=config.DB_PATH)
    p.add_argument("--csv-path", default=None, help="Default: results/metrics_all.csv")
    p.add_argument("--max-messages", type=int, default=0, help="0 = jalan terus sampai Ctrl+C")
    p.add_argument("--no-monitor", dest="monitor_resources", action="store_false",
                    help="Nonaktifkan pemantauan CPU/RAM (psutil)")
    p.set_defaults(monitor_resources=True)
    return p


if __name__ == "__main__":
    parser = build_arg_parser()
    run(parser.parse_args(sys.argv[1:]))
