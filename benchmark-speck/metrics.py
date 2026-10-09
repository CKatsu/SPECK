"""
metrics.py
==========
Merekam waktu enkripsi dan dekripsi, Round-Trip Time (RTT), throughput,
serta penggunaan CPU dan RAM pada sisi penerima (sesuai Tabel 1 dokumen
rancangan).

Catatan metodologis (mengikuti prinsip validitas eksperimen):
  - Waktu enkripsi/dekripsi diukur TERPISAH dari waktu pembentukan payload
    sensor dan waktu transmisi, memakai `time.perf_counter()` (resolusi
    tinggi, tidak dipengaruhi perubahan jam sistem) -- lihat device_sim.py
    dan server.py untuk titik pengukuran persisnya. Ini penting supaya
    "pure cryptographic execution time" tidak tercampur dengan waktu I/O.
  - RTT diukur di sisi pengirim (device_sim.py): selisih waktu antara
    pesan dikirim dan ACK/response diterima dari server.
  - CPU/RAM diukur dengan `psutil` pada proses server.py yang berjalan di
    komputer host -- BUKAN pada mikrokontroler (lihat batasan penelitian
    di README/dokumen rancangan bagian 8).
  - Semua hasil mentah (raw, per-iterasi) dicatat dulu ke CSV sebelum
    dihitung statistiknya di analyze.py -- tidak ada agregasi "di tempat"
    yang membuang data mentah.
"""

from __future__ import annotations

import csv
import os
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from typing import Optional

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None


@contextmanager
def timed():
    """Context manager -> objek dengan atribut `.elapsed_s` (detik) setelah
    blok selesai, diukur dengan time.perf_counter() (monotonic, presisi
    tinggi)."""
    class _T:
        elapsed_s: float = 0.0

    t = _T()
    start = time.perf_counter()
    try:
        yield t
    finally:
        t.elapsed_s = time.perf_counter() - start


class ResourceMonitor:
    """Sampling CPU% dan RAM (RSS, MB) proses saat ini pada interval
    tertentu di background thread, sesuai fase inisialisasi (3.1) dokumen
    rancangan: "modul pemantauan sumber daya mulai melakukan pencuplikan
    penggunaan CPU dan RAM pada interval tertentu".

    Dipakai oleh server.py (mengukur proses penerima)."""

    def __init__(self, interval_s: float = 0.2):
        if psutil is None:
            raise RuntimeError("psutil belum terinstall. Jalankan: pip install psutil")
        self.interval_s = interval_s
        self._process = psutil.Process(os.getpid())
        self._samples_cpu: list[float] = []
        self._samples_ram_mb: list[float] = []
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _run(self):
        # Panggilan pertama cpu_percent() selalu 0.0 (baseline) -- dibuang.
        self._process.cpu_percent(interval=None)
        while not self._stop_event.is_set():
            cpu = self._process.cpu_percent(interval=None)
            ram_mb = self._process.memory_info().rss / (1024 * 1024)
            self._samples_cpu.append(cpu)
            self._samples_ram_mb.append(ram_mb)
            self._stop_event.wait(self.interval_s)

    def start(self):
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def snapshot_means(self) -> tuple[float, float]:
        """Return (mean_cpu_percent, mean_ram_mb) dari sampel yang terkumpul
        sejak start() (atau sejak snapshot terakhir dipanggil -- sampel TIDAK
        direset di sini, panggil reset() eksplisit di batas skenario)."""
        cpu = sum(self._samples_cpu) / len(self._samples_cpu) if self._samples_cpu else 0.0
        ram = sum(self._samples_ram_mb) / len(self._samples_ram_mb) if self._samples_ram_mb else 0.0
        return cpu, ram

    def reset(self):
        self._samples_cpu.clear()
        self._samples_ram_mb.clear()

    def latest(self) -> tuple[float, float]:
        """Sampel CPU%/RAM(MB) paling akhir yang terekam background thread.
        Dipakai server.py untuk menandai tiap MetricRecord dengan kondisi
        sumber daya terkini tanpa memblokir loop penerimaan pesan."""
        cpu = self._samples_cpu[-1] if self._samples_cpu else 0.0
        ram = self._samples_ram_mb[-1] if self._samples_ram_mb else 0.0
        return cpu, ram


@dataclass
class MetricRecord:
    scenario: str                  # S1, S2, S3, S4
    comm_mode: str                  # "uart" | "mqtt"
    payload_size_bytes: int
    iteration: int                  # indeks pengulangan (0-based, sudah exclude warmup)
    condition: str                  # "normal" | "tampered"
    device_id: str
    seq: int
    encrypt_time_s: Optional[float] = None
    decrypt_time_s: Optional[float] = None
    rtt_s: Optional[float] = None
    throughput_bps: Optional[float] = None   # byte per detik (ciphertext/detik)
    cpu_percent: Optional[float] = None
    ram_mb: Optional[float] = None
    tag_valid: Optional[bool] = None
    accepted: Optional[bool] = None           # apakah server menerima pesan ini
    is_synthetic_sensor: bool = True           # True selama BME280 fisik belum terpasang
    timestamp_unix: float = field(default_factory=time.time)
    notes: str = ""


class MetricsLogger:
    """Menulis MetricRecord ke CSV per skenario. Header ditulis sekali;
    baris berikutnya di-append -- sehingga proses bisa dihentikan/dilanjutkan
    tanpa kehilangan data mentah yang sudah terekam."""

    _FIELDNAMES = list(MetricRecord.__dataclass_fields__.keys())

    def __init__(self, csv_path: str):
        self.csv_path = csv_path
        os.makedirs(os.path.dirname(csv_path), exist_ok=True)
        self._write_header_if_needed()

    def _write_header_if_needed(self):
        if not os.path.exists(self.csv_path) or os.path.getsize(self.csv_path) == 0:
            with open(self.csv_path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=self._FIELDNAMES)
                writer.writeheader()

    def log(self, record: MetricRecord) -> None:
        with open(self.csv_path, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=self._FIELDNAMES)
            writer.writerow(asdict(record))
