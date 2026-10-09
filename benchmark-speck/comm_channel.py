"""
comm_channel.py
================
Menyediakan antarmuka pengiriman data yang seragam (abstraksi) untuk moda
komunikasi UART dan MQTT, agar device_sim.py / server.py / metrics.py tidak
perlu tahu detail transport yang dipakai -- dan perbandingan antar moda
(skenario S3) tetap adil karena keduanya mengimplementasikan interface yang
sama (`CommChannel`).

Status implementasi (lihat keputusan desain di README):
  - UartChannel : SELESAI, dipakai untuk seluruh alur streaming dengan
    HARDWARE SUNGGUHAN (ESP32-S3 <-> PC lewat kabel USB, tanpa perlu
    WiFi/broker).
  - TcpLoopbackChannel : SELESAI. Transport TCP localhost, KHUSUS untuk
    menjalankan device_sim.py <-> server.py di SATU KOMPUTER TANPA hardware
    ESP32 dan TANPA virtual serial port driver (pengganti `socat`/com0com).
    Berguna terutama di Windows, di mana com0com sering bermasalah dengan
    driver signing (error "Code 52") di Windows 10/11 modern. Ini BUKAN
    salah satu dari dua moda komunikasi yang dibandingkan penelitian (UART
    vs MQTT) -- murni kemudahan pengembangan/pengujian lokal untuk
    menjalankan skenario S1-S4 lewat device_sim.py sebelum/tanpa hardware.
  - MqttChannel : KERANGKA / BELUM DIAKTIFKAN. Disediakan agar skenario S3
    (perbandingan UART vs MQTT) tinggal plug-in begitu WiFi & broker MQTT
    (mis. Mosquitto) sudah disiapkan. Memanggil connect()/send() pada kelas
    ini saat ini akan raise NotImplementedError dengan pesan yang jelas.

Framing pesan (dipakai oleh SEMUA channel di atas -- UART, TCP loopback,
dan nanti MQTT -- supaya server.py memproses pesan dengan cara yang sama
persis terlepas dari transportnya):
  Setiap pesan dikirim sebagai SATU baris teks:
      "SPK1:" + json.dumps(record) + "\n"
  Prefix "SPK1:" (protocol tag + versi) dipakai untuk membedakan baris
  protokol dari baris log/debug lain yang mungkin dicetak firmware ke
  Serial (mis. pesan boot ESP32), supaya parser tidak crash saat membaca
  baris non-protokol -- baris semacam itu cukup diabaikan (bukan dianggap
  pesan korup).
"""

from __future__ import annotations

import json
import socket
import time
from abc import ABC, abstractmethod
from typing import Optional

PROTOCOL_PREFIX = "SPK1:"


class CommChannel(ABC):
    """Interface seragam untuk semua jalur komunikasi."""

    @abstractmethod
    def connect(self) -> None: ...

    @abstractmethod
    def send(self, record: dict) -> None: ...

    @abstractmethod
    def receive(self, timeout_s: Optional[float] = None) -> Optional[dict]:
        """Return dict pesan berikutnya, atau None bila timeout / tidak ada
        baris protokol yang valid diterima dalam batas waktu."""
        ...

    @abstractmethod
    def close(self) -> None: ...

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()


class UartChannel(CommChannel):
    """Jalur UART/USB Serial. Dipakai oleh device_sim.py (mode software-only,
    lewat pty virtual atau langsung ke port ESP32) dan server.py (menerima
    dari ESP32-S3 sungguhan lewat kabel USB)."""

    def __init__(self, port: str, baudrate: int = 115200, timeout_s: float = 2.0):
        self.port = port
        self.baudrate = baudrate
        self.timeout_s = timeout_s
        self._ser = None

    def connect(self) -> None:
        import serial  # pyserial; lazy import agar modul lain tidak wajib install pyserial

        self._ser = serial.Serial(
            port=self.port, baudrate=self.baudrate, timeout=self.timeout_s
        )
        # Beri waktu board reset setelah port dibuka (perilaku umum ESP32
        # yang me-reset saat DTR/RTS toggle ketika serial port dibuka).
        time.sleep(2.0)
        self._ser.reset_input_buffer()

    def send(self, record: dict) -> None:
        if self._ser is None:
            raise RuntimeError("UartChannel belum connect()")
        line = (PROTOCOL_PREFIX + json.dumps(record, separators=(",", ":")) + "\n").encode("utf-8")
        self._ser.write(line)
        self._ser.flush()

    def receive(self, timeout_s: Optional[float] = None) -> Optional[dict]:
        if self._ser is None:
            raise RuntimeError("UartChannel belum connect()")
        deadline = None if timeout_s is None else (time.monotonic() + timeout_s)
        while True:
            if deadline is not None and time.monotonic() > deadline:
                return None
            raw = self._ser.readline()
            if not raw:
                if deadline is None:
                    continue
                return None
            try:
                text = raw.decode("utf-8", errors="replace").strip()
            except Exception:
                continue
            if not text.startswith(PROTOCOL_PREFIX):
                # Baris non-protokol (log boot ESP32, debug print, dsb) --
                # diabaikan, bukan error.
                continue
            payload_text = text[len(PROTOCOL_PREFIX):]
            try:
                return json.loads(payload_text)
            except json.JSONDecodeError:
                # Baris protokol tapi JSON korup (mis. terpotong akibat
                # gangguan transmisi) -- dilaporkan sebagai None supaya
                # pemanggil bisa mencatatnya sebagai pesan gagal, bukan
                # membuat proses crash.
                return None

    def close(self) -> None:
        if self._ser is not None:
            self._ser.close()
            self._ser = None


class TcpLoopbackChannel(CommChannel):
    """Transport TCP di 127.0.0.1, pengganti UartChannel KHUSUS untuk
    menjalankan device_sim.py <-> server.py di satu komputer tanpa hardware
    ESP32 dan tanpa virtual serial port driver (com0com/socat) -- lihat
    docstring modul. Framing pesan (baris "SPK1:{json}\\n") identik dengan
    UartChannel, jadi server.py/device_sim.py tidak perlu tahu bedanya.

    role="server": bind + listen di `port`, connect() akan BLOCK sampai
                   satu client (device_sim.py) tersambung -- jalankan
                   server.py TERLEBIH DAHULU.
    role="client": connect ke 127.0.0.1:`port`, dengan beberapa kali retry
                   singkat (server mungkin belum selesai listen())."""

    def __init__(self, role: str, port: int, host: str = "127.0.0.1", timeout_s: float = 2.0):
        if role not in ("server", "client"):
            raise ValueError("role harus 'server' atau 'client'")
        self.role = role
        self.host = host
        self.port = port
        self.timeout_s = timeout_s
        self._listen_sock: Optional[socket.socket] = None
        self._sock: Optional[socket.socket] = None
        self._rfile = None  # file-like buffered reader (mirip readline() UartChannel)

    def connect(self) -> None:
        if self.role == "server":
            self._listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._listen_sock.bind((self.host, self.port))
            self._listen_sock.listen(1)
            self._sock, _addr = self._listen_sock.accept()
        else:
            last_exc = None
            for _attempt in range(20):  # +/- 10 detik total, cukup untuk server sempat listen()
                try:
                    self._sock = socket.create_connection((self.host, self.port), timeout=self.timeout_s)
                    last_exc = None
                    break
                except OSError as exc:
                    last_exc = exc
                    time.sleep(0.5)
            if last_exc is not None:
                raise ConnectionError(
                    f"Gagal connect ke 127.0.0.1:{self.port} setelah beberapa kali percobaan -- "
                    f"pastikan server.py sudah dijalankan LEBIH DULU dengan --mode tcp --tcp-port {self.port}. "
                    f"Error terakhir: {last_exc}"
                )

        self._sock.settimeout(self.timeout_s)
        self._rfile = self._sock.makefile("rb")

    def send(self, record: dict) -> None:
        if self._sock is None:
            raise RuntimeError("TcpLoopbackChannel belum connect()")
        line = (PROTOCOL_PREFIX + json.dumps(record, separators=(",", ":")) + "\n").encode("utf-8")
        self._sock.sendall(line)

    def receive(self, timeout_s: Optional[float] = None) -> Optional[dict]:
        if self._sock is None or self._rfile is None:
            raise RuntimeError("TcpLoopbackChannel belum connect()")
        self._sock.settimeout(timeout_s if timeout_s is not None else self.timeout_s)
        try:
            raw = self._rfile.readline()
        except socket.timeout:
            return None
        if not raw:
            return None  # koneksi ditutup pihak lain
        text = raw.decode("utf-8", errors="replace").strip()
        if not text.startswith(PROTOCOL_PREFIX):
            return None
        payload_text = text[len(PROTOCOL_PREFIX):]
        try:
            return json.loads(payload_text)
        except json.JSONDecodeError:
            return None

    def close(self) -> None:
        if self._rfile is not None:
            self._rfile.close()
            self._rfile = None
        if self._sock is not None:
            self._sock.close()
            self._sock = None
        if self._listen_sock is not None:
            self._listen_sock.close()
            self._listen_sock = None


class MqttChannel(CommChannel):
    """Kerangka jalur MQTT untuk skenario S3 (belum diaktifkan pada rilis
    ini). Lihat docstring modul untuk alasan penundaan."""

    def __init__(self, host: str, port: int, topic: str):
        self.host = host
        self.port = port
        self.topic = topic

    def connect(self) -> None:
        raise NotImplementedError(
            "MqttChannel belum diaktifkan pada rilis pertama ini (fokus awal: "
            "jalur UART langsung dari ESP32-S3, sesuai keputusan desain). "
            "Untuk mengaktifkan skenario S3 (UART vs MQTT): (1) siapkan "
            "broker MQTT lokal, mis. Mosquitto, (2) install `paho-mqtt`, "
            "(3) isi kredensial WiFi & broker di config.py dan "
            "esp32-firmware/include/config.h, lalu implementasikan "
            "connect()/send()/receive() di kelas ini mengikuti interface "
            "CommChannel yang sama dengan UartChannel."
        )

    def send(self, record: dict) -> None:
        raise NotImplementedError("MqttChannel belum diaktifkan, lihat connect().")

    def receive(self, timeout_s: Optional[float] = None) -> Optional[dict]:
        raise NotImplementedError("MqttChannel belum diaktifkan, lihat connect().")

    def close(self) -> None:
        pass


def make_channel(mode: str, **kwargs) -> CommChannel:
    """Factory sederhana dipakai server.py/device_sim.py agar mode
    komunikasi bisa dipilih lewat argumen CLI (--mode uart|tcp|mqtt) tanpa
    mengubah logika utama."""
    mode = mode.lower()
    if mode == "uart":
        return UartChannel(
            port=kwargs.get("port"),
            baudrate=kwargs.get("baudrate", 115200),
            timeout_s=kwargs.get("timeout_s", 2.0),
        )
    if mode == "tcp":
        return TcpLoopbackChannel(
            role=kwargs.get("role"),
            port=kwargs.get("tcp_port", 9999),
            host=kwargs.get("host", "127.0.0.1"),
            timeout_s=kwargs.get("timeout_s", 2.0),
        )
    if mode == "mqtt":
        return MqttChannel(
            host=kwargs.get("host"), port=kwargs.get("port", 1883), topic=kwargs.get("topic")
        )
    raise ValueError(f"Unknown comm mode: {mode!r} (expected 'uart', 'tcp', or 'mqtt')")
