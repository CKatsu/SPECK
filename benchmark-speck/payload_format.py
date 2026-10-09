"""
payload_format.py
==================
Definisi tunggal (single source of truth) untuk format PLAINTEXT sensor
yang dienkripsi SPECK64/128-CTR, dipakai bersama oleh device_sim.py dan
server.py (dan direplikasi persis sebagai struct C di
esp32-firmware/src/sensor.h -- lihat komentar di sana).

Layout header (16 byte, little-endian):
    offset  size  field         keterangan
    0       4     seq           uint32, nomor urut pesan
    4       4     ts_ms32       uint32, 32 bit rendah dari epoch ms (wrap
                                  ~49.7 hari -- cukup untuk durasi pengujian)
    8       2     temp_centi     int16,  suhu (Celsius) x 100
    10      2     hum_centi      uint16, kelembapan relatif (%) x 100
    12      2     pres_deca      uint16, tekanan (hPa) x 10
    14      1     flags           uint8,  bit0 = 1 jika data sintetis
    15      1     reserved        uint8,  selalu 0, disediakan untuk versi mendatang

Byte setelah offset 16 (jika ada) adalah byte pengisi (PAD_BYTE) yang HANYA
menyesuaikan ukuran total payload ke target ukuran tier (skenario S2),
tidak dibaca sebagai data.

Payload biner (bukan JSON) dipilih agar:
  1. Tier terkecil pada skenario S2 (mis. 64 byte, dokumen rancangan)
     benar-benar tercapai -- amplop JSON saja sudah >100 byte.
  2. Firmware ESP32-S3 tidak perlu pustaka parsing JSON (mis. ArduinoJson)
     yang memakai alokasi memori dinamis -- cukup struct C dengan
     `__attribute__((packed))` yang identik dengan layout ini.
"""

from __future__ import annotations

import struct

HEADER_FMT = "<IIhHHBB"
HEADER_LEN = struct.calcsize(HEADER_FMT)
assert HEADER_LEN == 16, f"Header layout berubah ukuran ({HEADER_LEN} byte) -- perbarui dokumentasi & firmware C"
PAD_BYTE = 0xAA

FLAG_SYNTHETIC = 0x01


def pack_header(seq: int, ts_ms32: int, temp_centi: int, hum_centi: int,
                 pres_deca: int, flags: int) -> bytes:
    return struct.pack(
        HEADER_FMT,
        seq & 0xFFFFFFFF, ts_ms32 & 0xFFFFFFFF,
        max(-32768, min(32767, temp_centi)),
        max(0, min(65535, hum_centi)),
        max(0, min(65535, pres_deca)),
        flags & 0xFF, 0,
    )


def unpack_header(plaintext: bytes) -> dict:
    """Raise struct.error bila plaintext lebih pendek dari HEADER_LEN."""
    seq, ts_ms32, temp_centi, hum_centi, pres_deca, flags, _reserved = struct.unpack_from(
        HEADER_FMT, plaintext, 0
    )
    return {
        "seq": seq,
        "ts_ms32": ts_ms32,
        "temp_c": temp_centi / 100.0,
        "hum_pct": hum_centi / 100.0,
        "pres_hpa": pres_deca / 10.0,
        "synthetic": bool(flags & FLAG_SYNTHETIC),
    }
