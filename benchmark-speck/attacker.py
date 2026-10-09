"""
attacker.py
===========
Menghasilkan varian pesan tampered (termanipulasi) untuk menguji mekanisme
autentikasi/tag pada skenario S4 (pengujian normal vs tampered), sesuai
Tabel 1 dokumen rancangan.

Lingkup pengujian (lihat batasan penelitian, bagian 8 dokumen rancangan):
modul ini HANYA menghasilkan variasi pesan untuk menguji apakah mekanisme
autentikasi (HMAC tag) mendeteksi manipulasi data-in-transit. Modul ini
BUKAN kriptanalisis terhadap algoritma SPECK itu sendiri (mis. tidak
mencoba memecahkan kunci, tidak menganalisis kelemahan struktural cipher).

Semua fungsi di sini beroperasi pada representasi pesan level-wire (dict
hasil `crypto_utils.encrypt_payload` yang sudah di-serialize seperti pada
`device_sim.py`), BUKAN pada plaintext -- ini mensimulasikan penyerang yang
mengintersep/memodifikasi data di jalur komunikasi tanpa mengetahui kunci
rahasia, skenario ancaman yang realistis untuk transmisi sensor IoT.
"""

from __future__ import annotations

import base64
import copy
import os
import random
from typing import Callable

TamperStrategy = Callable[[dict], dict]


def _flip_bit_in_b64(b64_str: str) -> str:
    raw = bytearray(base64.b64decode(b64_str))
    if not raw:
        return b64_str
    idx = random.randrange(len(raw))
    bit = 1 << random.randrange(8)
    raw[idx] ^= bit
    return base64.b64encode(bytes(raw)).decode("ascii")


def tamper_flip_ciphertext_bit(msg: dict) -> dict:
    """Membalik satu bit acak pada ciphertext. Karena SPECK-CTR adalah
    stream cipher, ini akan mengubah SATU bit plaintext hasil dekripsi jika
    tag tidak diverifikasi -- tapi karena HMAC dihitung atas ciphertext,
    perubahan ini HARUS terdeteksi sebagai tag mismatch."""
    out = copy.deepcopy(msg)
    out["ct"] = _flip_bit_in_b64(out["ct"])
    out["condition"] = "tampered"
    out["tamper_strategy"] = "flip_ciphertext_bit"
    return out


def tamper_flip_tag_bit(msg: dict) -> dict:
    """Membalik satu bit acak pada tag HMAC itu sendiri (mensimulasikan
    korupsi/spoofing tag)."""
    out = copy.deepcopy(msg)
    out["tag"] = _flip_bit_in_b64(out["tag"])
    out["condition"] = "tampered"
    out["tamper_strategy"] = "flip_tag_bit"
    return out


def tamper_truncate_ciphertext(msg: dict) -> dict:
    """Memotong beberapa byte terakhir ciphertext (mensimulasikan pesan
    terpotong akibat gangguan transmisi yang secara tidak sengaja bisa juga
    dieksploitasi sebagai manipulasi)."""
    out = copy.deepcopy(msg)
    raw = base64.b64decode(out["ct"])
    cut = max(1, len(raw) // 8)
    out["ct"] = base64.b64encode(raw[:-cut]).decode("ascii")
    out["condition"] = "tampered"
    out["tamper_strategy"] = "truncate_ciphertext"
    return out


def tamper_replay_old_nonce(msg: dict, old_nonce_hex: str) -> dict:
    """Mengganti nonce pesan dengan nonce pesan lain yang pernah terekam
    (replay-style nonce reuse) tanpa memperbarui ciphertext/tag yang sesuai
    -- HMAC dihitung atas (nonce || ciphertext), sehingga nonce yang tidak
    konsisten dengan tag aslinya akan terdeteksi sebagai tag mismatch."""
    out = copy.deepcopy(msg)
    out["nonce"] = old_nonce_hex
    out["condition"] = "tampered"
    out["tamper_strategy"] = "replay_old_nonce"
    return out


STRATEGIES: dict[str, TamperStrategy] = {
    "flip_ciphertext_bit": tamper_flip_ciphertext_bit,
    "flip_tag_bit": tamper_flip_tag_bit,
    "truncate_ciphertext": tamper_truncate_ciphertext,
    # "replay_old_nonce" butuh argumen tambahan, dipanggil terpisah oleh device_sim.py
}


def random_tamper(msg: dict, rng: random.Random | None = None) -> dict:
    """Pilih satu strategi tamper secara acak dan terapkan. Dipakai
    device_sim.py pada skenario S4 untuk kondisi 'tampered'."""
    rng = rng or random
    strategy_name = rng.choice(list(STRATEGIES.keys()))
    return STRATEGIES[strategy_name](msg)
