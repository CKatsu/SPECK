"""
tests/test_speck_kat.py
========================
Known Answer Test (KAT) formal untuk crypto_utils.py, dijalankan lewat
pytest (atau langsung: `python tests/test_speck_kat.py`).

Referensi test vector: Beaulieu, R., Shors, D., Smith, J., Treatman-Clark,
S., Weeks, B., & Wingers, L. (2015). "The SIMON and SPECK Families of
Lightweight Block Ciphers". Appendix C.

Catatan: import crypto_utils SAJA sudah menjalankan `_self_test()` (lihat
akhir file crypto_utils.py) yang meng-assert KAT ini -- modul ini
membungkusnya sebagai test case eksplisit yang bisa dilaporkan terpisah
oleh test runner, dan menambahkan beberapa pemeriksaan tambahan pada mode
CTR dan mekanisme tag.
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import crypto_utils  # noqa: E402


def test_speck64_128_official_kat():
    key = struct.pack("<4I", 0x03020100, 0x0B0A0908, 0x13121110, 0x1B1A1918)
    pt = struct.pack("<2I", 0x7475432D, 0x3B726574)
    expected_ct = struct.pack("<2I", 0x454E028B, 0x8C6FA548)

    ct = crypto_utils.speck_encrypt_block(key, pt)
    assert ct == expected_ct

    pt_roundtrip = crypto_utils.speck_decrypt_block(key, ct)
    assert pt_roundtrip == pt


def test_ctr_mode_roundtrip_various_lengths():
    km = crypto_utils.KeyMaterial.from_master(b"\x01" * 32)
    for length in [1, 7, 8, 9, 63, 64, 255, 256, 1023, 1024]:
        msg = os.urandom(length)
        nonce, ct, tag = crypto_utils.encrypt_payload(km, msg)
        assert len(ct) == length, "SPECK-CTR harus stream cipher (ciphertext length == plaintext length)"
        pt = crypto_utils.decrypt_payload(km, nonce, ct, tag)
        assert pt == msg


def test_tampered_ciphertext_is_rejected():
    km = crypto_utils.KeyMaterial.from_master(b"\x02" * 32)
    msg = b"suhu=27.5C;kelembapan=61%"
    nonce, ct, tag = crypto_utils.encrypt_payload(km, msg)
    bad_ct = bytearray(ct)
    bad_ct[0] ^= 0x80
    try:
        crypto_utils.decrypt_payload(km, nonce, bytes(bad_ct), tag)
        assert False, "Ciphertext yang dimanipulasi seharusnya ditolak (ValueError)"
    except ValueError:
        pass


def test_tampered_tag_is_rejected():
    km = crypto_utils.KeyMaterial.from_master(b"\x03" * 32)
    msg = b"payload uji"
    nonce, ct, tag = crypto_utils.encrypt_payload(km, msg)
    bad_tag = bytearray(tag)
    bad_tag[0] ^= 0x01
    try:
        crypto_utils.decrypt_payload(km, nonce, ct, bytes(bad_tag))
        assert False, "Tag yang dimanipulasi seharusnya ditolak (ValueError)"
    except ValueError:
        pass


if __name__ == "__main__":
    test_speck64_128_official_kat()
    test_ctr_mode_roundtrip_various_lengths()
    test_tampered_ciphertext_is_rejected()
    test_tampered_tag_is_rejected()
    print("ALL KAT / CTR / tamper-detection tests PASSED")
