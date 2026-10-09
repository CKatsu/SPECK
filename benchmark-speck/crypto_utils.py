"""
crypto_utils.py
================
Wrapper untuk algoritma cipher blok ringan SPECK beserta pengelolaan kunci
dan mode operasi, sesuai Tabel 1 modul "crypto_utils.py" pada dokumen
"Rancangan Simulasi Benchmarking Algoritma Kriptografi SPECK dengan Beban
Kerja pada Perangkat IoT".

Spesifikasi algoritma
----------------------
Varian     : SPECK64/128  (block size = 64 bit, key size = 128 bit)
Sumber     : Beaulieu, R., Shors, D., Smith, J., Treatman-Clark, S.,
             Weeks, B., & Wingers, L. (2015). "The SIMON and SPECK Families
             of Lightweight Block Ciphers". IACR ePrint 2013/404 (revised
             2015 version), Appendix C (Test Vectors).
Word size  : n = 32 bit  -> alpha = 8, beta = 3
Rounds     : T = 27 (untuk key size 128 bit pada block size 64 bit)
Key words  : m = 4 (128 bit / 32 bit)

PENTING (academic integrity):
Implementasi ini divalidasi terhadap Known Answer Test (KAT) resmi dari
paper di atas sebelum dipakai untuk benchmarking apa pun. Lihat
tests/test_speck_kat.py dan fungsi `_self_test()` di bawah. Jika KAT
gagal, modul ini akan raise AssertionError saat import -- JANGAN
melanjutkan ke tahap benchmarking sebelum ini lulus.

Mode operasi & autentikasi
---------------------------
SPECK adalah block cipher murni tanpa autentikasi bawaan. Sesuai keputusan
desain penelitian ini:
  - Kerahasiaan (confidentiality): SPECK64/128 dalam mode CTR (counter
    mode). Dipilih karena tidak memerlukan padding (cocok untuk payload
    sensor yang panjangnya bervariasi/bertingkat pada skenario S2) dan
    dapat dijalankan sebagai stream cipher dengan overhead minimal di
    ESP32-S3.
  - Integritas/autentikasi (untuk skenario S4 - normal vs tampered):
    HMAC-SHA256 dihitung secara terpisah atas (nonce || ciphertext),
    dipotong (truncated) menjadi TAG_LEN byte. Konstruksi ini adalah
    encrypt-then-MAC, skema yang secara kriptografis terbukti aman
    (Bellare & Namprempre, 2000) selama HMAC dihitung atas ciphertext,
    bukan plaintext.

Dengan konstruksi ini, "kecepatan" (performa CTR) dan "keamanan"
(autentikasi HMAC) diukur dan dilaporkan sebagai DUA metrik yang berbeda
dan TIDAK saling menggantikan satu sama lain -- konsisten dengan prinsip
bahwa algoritma yang lebih cepat tidak otomatis lebih aman.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Parameter algoritma (JANGAN diubah tanpa mendokumentasikan alasannya --
# perubahan di sini mengubah hasil eksperimen dan harus dicatat sebagai
# modifikasi implementasi, bukan implementasi standar).
# ---------------------------------------------------------------------------
WORD_BITS = 32
WORD_MASK = (1 << WORD_BITS) - 1
ALPHA = 8
BETA = 3
ROUNDS = 27          # T untuk Speck64/128
KEY_WORDS = 4         # m = 128 / 32
BLOCK_BYTES = 8        # 64 bit
KEY_BYTES = 16        # 128 bit

TAG_LEN = 16           # byte HMAC-SHA256 truncated (128 bit, sesuai rekomendasi
                        # minimum panjang tag NIST SP 800-38B untuk keamanan
                        # praktis; bisa diperpendek dan didokumentasikan bila
                        # overhead perlu dikurangi lebih jauh)
NONCE_LEN = 8           # counter/nonce CTR, 64 bit, dikirim eksplisit (tidak
                        # rahasia) agar penerima dapat mensinkronkan counter


def _rotr(x: int, r: int) -> int:
    return ((x >> r) | (x << (WORD_BITS - r))) & WORD_MASK


def _rotl(x: int, r: int) -> int:
    return ((x << r) | (x >> (WORD_BITS - r))) & WORD_MASK


def _expand_key(key: bytes) -> list[int]:
    """Key schedule SPECK64/128 -> menghasilkan ROUNDS round key (32-bit)."""
    if len(key) != KEY_BYTES:
        raise ValueError(f"SPECK64/128 requires a {KEY_BYTES}-byte key, got {len(key)}")

    # Key words diambil little-endian per word, K0..K3, dengan K0 = word
    # paling tidak signifikan (little-endian word order), sesuai konvensi
    # implementasi referensi paper (byte 0..3 -> K0, dst).
    k = list(struct.unpack("<4I", key))  # K0, K1, K2, K3
    k0, l0, l1, l2 = k[0], k[1], k[2], k[3]

    round_keys = [k0]
    l = [l0, l1, l2]
    for i in range(ROUNDS - 1):
        new_l = (round_keys[i] + _rotr(l[i], ALPHA)) & WORD_MASK
        new_l ^= i
        l.append(new_l)
        new_k = _rotl(round_keys[i], BETA) ^ new_l
        round_keys.append(new_k)
    return round_keys[:ROUNDS]


def _encrypt_block(x: int, y: int, round_keys: list[int]) -> tuple[int, int]:
    for k in round_keys:
        x = (_rotr(x, ALPHA) + y) & WORD_MASK
        x ^= k
        y = _rotl(y, BETA) ^ x
    return x, y


def _decrypt_block(x: int, y: int, round_keys: list[int]) -> tuple[int, int]:
    for k in reversed(round_keys):
        y = _rotr(y ^ x, BETA)
        x ^= k
        x = _rotl((x - y) & WORD_MASK, ALPHA)
    return x, y


def speck_encrypt_block(key: bytes, plaintext_block: bytes) -> bytes:
    """Enkripsi satu block 64-bit (8 byte) plaintext -> 8 byte ciphertext."""
    if len(plaintext_block) != BLOCK_BYTES:
        raise ValueError("plaintext block must be 8 bytes")
    round_keys = _expand_key(key)
    y, x = struct.unpack("<2I", plaintext_block)  # y = low word, x = high word
    x, y = _encrypt_block(x, y, round_keys)
    return struct.pack("<2I", y, x)


def speck_decrypt_block(key: bytes, ciphertext_block: bytes) -> bytes:
    if len(ciphertext_block) != BLOCK_BYTES:
        raise ValueError("ciphertext block must be 8 bytes")
    round_keys = _expand_key(key)
    y, x = struct.unpack("<2I", ciphertext_block)
    x, y = _decrypt_block(x, y, round_keys)
    return struct.pack("<2I", y, x)


# ---------------------------------------------------------------------------
# Mode CTR: keystream_i = E(key, nonce || counter_i), ciphertext = pt XOR ks
# Tidak butuh padding -> panjang ciphertext == panjang plaintext.
# ---------------------------------------------------------------------------

def _keystream(key: bytes, nonce: bytes, nblocks: int):
    """CTR keystream generator.

    `nonce` adalah nilai counter-awal 64-bit (BLOCK_BYTES byte, little-endian)
    yang dipilih acak per pesan. Setiap block ke-i dari pesan yang sama
    dienkripsi dari nilai (nonce_int + i) mod 2**64, sehingga seluruh 64 bit
    ruang counter tersedia (bukan dipecah nonce/counter terpisah) --
    meminimalkan risiko pengulangan (keystream reuse) walaupun nonce
    dibangkitkan acak untuk tiap pesan."""
    if len(nonce) != NONCE_LEN:
        raise ValueError(f"nonce must be {NONCE_LEN} bytes")
    round_keys = _expand_key(key)
    nonce_int = int.from_bytes(nonce, "little")
    mask64 = (1 << 64) - 1
    for counter in range(nblocks):
        block_val = (nonce_int + counter) & mask64
        ctr_block = block_val.to_bytes(BLOCK_BYTES, "little")
        y, x = struct.unpack("<2I", ctr_block)
        x, y = _encrypt_block(x, y, round_keys)
        yield struct.pack("<2I", y, x)


def speck_ctr_crypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """XOR data dengan keystream SPECK-CTR. Fungsi yang sama dipakai untuk
    enkripsi maupun dekripsi (properti stream cipher)."""
    nblocks = (len(data) + BLOCK_BYTES - 1) // BLOCK_BYTES
    ks = b"".join(_keystream(key, nonce, nblocks))[: len(data)]
    return bytes(a ^ b for a, b in zip(data, ks))


# ---------------------------------------------------------------------------
# Autentikasi: HMAC-SHA256 atas (nonce || ciphertext), truncated.
# ---------------------------------------------------------------------------

def compute_tag(mac_key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    full = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    return full[:TAG_LEN]


def verify_tag(mac_key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bool:
    expected = compute_tag(mac_key, nonce, ciphertext)
    return hmac.compare_digest(expected, tag)


# ---------------------------------------------------------------------------
# High-level API dipakai oleh device_sim.py / server.py / attacker.py
# ---------------------------------------------------------------------------

@dataclass
class KeyMaterial:
    """Kunci enkripsi (SPECK) dan kunci MAC (HMAC) dipisah (key separation
    principle) walaupun pada implementasi ini keduanya diturunkan dari satu
    master key via config, agar tiap fungsi kriptografis punya kunci
    sendiri-sendiri."""
    enc_key: bytes   # 16 byte, dipakai SPECK64/128
    mac_key: bytes    # 32 byte, dipakai HMAC-SHA256

    @staticmethod
    def from_master(master_key: bytes) -> "KeyMaterial":
        if len(master_key) != 32:
            raise ValueError("master key must be 32 bytes (256 bit)")
        enc_key = hashlib.sha256(master_key + b"SPECK-ENC").digest()[:KEY_BYTES]
        mac_key = hashlib.sha256(master_key + b"SPECK-MAC").digest()
        return KeyMaterial(enc_key=enc_key, mac_key=mac_key)


def encrypt_payload(km: KeyMaterial, plaintext: bytes, nonce: bytes | None = None):
    """Enkripsi + tag. Return (nonce, ciphertext, tag)."""
    nonce = nonce if nonce is not None else os.urandom(NONCE_LEN)
    ciphertext = speck_ctr_crypt(km.enc_key, nonce, plaintext)
    tag = compute_tag(km.mac_key, nonce, ciphertext)
    return nonce, ciphertext, tag


def decrypt_payload(km: KeyMaterial, nonce: bytes, ciphertext: bytes, tag: bytes):
    """Verifikasi tag lalu dekripsi. Raise ValueError bila tag tidak valid
    (pesan tampered) -- pemanggil (server.py) menangani ini sebagai
    penolakan pesan pada skenario S4."""
    if not verify_tag(km.mac_key, nonce, ciphertext, tag):
        raise ValueError("HMAC tag verification failed (message rejected: tampered or corrupted)")
    return speck_ctr_crypt(km.enc_key, nonce, ciphertext)


# ---------------------------------------------------------------------------
# Known Answer Test (KAT) resmi -- SPECK64/128, Beaulieu et al. 2015 App. C
# ---------------------------------------------------------------------------

def _self_test() -> None:
    # Key words (word0..word3, little-endian dalam tiap word) sesuai paper:
    # K0=0x03020100, K1=0x0b0a0908, K2=0x13121110, K3=0x1b1a1918
    key = struct.pack("<4I", 0x03020100, 0x0B0A0908, 0x13121110, 0x1B1A1918)
    # Plaintext words: x0=0x3b726574, y0=0x7475432d
    pt = struct.pack("<2I", 0x7475432D, 0x3B726574)  # (y, x) urutan sesuai encode
    expected_ct = struct.pack("<2I", 0x454E028B, 0x8C6FA548)  # (y, x)

    ct = speck_encrypt_block(key, pt)
    assert ct == expected_ct, (
        "SPECK64/128 KAT FAILED (encrypt): implementasi tidak sesuai "
        "test vector resmi Beaulieu et al. (2015) Appendix C. "
        f"got={ct.hex()} expected={expected_ct.hex()}"
    )
    pt_back = speck_decrypt_block(key, ct)
    assert pt_back == pt, "SPECK64/128 KAT FAILED (decrypt): round-trip mismatch"

    # Sanity check mode CTR + HMAC round trip (bukan bagian dari KAT resmi,
    # tapi wajib lulus sebelum dipakai untuk streaming).
    km = KeyMaterial.from_master(b"\x00" * 32)
    msg = b"hello iot sensor payload 1234567890"
    nonce, ct2, tag = encrypt_payload(km, msg)
    pt2 = decrypt_payload(km, nonce, ct2, tag)
    assert pt2 == msg, "CTR+HMAC round-trip sanity check failed"

    # Tampered message harus terdeteksi (dipakai attacker.py / skenario S4)
    tampered = bytearray(ct2)
    tampered[0] ^= 0x01
    try:
        decrypt_payload(km, nonce, bytes(tampered), tag)
        raise AssertionError("Tampered ciphertext was NOT detected -- security bug!")
    except ValueError:
        pass  # expected: tag verification must fail


_self_test()

if __name__ == "__main__":
    print("SPECK64/128 KAT self-test: PASSED")
    print(f"Rounds={ROUNDS} WordBits={WORD_BITS} Alpha={ALPHA} Beta={BETA}")
    print(f"Block={BLOCK_BYTES*8}-bit Key={KEY_BYTES*8}-bit TagLen={TAG_LEN*8}-bit")
