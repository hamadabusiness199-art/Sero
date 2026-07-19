"""
Reference Python implementation of the "ENCv1" hybrid RSA-OAEP-SHA256 +
AES-256-GCM container format used by the Sero Flutter app's native
(Kotlin/Swift) crypto engine.

Container layout (all integers big-endian):

    [0:5)     b"ENCv1"                       5 bytes  - magic/version
    [5:9)     encrypted_key_len (uint32)     4 bytes
    [9:9+N)   RSA-OAEP-SHA256(AES-256 key)   N bytes
    [..+12)   AES-GCM IV                     12 bytes
    [..EOF)   AES-256-GCM ciphertext || 16-byte GCM tag

Requires: pip install cryptography

This file is intended purely as an interop reference/test harness so you
can confirm files produced by the Flutter app decrypt correctly in Python
and vice versa - it is not meant to be a polished CLI.
"""
from __future__ import annotations

import os
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"ENCv1"
IV_LEN = 12
TAG_LEN = 16
AES_KEY_LEN = 32
CHUNK_SIZE = 8 * 1024 * 1024  # 8 MB - matches the native STREAM_BUFFER_SIZE

_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def generate_rsa_keypair(key_size: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def export_public_key_der(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def export_private_key_der(private_key) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_public_key_der(der: bytes):
    return serialization.load_der_public_key(der)


def load_private_key_der(der: bytes):
    return serialization.load_der_private_key(der, password=None)


def encrypt_file(input_path: str, output_path: str, public_key) -> None:
    aes_key = os.urandom(AES_KEY_LEN)
    iv = os.urandom(IV_LEN)
    encrypted_key = public_key.encrypt(aes_key, _OAEP)
    aesgcm = AESGCM(aes_key)

    with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
        fout.write(MAGIC)
        fout.write(struct.pack(">I", len(encrypted_key)))
        fout.write(encrypted_key)
        fout.write(iv)

        # AESGCM in the `cryptography` package is one-shot only, so for a
        # true constant-memory streaming Python reference you would use the
        # lower-level `CipherContext` (Cipher(algorithms.AES(...), modes.GCM(...)))
        # and call update() per chunk / finalize() once, exactly mirroring the
        # native Kotlin/Swift implementations. Shown below for completeness.
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv)).encryptor()
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            fout.write(encryptor.update(chunk))
        fout.write(encryptor.finalize())
        fout.write(encryptor.tag)  # 16-byte GCM tag, written last


def decrypt_file(input_path: str, output_path: str, private_key) -> None:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    with open(input_path, "rb") as fin:
        magic = fin.read(len(MAGIC))
        if magic != MAGIC:
            raise ValueError(f"Unrecognized header; expected {MAGIC!r}")
        (key_len,) = struct.unpack(">I", fin.read(4))
        encrypted_key = fin.read(key_len)
        iv = fin.read(IV_LEN)

        aes_key = private_key.decrypt(encrypted_key, _OAEP)

        total_size = os.fstat(fin.fileno()).st_size
        header_size = len(MAGIC) + 4 + key_len + IV_LEN
        ciphertext_size = total_size - header_size - TAG_LEN
        if ciphertext_size < 0:
            raise ValueError("File is smaller than the declared header")

        decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv)).decryptor()
        # NOTE: python-cryptography's GCM decryptor needs the tag set before
        # finalize(); since the tag trails the ciphertext in this format, we
        # read the ciphertext into `decryptor.update()` and only supply the
        # tag at construction OR verify manually. The cleanest approach with
        # this library is to read the tag first (seek to the end), then
        # stream-decrypt from the current position:
        fin.seek(header_size + ciphertext_size)
        tag = fin.read(TAG_LEN)
        fin.seek(header_size)

        decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag)).decryptor()
        remaining = ciphertext_size
        with open(output_path, "wb") as fout:
            while remaining > 0:
                chunk = fin.read(min(CHUNK_SIZE, remaining))
                if not chunk:
                    raise ValueError("Unexpected end of stream while reading ciphertext")
                remaining -= len(chunk)
                fout.write(decryptor.update(chunk))
            fout.write(decryptor.finalize())  # raises InvalidTag on auth failure


if __name__ == "__main__":
    # Minimal smoke test: round-trip a temp file through this module.
    import tempfile

    priv = generate_rsa_keypair()
    pub = priv.public_key()

    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "plain.bin")
        enc = os.path.join(tmp, "cipher.encv1")
        dec = os.path.join(tmp, "restored.bin")
        with open(src, "wb") as f:
            f.write(os.urandom(5 * 1024 * 1024 + 37))  # not a multiple of the chunk size

        encrypt_file(src, enc, pub)
        decrypt_file(enc, dec, priv)

        with open(src, "rb") as a, open(dec, "rb") as b:
            assert a.read() == b.read(), "Round-trip mismatch!"
        print("OK: round-trip matches. Container size:", os.path.getsize(enc))
