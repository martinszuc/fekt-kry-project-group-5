"""
Tests for symmetric encryption — Chunks 4 (AES-256-GCM) and 5 (ChaCha20-Poly1305).
"""

import os
import pytest
from src.crypto.symmetric import (
    encrypt_aes_gcm, decrypt_aes_gcm,
    encrypt_chacha20, decrypt_chacha20,
)


class TestAESGCM:
    def test_encrypt_returns_correct_types_and_sizes(self):
        key = os.urandom(32)
        ct, nonce, tag = encrypt_aes_gcm(key, b"hello")
        assert isinstance(ct, bytes) and isinstance(nonce, bytes) and isinstance(tag, bytes)
        assert len(nonce) == 12
        assert len(tag) == 16
        assert len(ct) == 5  # same length as plaintext

    def test_decrypt_recovers_plaintext(self):
        key = os.urandom(32)
        plaintext = b"secret message"
        ct, nonce, tag = encrypt_aes_gcm(key, plaintext)
        assert decrypt_aes_gcm(key, ct, nonce, tag) == plaintext

    def test_tampered_ciphertext_raises(self):
        key = os.urandom(32)
        ct, nonce, tag = encrypt_aes_gcm(key, b"data")
        bad_ct = bytes([ct[0] ^ 0xFF]) + ct[1:]
        with pytest.raises(Exception):
            decrypt_aes_gcm(key, bad_ct, nonce, tag)

    def test_tampered_tag_raises(self):
        key = os.urandom(32)
        ct, nonce, tag = encrypt_aes_gcm(key, b"data")
        bad_tag = bytes([tag[0] ^ 0xFF]) + tag[1:]
        with pytest.raises(Exception):
            decrypt_aes_gcm(key, ct, nonce, bad_tag)

    def test_wrong_key_raises(self):
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        ct, nonce, tag = encrypt_aes_gcm(key1, b"data")
        with pytest.raises(Exception):
            decrypt_aes_gcm(key2, ct, nonce, tag)

    def test_short_key_raises_value_error(self):
        with pytest.raises(ValueError):
            encrypt_aes_gcm(b"short", b"data")
        with pytest.raises(ValueError):
            decrypt_aes_gcm(b"short", b"ct", b"nonce", b"tag")

    def test_fresh_nonce_each_call(self):
        key = os.urandom(32)
        _, n1, _ = encrypt_aes_gcm(key, b"same")
        _, n2, _ = encrypt_aes_gcm(key, b"same")
        assert n1 != n2


class TestChaCha20:
    def test_encrypt_returns_ciphertext_and_nonce(self):
        key = os.urandom(32)
        ct, nonce = encrypt_chacha20(key, b"hello")
        assert isinstance(ct, bytes) and isinstance(nonce, bytes)
        assert len(nonce) == 12
        assert len(ct) == 5 + 16  # plaintext + 16-byte Poly1305 tag

    def test_decrypt_recovers_plaintext(self):
        key = os.urandom(32)
        msg = b"chacha test message"
        ct, nonce = encrypt_chacha20(key, msg)
        assert decrypt_chacha20(key, ct, nonce) == msg

    def test_tampered_ciphertext_raises(self):
        key = os.urandom(32)
        ct, nonce = encrypt_chacha20(key, b"data")
        bad_ct = bytes([ct[0] ^ 0xFF]) + ct[1:]
        with pytest.raises(Exception):
            decrypt_chacha20(key, bad_ct, nonce)

    def test_wrong_key_raises(self):
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        ct, nonce = encrypt_chacha20(key1, b"data")
        with pytest.raises(Exception):
            decrypt_chacha20(key2, ct, nonce)

    def test_fresh_nonce_each_call(self):
        key = os.urandom(32)
        _, n1 = encrypt_chacha20(key, b"x")
        _, n2 = encrypt_chacha20(key, b"x")
        assert n1 != n2

    def test_short_key_raises_value_error(self):
        with pytest.raises(ValueError):
            encrypt_chacha20(b"short", b"data")
        with pytest.raises(ValueError):
            decrypt_chacha20(b"short", b"ct", b"nonce")
