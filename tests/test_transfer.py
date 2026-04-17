"""
Tests for secure transfer — Chunk 9.
"""

import copy
import os
import pytest
from src.crypto import signatures_classical
from src.crypto.transfer import send_message, receive_message


def _make_session():
    session_key = os.urandom(32)
    sig_pub, sig_priv = signatures_classical.generate_keypair()
    return session_key, sig_pub, sig_priv


class TestSendReceiveAESGCM:
    def test_roundtrip_bytes(self):
        key, pub, priv = _make_session()
        payload = send_message(key, priv, b"hello world", "aes_gcm")
        assert receive_message(key, pub, payload) == b"hello world"

    def test_roundtrip_string(self):
        key, pub, priv = _make_session()
        payload = send_message(key, priv, "text message", "aes_gcm")
        assert receive_message(key, pub, payload) == b"text message"

    def test_payload_has_expected_fields(self):
        key, _, priv = _make_session()
        p = send_message(key, priv, b"x", "aes_gcm")
        for field in ("v", "symmetric", "nonce", "ciphertext", "tag", "signature"):
            assert field in p

    def test_tampered_ciphertext_raises(self):
        key, pub, priv = _make_session()
        p = send_message(key, priv, b"data", "aes_gcm")
        p2 = copy.deepcopy(p)
        p2["ciphertext"] = p2["ciphertext"][:-4] + "AAAA"
        with pytest.raises((ValueError, Exception)):
            receive_message(key, pub, p2)

    def test_tampered_signature_raises(self):
        key, pub, priv = _make_session()
        p = send_message(key, priv, b"data", "aes_gcm")
        p["signature"] = p["signature"][:-4] + "AAAA"
        with pytest.raises(ValueError, match="[Ss]ignature"):
            receive_message(key, pub, p)

    def test_wrong_session_key_raises(self):
        key, pub, priv = _make_session()
        p = send_message(key, priv, b"data", "aes_gcm")
        with pytest.raises(Exception):
            receive_message(os.urandom(32), pub, p)

    def test_wrong_verify_key_raises(self):
        key, pub, priv = _make_session()
        p = send_message(key, priv, b"data", "aes_gcm")
        wrong_pub, _ = signatures_classical.generate_keypair()
        with pytest.raises((ValueError, Exception)):
            receive_message(key, wrong_pub, p)


class TestSendReceiveChaCha20:
    def test_roundtrip(self):
        key, pub, priv = _make_session()
        payload = send_message(key, priv, b"chacha payload", "chacha20")
        assert receive_message(key, pub, payload) == b"chacha payload"

    def test_payload_has_expected_fields(self):
        key, _, priv = _make_session()
        p = send_message(key, priv, b"x", "chacha20")
        for field in ("v", "symmetric", "nonce", "ciphertext", "signature"):
            assert field in p
        assert "tag" not in p  # tag is embedded in ciphertext for chacha20

    def test_tampered_ciphertext_raises(self):
        key, pub, priv = _make_session()
        p = send_message(key, priv, b"data", "chacha20")
        p2 = copy.deepcopy(p)
        p2["ciphertext"] = p2["ciphertext"][:-4] + "AAAA"
        with pytest.raises((ValueError, Exception)):
            receive_message(key, pub, p2)


class TestEdgeCases:
    def test_unsupported_algo_raises_on_send(self):
        key, _, priv = _make_session()
        with pytest.raises(ValueError):
            send_message(key, priv, b"x", "des")

    def test_missing_signature_raises_on_receive(self):
        key, pub, priv = _make_session()
        p = send_message(key, priv, b"x", "aes_gcm")
        del p["signature"]
        with pytest.raises(ValueError, match="[Ss]ignature"):
            receive_message(key, pub, p)

    def test_wrong_version_raises_on_receive(self):
        key, pub, priv = _make_session()
        p = send_message(key, priv, b"x", "aes_gcm")
        p["v"] = 99
        with pytest.raises(ValueError):
            receive_message(key, pub, p)

    def test_empty_message(self):
        key, pub, priv = _make_session()
        payload = send_message(key, priv, b"", "aes_gcm")
        assert receive_message(key, pub, payload) == b""
