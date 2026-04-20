"""
Tests for secure transfer — Chunk 9.
"""

import copy
import os
import pytest
from src.crypto import signatures_classical
from src.crypto import signatures_pq
from src.crypto.transfer import send_message, receive_message
import base64

def _make_session(use_pq=False):
    """
    Helper to create a session with either Classical or PQ keys.
    """
    session_key = os.urandom(32)
    sig_mod = signatures_pq if use_pq else signatures_classical
    sig_pub, sig_priv = sig_mod.generate_keypair()
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


class TestSendReceivePQ:
    """
    Ensures that send/receive logic works with ML-DSA (PQ) signatures.
    PQ signatures and keys are much larger, which tests the robustness
    of the serialization/payload handling.
    """

    def test_roundtrip_pq_aes(self):
        key, pub, priv = _make_session(use_pq=True)
        msg = b"Post-Quantum roundtrip test"
        payload = send_message(key, priv, msg, "aes_gcm")
        assert receive_message(key, pub, payload) == msg

    def test_roundtrip_pq_chacha(self):
        key, pub, priv = _make_session(use_pq=True)
        msg = b"Post-Quantum Chacha test"
        payload = send_message(key, priv, msg, "chacha20")
        assert receive_message(key, pub, payload) == msg

    def test_tampered_pq_signature_raises(self):
        key, pub, priv = _make_session(use_pq=True)
        p = send_message(key, priv, b"secure data", "aes_gcm")

        # 1. Get the B64 string and decode to bytes
        sig_bytes = bytearray(base64.b64decode(p["signature"]))

        # 2. Tamper with the raw bytes (e.g., flip the first byte)
        sig_bytes[0] = (sig_bytes[0] + 1) % 256

        # 3. Re-encode to B64 string and update payload
        p["signature"] = base64.b64encode(sig_bytes).decode("ascii")

        # 4. Verification should now fail
        with pytest.raises(ValueError, match="[Ss]ignature"):
            receive_message(key, pub, p)

    def test_wrong_pq_key_raises(self):
        key, _, priv = _make_session(use_pq=True)
        wrong_pub, _ = signatures_pq.generate_keypair()
        p = send_message(key, priv, b"data", "aes_gcm")

        with pytest.raises((ValueError, Exception)):
            receive_message(key, wrong_pub, p)