"""
Tests for handshake protocol — Chunk 8.
"""

import pytest
from src.crypto.handshake import (
    alice_client_hello,
    bob_server_hello,
    alice_finish,
    bob_finish,
    derive_session_key,
    perform_handshake,
)


class TestDeriveSessionKey:
    def test_returns_32_bytes(self):
        key = derive_session_key(b"\x00" * 32)
        assert isinstance(key, bytes) and len(key) == 32

    def test_deterministic(self):
        secret = b"\xab" * 32
        assert derive_session_key(secret) == derive_session_key(secret)

    def test_different_secrets_produce_different_keys(self):
        assert derive_session_key(b"\x01" * 32) != derive_session_key(b"\x02" * 32)


class TestFullHandshake:
    def _run(self, symmetric_algo="aes_gcm"):
        a_state, hello = alice_client_hello(
            kem_algo="ecdh", sig_algo="ecdsa", symmetric_algo=symmetric_algo
        )
        b_state, server_hello = bob_server_hello(hello)
        a_key, a_sig_pub, a_sig_priv, b_sig_pub, finish = alice_finish(a_state, server_hello)
        b_alice_sig_pub = bob_finish(b_state, finish)
        return a_key, b_state.session_key, a_sig_pub, b_alice_sig_pub, b_sig_pub

    def test_both_sides_derive_same_session_key(self):
        a_key, b_key, _, _, _ = self._run()
        assert a_key == b_key
        assert len(a_key) == 32

    def test_session_key_chacha20(self):
        a_key, b_key, _, _, _ = self._run(symmetric_algo="chacha20")
        assert a_key == b_key

    def test_bob_receives_alice_signing_key(self):
        _, _, a_sig_pub, b_received_a_sig_pub, _ = self._run()
        assert a_sig_pub == b_received_a_sig_pub

    def test_alice_receives_bob_signing_key(self):
        _, _, _, _, b_sig_pub = self._run()
        assert isinstance(b_sig_pub, bytes) and len(b_sig_pub) == 91

    def test_different_runs_produce_different_session_keys(self):
        a_key1, _, _, _, _ = self._run()
        a_key2, _, _, _, _ = self._run()
        assert a_key1 != a_key2


class TestClientHello:
    def test_message_structure(self):
        _, msg = alice_client_hello(kem_algo="ecdh", sig_algo="ecdsa", symmetric_algo="aes_gcm")
        assert msg["v"] == 1
        assert msg["phase"] == "client_hello"
        assert "alice_kem_pub" in msg

    def test_unsupported_kem_raises(self):
        with pytest.raises(ValueError):
            alice_client_hello(kem_algo="rsa", sig_algo="ecdsa", symmetric_algo="aes_gcm")

    def test_unsupported_symmetric_raises(self):
        with pytest.raises(ValueError):
            alice_client_hello(kem_algo="ecdh", sig_algo="ecdsa", symmetric_algo="des")


class TestServerHello:
    def test_message_structure(self):
        _, hello = alice_client_hello(kem_algo="ecdh", sig_algo="ecdsa", symmetric_algo="aes_gcm")
        _, sh = bob_server_hello(hello)
        assert sh["phase"] == "server_hello"
        assert "bob_kem_pub" in sh and "bob_sig_pub" in sh and "signature" in sh

    def test_tampered_client_hello_raises(self):
        with pytest.raises((ValueError, KeyError)):
            bob_server_hello({"v": 1, "phase": "client_hello", "kem": "ecdh",
                              "sig": "ecdsa", "symmetric": "aes_gcm", "alice_kem_pub": "bad=="})

    def test_wrong_phase_raises(self):
        with pytest.raises(ValueError):
            bob_server_hello({"v": 1, "phase": "finish"})


class TestAliceFinish:
    def test_tampered_server_hello_signature_raises(self):
        a_state, hello = alice_client_hello(kem_algo="ecdh", sig_algo="ecdsa", symmetric_algo="aes_gcm")
        _, sh = bob_server_hello(hello)
        sh["signature"] = sh["signature"][:-4] + "AAAA"
        with pytest.raises(ValueError, match="signature"):
            alice_finish(a_state, sh)

    def test_symmetric_mismatch_raises(self):
        a_state, hello = alice_client_hello(kem_algo="ecdh", sig_algo="ecdsa", symmetric_algo="aes_gcm")
        _, sh = bob_server_hello(hello)
        sh["symmetric"] = "chacha20"
        with pytest.raises(ValueError):
            alice_finish(a_state, sh)


class TestPerformHandshake:
    def test_initiator_and_responder_share_key(self):
        a_key, _ = perform_handshake("ecdh", "ecdsa", initiator_side=True)
        b_key, _ = perform_handshake("ecdh", "ecdsa", initiator_side=False)
        assert len(a_key) == 32 and len(b_key) == 32
