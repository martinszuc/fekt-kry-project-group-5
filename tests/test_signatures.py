"""
Tests for signature modules — Chunk 7 (ECDSA) and Chunk 6 (ML-DSA).
"""

import pytest
import src.crypto.signatures_classical as cl


class TestECDSA:
    def test_keypair_types_and_sizes(self):
        pub, priv = cl.generate_keypair()
        assert isinstance(pub, bytes) and len(pub) == 91  # SubjectPublicKeyInfo P-256
        assert isinstance(priv, bytes) and len(priv) > 0

    def test_sign_returns_bytes(self):
        _, priv = cl.generate_keypair()
        sig = cl.sign(priv, b"test")
        assert isinstance(sig, bytes) and len(sig) > 0

    def test_verify_valid_signature(self):
        pub, priv = cl.generate_keypair()
        msg = b"hello MPC-KRY"
        sig = cl.sign(priv, msg)
        assert cl.verify(pub, msg, sig) is True

    def test_verify_tampered_message(self):
        pub, priv = cl.generate_keypair()
        sig = cl.sign(priv, b"original")
        assert cl.verify(pub, b"tampered", sig) is False

    def test_verify_tampered_signature(self):
        pub, priv = cl.generate_keypair()
        msg = b"data"
        sig = cl.sign(priv, msg)
        bad_sig = bytes([sig[0] ^ 0xFF]) + sig[1:]
        assert cl.verify(pub, msg, bad_sig) is False

    def test_verify_wrong_public_key(self):
        pub1, priv1 = cl.generate_keypair()
        pub2, _ = cl.generate_keypair()
        sig = cl.sign(priv1, b"msg")
        assert cl.verify(pub2, b"msg", sig) is False

    def test_signature_size_in_der_range(self):
        _, priv = cl.generate_keypair()
        sig = cl.sign(priv, b"x")
        # DER-encoded ECDSA P-256 is 70-72 bytes depending on r,s values
        assert 68 <= len(sig) <= 73

    def test_interface_parity_with_signatures_pq(self):
        # both modules expose the same function signatures; skip if pq not yet implemented
        import src.crypto.signatures_pq as pq
        for mod in (pq, cl):
            try:
                pub, priv = mod.generate_keypair()
            except NotImplementedError:
                pytest.skip("signatures_pq not yet implemented (Chunk 6)")
            sig = mod.sign(priv, b"test")
            assert mod.verify(pub, b"test", sig) is True
