"""
Tests for signature modules — Chunk 7 (ECDSA) and Chunk 6 (ML-DSA).
"""

import pytest
import src.crypto.signatures_classical as cl
import src.crypto.signatures_pq as pq


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


class TestMLDSA:
    """
    Tests for Module-Lattice-Based Digital Signature Algorithm (ML-DSA).
    Note: Sizes below correspond to ML-DSA-65 (Dilithium3).
    """

    def test_keypair_types_and_sizes(self):
        pub, priv = pq.generate_keypair()

        # ML-DSA-65 Sizes:
        # Public Key: 1952 bytes
        # Private Key: 4032 bytes
        assert isinstance(pub, bytes)
        assert len(pub) == 1952
        assert isinstance(priv, bytes)
        assert len(priv) == 4032

    def test_sign_returns_bytes(self):
        _, priv = pq.generate_keypair()
        sig = pq.sign(priv, b"test message")

        # ML-DSA-65 Signature size is fixed: 3309 bytes
        assert isinstance(sig, bytes)
        assert len(sig) == 3309

    def test_verify_valid_signature(self):
        pub, priv = pq.generate_keypair()
        msg = b"Post-Quantum Security"
        sig = pq.sign(priv, msg)
        assert pq.verify(pub, msg, sig) is True

    def test_verify_tampered_message(self):
        pub, priv = pq.generate_keypair()
        msg = b"Original Message"
        sig = pq.sign(priv, msg)
        # Attempt to verify with a different message
        assert pq.verify(pub, b"Tampered Message", sig) is False

    def test_verify_tampered_signature(self):
        pub, priv = pq.generate_keypair()
        msg = b"Data integrity test"
        sig = list(pq.sign(priv, msg))

        # Flip a bit in the signature
        sig[0] ^= 0xFF
        tampered_sig = bytes(sig)

        assert pq.verify(pub, msg, tampered_sig) is False

    def test_verify_wrong_public_key(self):
        pub1, priv1 = pq.generate_keypair()
        pub2, _ = pq.generate_keypair()
        msg = b"Verification consistency"
        sig = pq.sign(priv1, msg)

        # Signature from priv1 should not verify with pub2
        assert pq.verify(pub2, msg, sig) is False

    def test_determinism_or_randomization(self):
        """
        ML-DSA can be deterministic or use external entropy.
        If your implementation uses a deterministic nonce,
        signing the same message twice should yield the same signature.
        """
        pub, priv = pq.generate_keypair()
        msg = b"Deterministic check"
        sig1 = pq.sign(priv, msg)
        sig2 = pq.sign(priv, msg)

        # Standard ML-DSA (FIPS 204) recommends deterministic signing by default
        assert sig1 == sig2


class TestSignatureParity:
    """
    Ensures that both Classical (ECDSA) and PQ (ML-DSA) modules
    follow the exact same API contract.
    """

    @pytest.mark.parametrize("mod", [cl, pq], ids=["Classical", "Post-Quantum"])
    def test_consistent_interface(self, mod):
        # 1. Check for implementation
        try:
            # 2. Key Generation
            pub, priv = mod.generate_keypair()
        except NotImplementedError:
            pytest.skip(f"{mod.__name__} not yet implemented")

        # 3. Signing
        msg = b"Parity test message"
        sig = mod.sign(priv, msg)

        # 4. Type consistency
        assert isinstance(pub, bytes), f"{mod.__name__} public key must be bytes"
        assert isinstance(priv, bytes), f"{mod.__name__} private key must be bytes"
        assert isinstance(sig, bytes), f"{mod.__name__} signature must be bytes"

        # 5. Verification logic
        assert mod.verify(pub, msg, sig) is True, f"{mod.__name__} failed self-verification"

        # 6. Failure consistency (Tampering)
        assert mod.verify(pub, b"wrong message", sig) is False
