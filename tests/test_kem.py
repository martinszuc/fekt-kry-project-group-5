"""
Tests for KEM modules — Chunk 3 (ECDH) and Chunk 2 (ML-KEM).
"""

import pytest
from src.crypto import kem_classical as classical
from src.crypto import kem_pq as pq


class TestECDH:
    def test_keypair_types_and_lengths(self):
        pub, priv = classical.generate_keypair()
        assert isinstance(pub, bytes) and len(pub) > 0
        assert isinstance(priv, bytes) and len(priv) > 0

    def test_public_key_size(self):
        # SubjectPublicKeyInfo DER for P-256 is always 91 bytes
        pub, _ = classical.generate_keypair()
        assert len(pub) == 91

    def test_both_sides_derive_same_secret(self):
        pub_a, priv_a = classical.generate_keypair()
        pub_b, priv_b = classical.generate_keypair()
        ss_a = classical.derive_shared_secret(priv_a, pub_b)
        ss_b = classical.derive_shared_secret(priv_b, pub_a)
        assert ss_a == ss_b
        assert len(ss_a) == 32

    def test_different_pairs_produce_different_secrets(self):
        pub_a, priv_a = classical.generate_keypair()
        pub_b, _ = classical.generate_keypair()
        pub_c, _ = classical.generate_keypair()
        ss1 = classical.derive_shared_secret(priv_a, pub_b)
        ss2 = classical.derive_shared_secret(priv_a, pub_c)
        assert ss1 != ss2

    def test_wrong_private_key_gives_different_secret(self):
        pub_a, priv_a = classical.generate_keypair()
        pub_b, _ = classical.generate_keypair()
        _, priv_x = classical.generate_keypair()
        ss_correct = classical.derive_shared_secret(priv_a, pub_b)
        ss_wrong = classical.derive_shared_secret(priv_x, pub_b)
        assert ss_correct != ss_wrong

    def test_invalid_key_bytes_raise_value_error(self):
        pub, _ = classical.generate_keypair()
        with pytest.raises((ValueError, Exception)):
            classical.derive_shared_secret(b"not-a-key", pub)


class TestMLKEM768:
    def test_keypair_types_and_lengths(self):
        pub, priv = pq.generate_keypair()
        assert isinstance(pub, bytes)
        assert isinstance(priv, bytes)
        # ML-KEM-768 standard sizes
        assert len(pub) == 1184
        assert len(priv) == 2400

    def test_encapsulate_decapsulate_flow(self):
        """
        Tests the standard PQ flow:
        Alice sends PK -> Bob encapsulates -> Bob sends CT -> Alice decapsulates.
        """
        # Alice's setup
        pub_a, priv_a = pq.generate_keypair()

        # Bob's action (using Alice's Public Key)
        ciphertext, ss_bob = pq.encapsulate(pub_a)
        assert len(ciphertext) == 1088
        assert len(ss_bob) == 32

        # Alice's recovery (using her Private Key and Bob's Ciphertext)
        ss_alice = pq.decapsulate(priv_a, ciphertext)

        assert ss_alice == ss_bob

    def test_unique_encapsulation_secrets(self):
        """Every call to encapsulate must yield a unique secret/ciphertext."""
        pub_a, _ = pq.generate_keypair()
        ct1, ss1 = pq.encapsulate(pub_a)
        ct2, ss2 = pq.encapsulate(pub_a)

        assert ct1 != ct2
        assert ss1 != ss2

    def test_decapsulation_failure_with_wrong_key(self):
        """Decapsulating with a mismatched private key must not yield Bob's secret."""
        pub_a, _ = pq.generate_keypair()
        _, priv_b = pq.generate_keypair()

        ct, ss_bob = pq.encapsulate(pub_a)
        ss_alice_wrong = pq.decapsulate(priv_b, ct)

        assert ss_alice_wrong != ss_bob

    def test_tampered_ciphertext_rejection(self):
        """
        ML-KEM uses implicit rejection. Tampering with the ciphertext
        results in a different shared secret rather than a crash.
        """
        pub_a, priv_a = pq.generate_keypair()
        ct, ss_bob = pq.encapsulate(pub_a)

        # Flip the last bit of the ciphertext
        tampered_ct = bytearray(ct)
        tampered_ct[-1] ^= 0x01

        ss_alice = pq.decapsulate(priv_a, bytes(tampered_ct))
        assert ss_alice != ss_bob

    def test_invalid_input_errors(self):
        with pytest.raises(ValueError):
            pq.encapsulate(b"short-junk")

        _, priv_a = pq.generate_keypair()
        with pytest.raises(ValueError):
            pq.decapsulate(priv_a, b"short-junk")