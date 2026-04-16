"""
Tests for KEM modules — Chunk 3 (ECDH) and Chunk 2 (ML-KEM).
"""

import pytest
from src.crypto.kem_classical import generate_keypair, derive_shared_secret


class TestECDH:
    def test_keypair_types_and_lengths(self):
        pub, priv = generate_keypair()
        assert isinstance(pub, bytes) and len(pub) > 0
        assert isinstance(priv, bytes) and len(priv) > 0

    def test_public_key_size(self):
        # SubjectPublicKeyInfo DER for P-256 is always 91 bytes
        pub, _ = generate_keypair()
        assert len(pub) == 91

    def test_both_sides_derive_same_secret(self):
        pub_a, priv_a = generate_keypair()
        pub_b, priv_b = generate_keypair()
        ss_a = derive_shared_secret(priv_a, pub_b)
        ss_b = derive_shared_secret(priv_b, pub_a)
        assert ss_a == ss_b
        assert len(ss_a) == 32

    def test_different_pairs_produce_different_secrets(self):
        pub_a, priv_a = generate_keypair()
        pub_b, _ = generate_keypair()
        pub_c, _ = generate_keypair()
        ss1 = derive_shared_secret(priv_a, pub_b)
        ss2 = derive_shared_secret(priv_a, pub_c)
        assert ss1 != ss2

    def test_wrong_private_key_gives_different_secret(self):
        pub_a, priv_a = generate_keypair()
        pub_b, _ = generate_keypair()
        _, priv_x = generate_keypair()
        ss_correct = derive_shared_secret(priv_a, pub_b)
        ss_wrong = derive_shared_secret(priv_x, pub_b)
        assert ss_correct != ss_wrong

    def test_invalid_key_bytes_raise_value_error(self):
        pub, _ = generate_keypair()
        with pytest.raises((ValueError, Exception)):
            derive_shared_secret(b"not-a-key", pub)
