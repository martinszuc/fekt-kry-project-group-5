"""
ML-KEM-768 (Post-Quantum) key exchange.
Corrected for FIPS 203 (Secret, Ciphertext) return order.
"""

from mlkem.ml_kem import ML_KEM
from mlkem.parameter_set import ML_KEM_768

# Initialize the ML-KEM-768 instance
_kem = ML_KEM(ML_KEM_768)

def generate_keypair() -> tuple[bytes, bytes]:
    """
    Generate ML-KEM-768 keypair.
    Returns (public_key, private_key).
    """
    # key_gen returns (ek, dk) -> (encapsulation key, decapsulation key)
    public_key, private_key = _kem.key_gen()
    return public_key, private_key


def encapsulate(peer_public_key: bytes) -> tuple[bytes, bytes]:
    """
    Returns (ciphertext, shared_secret).
    """
    try:
        # FIPS 203: Encaps(ek) returns (K, c)
        # K = shared_secret (32 bytes), c = ciphertext (1088 bytes)
        shared_secret, ciphertext = _kem.encaps(peer_public_key)

        # We return (ciphertext, shared_secret) to match your desired API
        return ciphertext, shared_secret
    except Exception as e:
        raise ValueError(f"ML-KEM encapsulation failed: {e}")


def decapsulate(private_key: bytes, ciphertext: bytes) -> bytes:
    """
    Returns shared_secret (32 bytes).
    """
    try:
        # decaps(dk, c) returns K
        shared_secret = _kem.decaps(private_key, ciphertext)
        return shared_secret
    except Exception as e:
        # This will now receive a 1088-byte ciphertext instead of 32
        raise ValueError(f"ML-KEM decapsulation failed: {e}")