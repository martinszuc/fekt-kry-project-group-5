"""
ML-DSA-65 (Dilithium3) Signature Algorithm.
Pure Python implementation via dilithium-py.
Compliant with FIPS 204.
"""

from dilithium_py.ml_dsa import ML_DSA_65
from typing import Tuple

def generate_keypair() -> Tuple[bytes, bytes]:
    """
    Generate ML-DSA-65 keypair.
    Returns (public_key, private_key) as bit-packed bytes.
    """
    pk, sk = ML_DSA_65.keygen()
    return pk, sk

def sign(private_key: bytes, message: bytes) -> bytes:
    """
    Signs a message using the ML-DSA-65 private key.
    Uses deterministic nonce (32 zero bytes) for FIPS 204 compliance and testing.
    """
    try:
        # FIPS 204 requires a context string (ctx), default is empty bytes
        ctx = b""
        # Fixed-zero randomness gives deterministic signatures (good for tests).
        # For production, replace with os.urandom(32) to use hedged mode (FIPS 204 §5.2).
        randomness = b"\x00" * 32
        return ML_DSA_65.sign(private_key, message, ctx, randomness)
    except Exception as e:
        raise ValueError(f"ML-DSA signing failed: {e}")

def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """
    Verifies an ML-DSA-65 signature.
    Returns True if valid, False otherwise.
    """
    try:
        # Context must match the one used during signing
        ctx = b""
        # ML_DSA_65.verify(pk, msg, sig, ctx)
        return ML_DSA_65.verify(public_key, message, signature, ctx)
    except Exception:
        # Catch-all for malformed signatures or length mismatches
        return False
