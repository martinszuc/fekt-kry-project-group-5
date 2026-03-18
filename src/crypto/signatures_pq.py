"""
ML-DSA-65 (Dilithium) digital signatures — Chunk 6.
Uses liboqs-python when implemented.
"""


def generate_keypair():
    """Generate ML-DSA keypair. Returns (public_key, private_key)."""
    raise NotImplementedError("Chunk 6: implement ML-DSA key generation via liboqs-python")


def sign(private_key, message):
    """Sign message. Returns signature bytes."""
    raise NotImplementedError("Chunk 6: implement ML-DSA sign")


def verify(public_key, message, signature):
    """Verify signature. Returns True/False."""
    raise NotImplementedError("Chunk 6: implement ML-DSA verify")
