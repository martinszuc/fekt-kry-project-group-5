"""
ECDSA P-256 digital signatures — Chunk 7.
Uses cryptography library.
"""


def generate_keypair():
    """Generate ECDSA keypair. Returns (public_key, private_key)."""
    raise NotImplementedError("Chunk 7: implement ECDSA key generation via cryptography")


def sign(private_key, message):
    """Sign message. Returns signature bytes."""
    raise NotImplementedError("Chunk 7: implement ECDSA sign")


def verify(public_key, message, signature):
    """Verify signature. Returns True/False."""
    raise NotImplementedError("Chunk 7: implement ECDSA verify")
