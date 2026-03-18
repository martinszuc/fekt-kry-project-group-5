"""
ML-KEM-768 (Kyber) key encapsulation — Chunk 2.
Uses liboqs-python when implemented.
"""


def generate_keypair():
    """Generate ML-KEM keypair. Returns (public_key, private_key)."""
    raise NotImplementedError("Chunk 2: implement ML-KEM key generation via liboqs-python")


def encapsulate(public_key):
    """Encapsulate shared secret. Returns (ciphertext, shared_secret)."""
    raise NotImplementedError("Chunk 2: implement ML-KEM encapsulate")


def decapsulate(private_key, ciphertext):
    """Decapsulate shared secret from ciphertext."""
    raise NotImplementedError("Chunk 2: implement ML-KEM decapsulate")
