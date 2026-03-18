"""
ECDH P-256 key exchange — Chunk 3.
Uses cryptography library.
"""


def generate_keypair():
    """Generate ECDH keypair. Returns (public_key, private_key)."""
    raise NotImplementedError("Chunk 3: implement ECDH key generation via cryptography")


def derive_shared_secret(private_key, peer_public_key):
    """Derive shared secret from own private key and peer's public key."""
    raise NotImplementedError("Chunk 3: implement ECDH shared secret derivation")
