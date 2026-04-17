"""
ML-KEM-768 (Kyber) key encapsulation — Chunk 2.
Uses liboqs-python (import oqs).

Quick reference — how the oqs KEM API works:

    import oqs
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()          # also stores private key inside kem
    ciphertext, shared_secret = oqs.KeyEncapsulation("ML-KEM-768").encap_secret(public_key)
    recovered = kem.decap_secret(ciphertext)     # recovered == shared_secret
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
