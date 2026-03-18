"""
Symmetric encryption — Chunks 4 & 5.
AES-256-GCM and ChaCha20-Poly1305.
"""


def encrypt_aes_gcm(key, plaintext):
    """Encrypt with AES-256-GCM. Returns (ciphertext, nonce, tag)."""
    raise NotImplementedError("Chunk 4: implement AES-256-GCM encrypt")


def decrypt_aes_gcm(key, ciphertext, nonce, tag):
    """Decrypt AES-256-GCM. Tampered ciphertext must raise error."""
    raise NotImplementedError("Chunk 4: implement AES-256-GCM decrypt")


def encrypt_chacha20(key, plaintext):
    """Encrypt with ChaCha20-Poly1305. Returns (ciphertext, nonce)."""
    raise NotImplementedError("Chunk 5: implement ChaCha20-Poly1305 encrypt")


def decrypt_chacha20(key, ciphertext, nonce):
    """Decrypt ChaCha20-Poly1305. Tampered ciphertext must raise error."""
    raise NotImplementedError("Chunk 5: implement ChaCha20-Poly1305 decrypt")
