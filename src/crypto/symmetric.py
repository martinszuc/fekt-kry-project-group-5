"""
Symmetric encryption — Chunks 4 & 5.
AES-256-GCM  (Chunk 4) and ChaCha20-Poly1305 (Chunk 5).
Both use AEAD — confidentiality + integrity in one pass.
Nonces are always generated fresh on encrypt; never reused.
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


# --- Chunk 4: AES-256-GCM ---

def encrypt_aes_gcm(key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt plaintext with AES-256-GCM.
    key: exactly 32 bytes
    Returns (ciphertext, nonce, tag).
    nonce: 12 bytes, freshly generated
    tag: 16 bytes GCM authentication tag separated from ciphertext
    """
    if len(key) != 32:
        raise ValueError("AES-256-GCM requires 32-byte key")
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    # library returns ciphertext + 16-byte tag concatenated
    combined = aesgcm.encrypt(nonce, plaintext, None)
    ciphertext = combined[:-16]
    tag = combined[-16:]
    return ciphertext, nonce, tag


def decrypt_aes_gcm(key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes) -> bytes:
    """
    Decrypt AES-256-GCM ciphertext.
    key: exactly 32 bytes
    Raises cryptography.exceptions.InvalidTag if authentication fails (tampered data).
    Returns plaintext bytes.
    """
    if len(key) != 32:
        raise ValueError("AES-256-GCM requires 32-byte key")
    aesgcm = AESGCM(key)
    combined = ciphertext + tag
    return aesgcm.decrypt(nonce, combined, None)


# --- Chunk 5: ChaCha20-Poly1305 ---

def encrypt_chacha20(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt plaintext with ChaCha20-Poly1305.
    key: exactly 32 bytes
    Returns (ciphertext, nonce).
    nonce: 12 bytes, freshly generated
    ciphertext includes the 16-byte Poly1305 tag appended by the library.
    """
    if len(key) != 32:
        raise ValueError("ChaCha20-Poly1305 requires 32-byte key")
    nonce = os.urandom(12)
    chacha = ChaCha20Poly1305(key)
    ciphertext = chacha.encrypt(nonce, plaintext, None)
    return ciphertext, nonce


def decrypt_chacha20(key: bytes, ciphertext: bytes, nonce: bytes) -> bytes:
    """
    Decrypt ChaCha20-Poly1305 ciphertext.
    key: exactly 32 bytes
    ciphertext: includes the 16-byte Poly1305 tag at the end (as returned by encrypt)
    Raises cryptography.exceptions.InvalidTag if authentication fails.
    Returns plaintext bytes.
    """
    if len(key) != 32:
        raise ValueError("ChaCha20-Poly1305 requires 32-byte key")
    chacha = ChaCha20Poly1305(key)
    return chacha.decrypt(nonce, ciphertext, None)
