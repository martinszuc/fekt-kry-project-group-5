"""
ECDH P-256 key exchange — Chunk 3.
Uses cryptography library.
Public keys serialized as SubjectPublicKeyInfo DER (91 bytes).
Private keys serialized as PKCS8 DER.
"""

from cryptography.hazmat.primitives.asymmetric.ec import ECDH, generate_private_key, SECP256R1
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
    load_der_private_key, load_der_public_key,
)
from cryptography.hazmat.backends import default_backend


def generate_keypair() -> tuple[bytes, bytes]:
    """
    Generate ECDH P-256 keypair.
    Returns (public_key_bytes, private_key_bytes).
    public_key_bytes: SubjectPublicKeyInfo DER (91 bytes)
    private_key_bytes: PKCS8 DER (~121 bytes)
    """
    private_key = generate_private_key(SECP256R1(), default_backend())
    public_key_bytes = private_key.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    private_key_bytes = private_key.private_bytes(
        Encoding.DER, PrivateFormat.PKCS8, NoEncryption()
    )
    return public_key_bytes, private_key_bytes


def derive_shared_secret(private_key: bytes, peer_public_key: bytes) -> bytes:
    """
    Derive shared secret using own private key and peer's public key.
    Returns raw shared secret bytes (32 bytes for P-256).
    Raises ValueError on invalid key material.
    """
    try:
        private_key_obj = load_der_private_key(private_key, password=None, backend=default_backend())
        peer_key_obj = load_der_public_key(peer_public_key, backend=default_backend())
        return private_key_obj.exchange(ECDH(), peer_key_obj)
    except Exception as e:
        raise ValueError(f"ECDH key derivation failed: {e}")
