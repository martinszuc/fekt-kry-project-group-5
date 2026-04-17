"""
ECDSA P-256 digital signatures — Chunk 7.
Uses cryptography library.
Keys serialized as DER (SubjectPublicKeyInfo / PKCS8).
Signing uses ECDSA + SHA-256; message is hashed internally by the library.
"""

from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, generate_private_key, SECP256R1
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
    load_der_private_key, load_der_public_key,
)
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


def generate_keypair() -> tuple[bytes, bytes]:
    """
    Generate ECDSA P-256 keypair.
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


def sign(private_key: bytes, message: bytes) -> bytes:
    """
    Sign message with ECDSA P-256 + SHA-256.
    Returns DER-encoded signature bytes (~70-72 bytes).
    Raises ValueError on failure.
    """
    try:
        private_key_obj = load_der_private_key(private_key, password=None, backend=default_backend())
        return private_key_obj.sign(message, ECDSA(SHA256()))
    except Exception as e:
        raise ValueError(f"ECDSA signing failed: {e}")


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """
    Verify ECDSA P-256 signature.
    Returns True if valid, False if invalid or on any error.
    """
    try:
        public_key_obj = load_der_public_key(public_key, backend=default_backend())
        public_key_obj.verify(signature, message, ECDSA(SHA256()))
        return True
    except InvalidSignature:
        return False
