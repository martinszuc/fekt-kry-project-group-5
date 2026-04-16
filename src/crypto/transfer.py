"""
Secure message/file transfer — Chunk 9.
Encrypt + sign using session from handshake.
Depends on Chunks 4, 5, 6, 7, 8.
"""

from __future__ import annotations

import base64
import json

from src.crypto.symmetric import (
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    encrypt_chacha20,
    decrypt_chacha20,
)
from src.crypto import signatures_classical


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def _canonical_json(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def send_message(session_key, signing_key, message, symmetric_algo):
    """Encrypt and sign message. Returns payload for transmission."""
    if not isinstance(message, (bytes, bytearray)):
        message_bytes = str(message).encode("utf-8")
    else:
        message_bytes = bytes(message)

    payload: dict = {
        "v": 1,
        "symmetric": symmetric_algo,
    }

    if symmetric_algo == "aes_gcm":
        ct, nonce, tag = encrypt_aes_gcm(session_key, message_bytes)
        payload.update(
            {
                "nonce": _b64e(nonce),
                "ciphertext": _b64e(ct),
                "tag": _b64e(tag),
            }
        )
    elif symmetric_algo == "chacha20":
        ct, nonce = encrypt_chacha20(session_key, message_bytes)
        payload.update(
            {
                "nonce": _b64e(nonce),
                "ciphertext": _b64e(ct),
            }
        )
    else:
        raise ValueError("Unsupported symmetric algorithm")

    to_sign = dict(payload)
    sig = signatures_classical.sign(signing_key, _canonical_json(to_sign))
    payload["signature"] = _b64e(sig)
    return payload


def receive_message(session_key, peer_verify_key, payload):
    """Decrypt and verify. Returns plaintext or raises on tampering."""
    if payload.get("v") != 1:
        raise ValueError("Unsupported payload version")

    signature_b64 = payload.get("signature")
    if not signature_b64:
        raise ValueError("Missing signature")

    signed_obj = dict(payload)
    signed_obj.pop("signature", None)
    signature = _b64d(signature_b64)
    if not signatures_classical.verify(peer_verify_key, _canonical_json(signed_obj), signature):
        raise ValueError("Signature verification failed")

    symmetric_algo = payload.get("symmetric")
    nonce = _b64d(payload["nonce"])
    ciphertext = _b64d(payload["ciphertext"])

    if symmetric_algo == "aes_gcm":
        tag = _b64d(payload["tag"])
        return decrypt_aes_gcm(session_key, ciphertext, nonce, tag)
    if symmetric_algo == "chacha20":
        return decrypt_chacha20(session_key, ciphertext, nonce)

    raise ValueError("Unsupported symmetric algorithm")
