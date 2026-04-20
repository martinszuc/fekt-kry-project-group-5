"""
Secure message/file transfer — Chunk 9.
Encrypt + sign using session from handshake.
Updated for Crypto-Agility (Classical + PQ).
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
from src.crypto import signatures_classical, signatures_pq
from src.utils import logger


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def _canonical_json(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sig_module(sig_algo: str):
    if sig_algo == "mldsa":
        return signatures_pq
    return signatures_classical


def send_message(session_key, signing_key, message, symmetric_algo, sig_algo="ecdsa"):
    """Encrypt and sign message. Returns payload for transmission."""
    if not isinstance(message, (bytes, bytearray)):
        message_bytes = str(message).encode("utf-8")
    else:
        message_bytes = bytes(message)

    payload: dict = {
        "v": 1,
        "symmetric": symmetric_algo,
    }

    logger.info("transfer.send", f"sym={symmetric_algo}  sig={sig_algo}  pt={len(message_bytes)}B")

    if symmetric_algo == "aes_gcm":
        ct, nonce, tag = encrypt_aes_gcm(session_key, message_bytes)
        payload.update({"nonce": _b64e(nonce), "ciphertext": _b64e(ct), "tag": _b64e(tag)})
        logger.info("transfer.encrypt", f"algo=aes_gcm  ct={len(ct)}B  nonce={len(nonce)}B  tag={len(tag)}B")
    elif symmetric_algo == "chacha20":
        ct, nonce = encrypt_chacha20(session_key, message_bytes)
        payload.update({"nonce": _b64e(nonce), "ciphertext": _b64e(ct)})
        logger.info("transfer.encrypt", f"algo=chacha20  ct={len(ct)}B  nonce={len(nonce)}B")
    else:
        raise ValueError("Unsupported symmetric algorithm")

    sig_mod = _sig_module(sig_algo)
    to_sign = dict(payload)
    to_sign_bytes = _canonical_json(to_sign)
    sig = sig_mod.sign(signing_key, to_sign_bytes)
    logger.info("transfer.sign", f"algo={sig_algo}  payload={len(to_sign_bytes)}B  sig={len(sig)}B")
    payload["signature"] = _b64e(sig)
    return payload


def receive_message(session_key, peer_verify_key, payload, sig_algo="ecdsa"):
    """Decrypt and verify. Returns plaintext or raises on tampering."""
    if payload.get("v") != 1:
        raise ValueError("Unsupported payload version")

    signature_b64 = payload.get("signature")
    if not signature_b64:
        raise ValueError("Missing signature")

    signed_obj = dict(payload)
    signed_obj.pop("signature", None)
    signature = _b64d(signature_b64)

    sig_mod = _sig_module(sig_algo)
    signed_bytes = _canonical_json(signed_obj)
    ok = sig_mod.verify(peer_verify_key, signed_bytes, signature)
    logger.info("transfer.verify", f"algo={sig_algo}  data={len(signed_bytes)}B  result={'ok' if ok else 'FAIL'}")
    if not ok:
        raise ValueError("Signature verification failed")

    symmetric_algo = payload.get("symmetric")
    nonce = _b64d(payload["nonce"])
    ciphertext = _b64d(payload["ciphertext"])
    logger.info("transfer.receive", f"sym={symmetric_algo}  ct={len(ciphertext)}B")

    if symmetric_algo == "aes_gcm":
        tag = _b64d(payload["tag"])
        pt = decrypt_aes_gcm(session_key, ciphertext, nonce, tag)
        logger.info("transfer.decrypt", f"algo=aes_gcm  ct={len(ciphertext)}B  →  pt={len(pt)}B")
        return pt
    if symmetric_algo == "chacha20":
        pt = decrypt_chacha20(session_key, ciphertext, nonce)
        logger.info("transfer.decrypt", f"algo=chacha20  ct={len(ciphertext)}B  →  pt={len(pt)}B")
        return pt

    raise ValueError("Unsupported symmetric algorithm")