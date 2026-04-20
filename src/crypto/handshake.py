"""
Handshake protocol — Chunk 8.

This file implements the *classical* end-to-end handshake used for Option 1:
- KEM: ECDH P-256 (simulated as ephemeral ECDH exchange)
- Signatures: ECDSA P-256
- KDF: HKDF-SHA256 -> 32-byte session key

The API is designed to be easy to wire into Flask routes (client_hello/server_hello/finish).
Post-quantum variants (ML-KEM / ML-DSA) can be plugged in later while keeping the flow.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.crypto import kem_classical
from src.crypto import kem_pq
from src.crypto import signatures_classical
from src.crypto import signatures_pq
from src.utils import logger


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def _canonical_json(obj: dict) -> bytes:
    # Stable encoding for signatures across both parties.
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def derive_session_key(shared_secret: bytes) -> bytes:
    """
    Derive 32-byte session key from shared secret using HKDF-SHA256.
    """
    hkdf = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b"mpc-kry-handshake-v1",
    )
    return hkdf.derive(shared_secret)


@dataclass(frozen=True)
class AliceHandshakeState:
    kem_private_key: bytes
    kem_public_key: bytes
    symmetric_algo: str


@dataclass(frozen=True)
class BobHandshakeState:
    kem_private_key: bytes
    kem_public_key: bytes
    sig_private_key: bytes
    sig_public_key: bytes
    symmetric_algo: str
    session_key: bytes


def alice_client_hello(*, kem_algo: str, sig_algo: str, symmetric_algo: str) -> tuple[AliceHandshakeState, dict]:
    """
    Alice (initiator) creates ClientHello.

    Returns:
    - state: stored by Alice until ServerHello arrives
    - message dict: JSON-serializable (base64 for bytes)
    """
    if kem_algo not in ("ecdh", "mlkem"):
        raise ValueError("Unsupported KEM algorithm")
    if sig_algo not in ("ecdsa", "mldsa"):
        raise ValueError("Unsupported signature algorithm")
    if symmetric_algo not in ("aes_gcm", "chacha20"):
        raise ValueError("Unsupported symmetric algorithm")

    if kem_algo == "ecdh":
        kem = kem_classical
    elif kem_algo == "mlkem":
        kem = kem_pq

    logger.info("handshake.client_hello", f"KEM={kem_algo}  SIG={sig_algo}  SYM={symmetric_algo}")
    kem_pub, kem_priv = kem.generate_keypair()
    logger.info("kem.keygen", f"algo={kem_algo}  pub={len(kem_pub)}B  priv={len(kem_priv)}B")

    state = AliceHandshakeState(
        kem_private_key=kem_priv,
        kem_public_key=kem_pub,
        symmetric_algo=symmetric_algo,
    )
    msg = {
        "v": 1,
        "phase": "client_hello",
        "kem": kem_algo,
        "sig": sig_algo,
        "symmetric": symmetric_algo,
        "alice_kem_pub": _b64e(kem_pub),
    }
    return state, msg


def bob_server_hello(client_hello: dict) -> tuple[BobHandshakeState, dict]:
    """
    Bob (responder) handles ClientHello and returns ServerHello.

    ServerHello includes Bob's ECDH public key, Bob's signing public key, and a signature
    over the handshake transcript.
    """
    if client_hello.get("v") != 1 or client_hello.get("phase") != "client_hello":
        raise ValueError("Invalid client_hello")

    kem_algo = client_hello.get("kem")

    sig_algo = client_hello.get("sig")
    symmetric_algo = client_hello.get("symmetric")
    if kem_algo not in ("ecdh", "mlkem"):
        raise ValueError("Unsupported KEM algorithm")

    if sig_algo not in ("ecdsa", "mldsa"):
        raise ValueError("Unsupported signature algorithm")

    if symmetric_algo not in ("aes_gcm", "chacha20"):
        raise ValueError("Unsupported symmetric algorithm")

    alice_kem_pub = _b64d(client_hello["alice_kem_pub"])

    logger.info("handshake.server_hello", f"algo={kem_algo}+{sig_algo}  sym={symmetric_algo}")

    if kem_algo == "ecdh":
        bob_kem_pub, bob_kem_priv = kem_classical.generate_keypair()
        shared_secret = kem_classical.derive_shared_secret(bob_kem_priv, alice_kem_pub)
        logger.info("kem.derive", f"algo=ecdh  peer_pub={len(alice_kem_pub)}B  secret={len(shared_secret)}B")
    elif kem_algo == "mlkem":
        # Bob encapsulates against Alice's public key; sends ciphertext, keeps shared secret
        ciphertext, shared_secret = kem_pq.encapsulate(alice_kem_pub)
        bob_kem_pub = ciphertext
        bob_kem_priv = b""
        logger.info("kem.encapsulate", f"algo=mlkem  ct={len(ciphertext)}B  secret={len(shared_secret)}B")

    session_key = derive_session_key(shared_secret)
    logger.info("kdf.hkdf", f"input={len(shared_secret)}B  →  session_key={len(session_key)}B")

    if sig_algo == "ecdsa":
        signatures = signatures_classical
    elif sig_algo == "mldsa":
        signatures = signatures_pq
    else:
        raise ValueError(f"Unsupported signature algorithm: {sig_algo}")

    bob_sig_pub, bob_sig_priv = signatures.generate_keypair()
    logger.info("sig.keygen", f"algo={sig_algo}  pub={len(bob_sig_pub)}B  priv={len(bob_sig_priv)}B")

    transcript = {
        "v": 1,
        "kem": kem_algo,
        "sig": sig_algo,
        "symmetric": symmetric_algo,
        "alice_kem_pub": client_hello["alice_kem_pub"],
        "bob_kem_pub": _b64e(bob_kem_pub),
        "bob_sig_pub": _b64e(bob_sig_pub),
    }

    transcript_bytes = _canonical_json(transcript)
    signature = signatures.sign(bob_sig_priv, transcript_bytes)
    logger.info("sig.sign", f"algo={sig_algo}  data={len(transcript_bytes)}B  sig={len(signature)}B")

    state = BobHandshakeState(
        kem_private_key=bob_kem_priv,
        kem_public_key=bob_kem_pub,
        sig_private_key=bob_sig_priv,
        sig_public_key=bob_sig_pub,
        symmetric_algo=symmetric_algo,
        session_key=session_key,
    )

    server_hello = {
        "v": 1,
        "phase": "server_hello",
        "kem": kem_algo,
        "sig": sig_algo,
        "symmetric": symmetric_algo,
        "alice_kem_pub": client_hello["alice_kem_pub"],
        "bob_kem_pub": _b64e(bob_kem_pub),
        "bob_sig_pub": _b64e(bob_sig_pub),
        "signature": _b64e(signature),
    }
    return state, server_hello


def alice_finish(state: AliceHandshakeState, server_hello: dict) -> tuple[bytes, bytes, bytes, bytes, dict]:
    """
    Alice verifies ServerHello signature, derives session key, and generates her signing keypair.

    Returns:
    - session_key
    - alice_sig_public_key
    - alice_sig_private_key
    - bob_sig_public_key
    - finish message dict (to send to Bob)
    """
    if server_hello.get("v") != 1 or server_hello.get("phase") != "server_hello":
        raise ValueError("Invalid server_hello")

    if server_hello.get("symmetric") != state.symmetric_algo:
        raise ValueError("Handshake symmetric mismatch")

    bob_sig_pub = _b64d(server_hello["bob_sig_pub"])
    signature = _b64d(server_hello["signature"])

    transcript = {
        "v": 1,
        "kem": server_hello.get("kem"),
        "sig": server_hello.get("sig"),
        "symmetric": server_hello.get("symmetric"),
        "alice_kem_pub": server_hello["alice_kem_pub"],
        "bob_kem_pub": server_hello["bob_kem_pub"],
        "bob_sig_pub": server_hello["bob_sig_pub"],
    }
    sig_algo = server_hello.get("sig")
    kem_algo = server_hello.get("kem")

    logger.info("handshake.alice_finish", f"algo={kem_algo}+{sig_algo}")

    if sig_algo == "ecdsa":
        signatures = signatures_classical
    elif sig_algo == "mldsa":
        signatures = signatures_pq
    else:
        raise ValueError(f"Unsupported signature algorithm: {sig_algo}")

    transcript_bytes = _canonical_json(transcript)
    ok = signatures.verify(bob_sig_pub, transcript_bytes, signature)
    logger.info("sig.verify", f"algo={sig_algo}  data={len(transcript_bytes)}B  result={'ok' if ok else 'FAIL'}")
    if not ok:
        raise ValueError("ServerHello signature verification failed")

    if kem_algo == "ecdh":
        bob_payload = _b64d(server_hello["bob_kem_pub"])
        shared_secret = kem_classical.derive_shared_secret(state.kem_private_key, bob_payload)
        logger.info("kem.derive", f"algo=ecdh  secret={len(shared_secret)}B")
    elif kem_algo == "mlkem":
        bob_payload = _b64d(server_hello["bob_kem_pub"])
        shared_secret = kem_pq.decapsulate(state.kem_private_key, bob_payload)
        logger.info("kem.decapsulate", f"algo=mlkem  ct={len(bob_payload)}B  →  secret={len(shared_secret)}B")

    session_key = derive_session_key(shared_secret)
    logger.info("kdf.hkdf", f"input={len(shared_secret)}B  →  session_key={len(session_key)}B")

    alice_sig_pub, alice_sig_priv = signatures.generate_keypair()
    logger.info("sig.keygen", f"algo={sig_algo}  pub={len(alice_sig_pub)}B  (alice ephemeral)")
    finish_msg = {
        "v": 1,
        "phase": "finish",
        "alice_sig_pub": _b64e(alice_sig_pub),
    }
    return session_key, alice_sig_pub, alice_sig_priv, bob_sig_pub, finish_msg


def bob_finish(state: BobHandshakeState, finish_msg: dict) -> bytes:
    """
    Bob stores Alice's signing public key for future message verification.
    Returns Alice's signing public key bytes.
    """
    if finish_msg.get("v") != 1 or finish_msg.get("phase") != "finish":
        raise ValueError("Invalid finish message")
    return _b64d(finish_msg["alice_sig_pub"])


def perform_handshake(kem_algo, sig_algo, initiator_side):
    """
    Convenience helper for local testing: simulates a full 2-party handshake in-memory.

    Returns (session_key, peer_signing_public_key) for the requested side.
    """

    a_state, hello = alice_client_hello(kem_algo=kem_algo, sig_algo=sig_algo, symmetric_algo="aes_gcm")
    b_state, sh = bob_server_hello(hello)
    a_session_key, _a_sig_pub, _a_sig_priv, b_sig_pub, finish = alice_finish(a_state, sh)
    a_sig_pub_bytes = _b64d(finish["alice_sig_pub"])
    _ = bob_finish(b_state, finish)

    if initiator_side:
        return a_session_key, b_sig_pub
    return b_state.session_key, a_sig_pub_bytes
