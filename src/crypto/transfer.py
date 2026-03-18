"""
Secure message/file transfer — Chunk 9.
Encrypt + sign using session from handshake.
Depends on Chunks 4, 5, 6, 7, 8.
"""


def send_message(session_key, signing_key, message, symmetric_algo):
    """Encrypt and sign message. Returns payload for transmission."""
    raise NotImplementedError("Chunk 9: implement send_message")


def receive_message(session_key, peer_verify_key, payload):
    """Decrypt and verify. Returns plaintext or raises on tampering."""
    raise NotImplementedError("Chunk 9: implement receive_message")
