"""
Handshake protocol — Chunk 8.
Orchestrates KEM + signatures to establish secure session.
Depends on Chunks 2, 3, 6, 7.
"""


def perform_handshake(kem_algo, sig_algo, initiator_side):
    """
    Perform handshake. Returns session_key and peer's signing public key.
    initiator_side: True for Alice (initiates), False for Bob (responds).
    """
    raise NotImplementedError(
        "Chunk 8: implement handshake — KEM exchange, KDF, signature verification"
    )
