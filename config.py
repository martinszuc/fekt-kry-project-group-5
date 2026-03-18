"""Shared configuration for Alice and Bob instances."""

ALICE_PORT = 5001
BOB_PORT = 5002

ALICE_URL = "http://localhost:5001"
BOB_URL = "http://localhost:5002"

# algorithm options for UI dropdowns
KEM_OPTIONS = [
    ("mlkem", "ML-KEM-768 (post-quantum)"),
    ("ecdh", "ECDH P-256 (classical)"),
]

SIGNATURE_OPTIONS = [
    ("mldsa", "ML-DSA-65 (post-quantum)"),
    ("ecdsa", "ECDSA P-256 (classical)"),
]

SYMMETRIC_OPTIONS = [
    ("aes_gcm", "AES-256-GCM"),
    ("chacha20", "ChaCha20-Poly1305"),
]
