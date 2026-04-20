"""
Security event logger — Chunk 10.

HMAC-chained log: each entry's MAC covers (seq + timestamp + level + event + detail + prev_mac),
keyed with an ephemeral per-session secret. Call verify_chain() to check integrity at any point.

Public API
----------
  info(event, detail="")   — normal operation steps
  warn(event, detail="")   — unexpected but recoverable
  error(event, detail="")  — operation failed
  log_event(...)           — backward-compatible shim used by Flask routes
  get_log_entries()        — returns entries newest-first (for UI)
  verify_chain()           — returns (ok: bool, first_bad_seq: int)
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sys
from datetime import datetime, timezone

# ── paths ────────────────────────────────────────────────────────────────────
_BASE = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.normpath(os.path.join(_BASE, "..", "..", "logs"))
LOG_FILE = os.path.join(LOG_DIR, "security.log")

# ── state ────────────────────────────────────────────────────────────────────
_CHAIN_KEY: bytes = secrets.token_bytes(32)   # ephemeral per-session HMAC key
_entries: list[dict] = []
_prev_mac: bytes = b"\x00" * 32

# ── levels ───────────────────────────────────────────────────────────────────
INFO  = "INFO"
WARN  = "WARN"
ERROR = "ERROR"

_LEVEL_PREFIX = {INFO: "·", WARN: "!", ERROR: "✗"}


# ── internal ─────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3] + "Z"


def _mac(seq: int, ts: str, level: str, event: str, detail: str, prev: bytes) -> bytes:
    msg = f"{seq}|{ts}|{level}|{event}|{detail}".encode("utf-8") + prev
    return hmac.new(_CHAIN_KEY, msg, hashlib.sha256).digest()


def _log(level: str, event: str, detail: str = "") -> dict:
    global _prev_mac
    os.makedirs(LOG_DIR, exist_ok=True)

    seq = len(_entries)
    ts  = _now()
    mac = _mac(seq, ts, level, event, detail, _prev_mac)
    _prev_mac = mac

    entry = {
        "seq":       seq,
        "timestamp": ts,
        "level":     level,
        "event":     event,
        "detail":    detail,
        "mac":       mac.hex(),
        # backward-compat fields consumed by the UI template
        "result":    "OK" if level != ERROR else "FAIL",
        "algorithm": _extract_algo(detail),
        "data_size": _extract_size(detail),
    }
    _entries.append(entry)

    # ── file ──────────────────────────────────────────────────────────────────
    prefix = _LEVEL_PREFIX.get(level, " ")
    line = f"{ts} {prefix} {level:<5}  {event}"
    if detail:
        line += f"  {detail}"
    with open(LOG_FILE, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")

    # ── stdout (for dev / docker logs) ────────────────────────────────────────
    stream = sys.stderr if level == ERROR else sys.stdout
    print(line, file=stream)

    return entry


def _extract_algo(detail: str) -> str:
    """Pull algo= value from a detail string, or return '-'."""
    for tok in detail.split():
        if tok.startswith("algo="):
            return tok[5:]
    return "-"


def _extract_size(detail: str) -> int:
    """Pull first NNB token from detail, e.g. '27B' → 27."""
    for tok in detail.split():
        if tok.endswith("B") and tok[:-1].isdigit():
            return int(tok[:-1])
    return 0


# ── public API ───────────────────────────────────────────────────────────────

def info(event: str, detail: str = "") -> dict:
    return _log(INFO, event, detail)


def warn(event: str, detail: str = "") -> dict:
    return _log(WARN, event, detail)


def error(event: str, detail: str = "") -> dict:
    return _log(ERROR, event, detail)


def log_event(event_type: str, algorithm: str | None = None,
              data_size: int | None = None, result: str = "OK",
              detail: str = "") -> dict:
    """Backward-compatible shim — maps old call-sites to the new logger."""
    parts: list[str] = []
    if algorithm:
        parts.append(f"algo={algorithm}")
    if data_size:
        parts.append(f"{data_size}B")
    if detail:
        parts.append(detail)
    full = "  ".join(parts)
    level = ERROR if result.upper() not in ("OK",) else INFO
    return _log(level, event_type, full)


def get_log_entries() -> list[dict]:
    """Return all entries newest-first for the UI."""
    return list(reversed(_entries))


def verify_chain() -> tuple[bool, int]:
    """
    Walk the HMAC chain and verify every entry.
    Returns (True, -1) if intact, or (False, first_bad_seq) on failure.
    """
    prev = b"\x00" * 32
    for e in _entries:
        expected = _mac(e["seq"], e["timestamp"], e["level"],
                        e["event"], e["detail"], prev)
        if not hmac.compare_digest(expected.hex(), e["mac"]):
            return False, e["seq"]
        prev = bytes.fromhex(e["mac"])
    return True, -1
