"""
Security event logger — Chunk 10.
Placeholder implementation for UI demo. Replace with integrity-protected version.
"""

import os
from datetime import datetime

LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "logs")
LOG_FILE = os.path.join(LOG_DIR, "security.log")

_entries = []


def _ensure_log_dir():
    os.makedirs(LOG_DIR, exist_ok=True)


def log_event(event_type, algorithm=None, data_size=None, result="OK"):
    """Log security event. Placeholder — add HMAC chain in Chunk 10."""
    _ensure_log_dir()
    timestamp = datetime.utcnow().isoformat() + "Z"
    entry = {
        "timestamp": timestamp,
        "event": event_type,
        "algorithm": algorithm or "-",
        "data_size": data_size or 0,
        "result": result,
    }
    _entries.append(entry)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        line = f"{timestamp} | {event_type} | {algorithm or '-'} | {result}\n"
        f.write(line)
    return entry


def get_log_entries():
    """Return log entries for UI. Placeholder — add integrity check in Chunk 10."""
    if not _entries:
        log_event("app_start", result="OK")
    return list(reversed(_entries))
