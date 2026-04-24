#!/usr/bin/env python3
"""
Cross-platform launcher for the PQC demo.

Creates a venv, installs dependencies, starts Alice (:5001) and Bob (:5002),
then opens both browser tabs automatically.

Usage:
    python start.py
"""

import os
import signal
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

ROOT = Path(__file__).parent
VENV = ROOT / "venv"

if sys.platform == "win32":
    VENV_PYTHON = VENV / "Scripts" / "python.exe"
    VENV_PIP = VENV / "Scripts" / "pip.exe"
else:
    VENV_PYTHON = VENV / "bin" / "python"
    VENV_PIP = VENV / "bin" / "pip"


def _find_system_python():
    """Return the first python3.11+ executable found on PATH."""
    for cmd in ("python3", "python"):
        try:
            result = subprocess.run(
                [cmd, "-c", "import sys; assert sys.version_info >= (3, 11)"],
                capture_output=True,
            )
            if result.returncode == 0:
                return cmd
        except FileNotFoundError:
            continue
    return None


def setup():
    python = _find_system_python()
    if not python:
        sys.exit(
            "[!] Python 3.11+ not found.\n"
            "    Download from https://www.python.org/downloads/ and re-run this script.\n"
            "    On Windows make sure to check 'Add Python to PATH' during install."
        )

    if not VENV_PYTHON.exists():
        print("Creating virtual environment...")
        subprocess.run([python, "-m", "venv", str(VENV)], check=True)

    print("Installing dependencies (first run may take a minute — liboqs compiles native code)...")
    result = subprocess.run(
        [str(VENV_PIP), "install", "--quiet", "-r", "requirements.txt"],
        cwd=ROOT,
    )
    if result.returncode != 0:
        print(
            "\n[!] Dependency installation failed.\n"
            "    liboqs-python requires CMake and the native liboqs shared library\n"
            "    to be installed before running pip install.\n\n"
            "    Follow the platform-specific instructions in README.md (Step 4),\n"
            "    then re-run:  python start.py\n\n"
            "    Alternatively, use Docker:  docker compose up\n"
        )
        sys.exit(1)


def launch():
    print("\nStarting Alice on http://localhost:5001 ...")
    alice = subprocess.Popen([str(VENV_PYTHON), "src/alice/app.py"], cwd=ROOT)

    print("Starting Bob   on http://localhost:5002 ...")
    bob = subprocess.Popen([str(VENV_PYTHON), "src/bob/app.py"], cwd=ROOT)

    print("Waiting for servers...")
    time.sleep(2)

    print("Opening browser tabs...")
    webbrowser.open("http://localhost:5001")
    time.sleep(0.3)
    webbrowser.open("http://localhost:5002")

    print("\nBoth servers running. Press Ctrl+C to stop.\n")

    def _shutdown(_sig=None, _frame=None):
        print("\nShutting down...")
        alice.terminate()
        bob.terminate()
        alice.wait()
        bob.wait()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _shutdown)

    alice.wait()
    bob.wait()


if __name__ == "__main__":
    setup()
    launch()
