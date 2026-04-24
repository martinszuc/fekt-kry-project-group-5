# MPC-KRY Group 5 — Post-Quantum Cryptography Demo

**Course:** MPC-KRY 2025/2026  
**Members:** Martin Szüč (231284), Zakhar Vasiukov (253203), Pavlo Balan (241004), Branislav Kadlec (241045)

---

## Overview

Web app demonstrating post-quantum cryptography as a P2P secure channel between two parties — **Alice** (`:5001`) and **Bob** (`:5002`). Each party runs a Flask instance with a UI for performing handshakes and exchanging encrypted, signed messages.

| Category | Classical | Post-Quantum |
|---|---|---|
| Key exchange (KEM) | ECDH P-256 | ML-KEM-768 |
| Digital signatures | ECDSA P-256 | ML-DSA-65 |
| Symmetric encryption | AES-256-GCM | ChaCha20-Poly1305 |

---

## Codebase

```
src/
├── alice/app.py              # Flask instance for Alice (port 5001)
├── bob/app.py                # Flask instance for Bob (port 5002)
├── crypto/
│   ├── kem_pq.py             # ML-KEM-768
│   ├── kem_classical.py      # ECDH P-256
│   ├── signatures_pq.py      # ML-DSA-65
│   ├── signatures_classical.py  # ECDSA P-256
│   ├── symmetric.py          # AES-256-GCM, ChaCha20-Poly1305
│   ├── handshake.py          # TLS-like handshake protocol
│   └── transfer.py           # Encrypted + signed message transfer
└── utils/
    └── logger.py             # HMAC-chained security event log

config.py                     # Shared ports, URLs, algorithm options
tests/                        # pytest test suite
```

---

## Running

### Option 1 — Docker (recommended, no setup required)

```bash
docker compose up
```

Then open http://localhost:5001 (Alice) and http://localhost:5002 (Bob).

---

### Option 2 — start.py (Python 3.11+ required)

Handles venv creation, dependency install, and opens both browser tabs automatically.

```bash
python start.py
```

> **First run only:** `liboqs-python` requires the native liboqs shared library to be installed before this will work. See the liboqs install steps below.

---

### Option 3 — Manual

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Then in two separate terminals (both with venv active):

```bash
python src/alice/app.py   # http://localhost:5001
python src/bob/app.py     # http://localhost:5002
```

---

### liboqs native library (required for Options 2 and 3)

**macOS**
```bash
brew install cmake
git clone --depth 1 --branch 0.15.0 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs
cmake -S /tmp/liboqs -B /tmp/liboqs/build -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/opt/homebrew
cmake --build /tmp/liboqs/build --parallel 4
cmake --install /tmp/liboqs/build
```

**Linux (Ubuntu/Debian)**
```bash
sudo apt install cmake build-essential
git clone --depth 1 --branch 0.15.0 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs
cmake -S /tmp/liboqs -B /tmp/liboqs/build -DBUILD_SHARED_LIBS=ON
cmake --build /tmp/liboqs/build --parallel 4
sudo cmake --install /tmp/liboqs/build
```

**Windows** — install [CMake](https://cmake.org/download/) and [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) (workload: "Desktop development with C++"), then:
```powershell
git clone --depth 1 --branch 0.15.0 https://github.com/open-quantum-safe/liboqs.git C:\liboqs
cmake -S C:\liboqs -B C:\liboqs\build -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=C:\liboqs\install
cmake --build C:\liboqs\build --config Release --parallel 4
cmake --install C:\liboqs\build --config Release
$env:PATH = "C:\liboqs\install\bin;" + $env:PATH
```

---

## Tests

```bash
pytest tests/
```
