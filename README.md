# MPC-KRY Skupina 5 — Post-Quantum Cryptography Demo

**Předmět:** MPC-KRY 2025/2026 — Kryptografie  
**Skupina:** 5  
**Členové:** Martin Szüč (231284), Zakhar Vasiukov (243203), Pavlo Balan (241004), Branislav Kadlec (241045)

---

## Git — základní příkazy

### Klonování repozitáře
```bash
git clone https://github.com/martinszuc/fekt-kry-project-group-5.git
cd fekt-kry-project-group-5
```

### Vytvoření vlastní větve a přepnutí na ni
```bash
# Vždy pracuj na své větvi, NIKDY přímo na main
git checkout -b feature/tvoje-jmeno-co-delas
# Příklad:
git checkout -b feature/martin-kem
```

### Přidání změn (staging) a commit
```bash
# Zobrazit co se změnilo
git status

# Přidat konkrétní soubor
git add src/crypto/kem_pq.py

# Nebo přidat vše najednou
git add .

# Vytvořit commit (napiš srozumitelnou zprávu)
git commit -m "feat: implementace ML-KEM handshake"
```

### Pushnutí větve na GitHub
```bash
# První push nové větve
git push -u origin feature/martin-kem

# Další pushe na stejnou větev
git push
```

### Aktualizace své větve z main (dělej pravidelně!)
```bash
git checkout main
git pull
git checkout feature/martin-kem
git merge main
```

### Pull Request
Po zpushnutí větve jdi na GitHub → **Compare & pull request** → přiřaď reviewera → merge do `main`.

---

## Struktura větví

```
main                  ← stabilní společná verze, merge sem přes PR
├── feature/martin-kem
├── feature/zakhar-encryption
├── feature/pavlo-signatures
└── feature/branislav-docs
```

---

## O projektu

Webová aplikace demonstrující postkvantovou kryptografii jako peer-to-peer komunikaci mezi dvěma účastníky (Alice a Bob). Implementováno v Pythonu s webovým rozhraním Flask.

### Co aplikace dělá

- Simuluje P2P komunikaci mezi dvěma instancemi na různých portech (`:5001`, `:5002`)
- Navazuje zabezpečené spojení pomocí vlastního **handshake protokolu**
- Podporuje výběr mezi klasickými a postkvantovými algoritmy
- Šifruje a podepisuje zprávy/soubory přenášené mezi účastníky
- Loguje bezpečnostní události s ochranou integrity logů

### Kryptografické algoritmy

| Kategorie | Klasický | Post-kvantový |
|---|---|---|
| Ustanovení klíče (KEM) | ECDH | ML-KEM-768 (Kyber) |
| Digitální podpis | ECDSA (P-256) | ML-DSA-65 (Dilithium) |
| Symetrické šifrování | AES-256-GCM | ChaCha20-Poly1305 |

---

## Struktura repozitáře

```
fekt-kry-project-group-5/
├── README.md
├── codestyle.md            # krátký průvodce stylem kódu (EN)
├── config.py               # sdílená konfigurace
├── requirements.txt
├── assignment-and-research.txt   # zadání + plán chunků
├── src/
│   ├── alice/              # Instance Alice (port 5001)
│   │   ├── app.py
│   │   └── templates/
│   ├── bob/                # Instance Bob (port 5002)
│   │   ├── app.py
│   │   └── templates/
│   ├── crypto/             # moduly k implementaci (Chunks 2–9)
│   │   ├── kem_pq.py       # Chunk 2: ML-KEM-768
│   │   ├── kem_classical.py # Chunk 3: ECDH
│   │   ├── symmetric.py    # Chunks 4–5: AES-GCM, ChaCha20
│   │   ├── signatures_pq.py    # Chunk 6: ML-DSA-65
│   │   ├── signatures_classical.py # Chunk 7: ECDSA
│   │   ├── handshake.py    # Chunk 8: handshake protokol
│   │   └── transfer.py     # Chunk 9: šifrovaný přenos
│   ├── static/             # sdílené CSS/JS
│   └── utils/
│       └── logger.py       # Chunk 10: logování (placeholder)
├── tests/
│   └── (test_*.py)
└── docs/
    ├── studie.pdf
    └── dokumentace.pdf
```

**Rozdělení práce:** viz `assignment-and-research.txt` — Project Plan s Chunks 1–14. Každý chunk lze implementovat samostatně.

---

## Instalace a spuštění

### Krok 1 — Nainstaluj Python

Zkontroluj jestli Python máš:
```bash
python --version
# nebo
python3 --version
```

Pokud ne, stáhni Python **3.11 nebo novější** z https://www.python.org/downloads/  
⚠️ Při instalaci na Windows **zaškrtni "Add Python to PATH"**, jinak nic nebude fungovat.

---

### Krok 2 — Naklonuj repozitář

```bash
git clone https://github.com/martinszuc/fekt-kry-project-group-5.git
cd fekt-kry-project-group-5
```

---

### Krok 3 — Vytvoř virtuální prostředí (venv)

Virtuální prostředí izoluje závislosti tohoto projektu od zbytku tvého systému. **Vždy používej venv.**

```bash
# Vytvoření venv (udělej jen jednou)
python -m venv venv
```

Aktivace venv — **musíš udělat pokaždé když otevřeš nový terminál:**

```bash
# Windows (Command Prompt)
venv\Scripts\activate.bat

# Windows (PowerShell)
venv\Scripts\Activate.ps1

# macOS / Linux
source venv/bin/activate
```

Když je venv aktivní, uvidíš `(venv)` na začátku řádku terminálu:
```
(venv) C:\Users\tvoje-jmeno\fekt-kry-project-group-5>
```

Deaktivace (když skončíš):
```bash
deactivate
```

---

### Krok 4 — Nainstaluj závislosti

```bash
# Ujisti se že máš aktivní venv (viz krok 3)
pip install -r requirements.txt
```

> ⚠️ `liboqs-python` vyžaduje aby byl v systému nainstalovaný **CMake** a **C kompilátor**.  
> - Windows: nainstaluj [CMake](https://cmake.org/download/) + [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)  
> - macOS: `brew install cmake`  
> - Linux (Ubuntu/Debian): `sudo apt install cmake gcc`

---

### Krok 5 — Spusť aplikaci

Otevři **dva terminály** — jeden pro Alice, jeden pro Boba. V obou aktivuj venv (Krok 3).

**Terminál 1 — Alice:**
```bash
python src/alice/app.py
```

**Terminál 2 — Bob:**
```bash
python src/bob/app.py
```

Otevři v prohlížeči:
- Alice → http://localhost:5001
- Bob → http://localhost:5002

---

### Krok 6 — Spusť testy

```bash
pytest tests/
```

---

## Code style

Krátký průvodce stylem kódu: **`codestyle.md`** (EN). Při implementaci chunku dodržuj pojmenování, komentáře a strukturu popsanou tam.

---