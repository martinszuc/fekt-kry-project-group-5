"""
Chunk 13 — Benchmark & Comparison
Classical vs Post-Quantum algorithms.

Usage:
    python tests/benchmark.py

Outputs:
    - Comparison table printed to stdout
    - tests/benchmark_results.json  (raw numbers for documentation)
    - tests/benchmark_chart_kem.png
    - tests/benchmark_chart_sig.png
"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.crypto import kem_classical, kem_pq
from src.crypto import signatures_classical, signatures_pq

N = 50
SAMPLE_MSG = b"benchmark message for signing"


# ── timing helpers ────────────────────────────────────────────────────────────

def measure(fn, n=N):
    """Run fn() n times, return (mean_ms, last_result)."""
    start = time.perf_counter()
    result = None
    for _ in range(n):
        result = fn()
    elapsed = (time.perf_counter() - start) / n * 1000
    return elapsed, result


# ── KEM benchmarks ────────────────────────────────────────────────────────────

def bench_ecdh():
    keygen_ms, (pub, priv) = measure(kem_classical.generate_keypair)

    pub_b, priv_b = kem_classical.generate_keypair()
    exchange_ms, secret = measure(lambda: kem_classical.derive_shared_secret(priv, pub_b))

    return {
        "name": "ECDH P-256",
        "quantum_resistant": False,
        "nist_level": 3,
        "keygen_ms": keygen_ms,
        "exchange_ms": exchange_ms,
        "decaps_ms": None,
        "pub_key_bytes": len(pub),
        "priv_key_bytes": len(priv),
        "ciphertext_bytes": None,
        "secret_bytes": len(secret),
    }


def bench_mlkem():
    keygen_ms, (pub, priv) = measure(kem_pq.generate_keypair)
    encaps_ms, (ct, ss_enc) = measure(lambda: kem_pq.encapsulate(pub))
    decaps_ms, ss_dec = measure(lambda: kem_pq.decapsulate(priv, ct))

    return {
        "name": "ML-KEM-768",
        "quantum_resistant": True,
        "nist_level": 3,
        "keygen_ms": keygen_ms,
        "exchange_ms": encaps_ms,
        "decaps_ms": decaps_ms,
        "pub_key_bytes": len(pub),
        "priv_key_bytes": len(priv),
        "ciphertext_bytes": len(ct),
        "secret_bytes": len(ss_enc),
    }


# ── Signature benchmarks ──────────────────────────────────────────────────────

def bench_ecdsa():
    keygen_ms, (pub, priv) = measure(signatures_classical.generate_keypair)
    sign_ms, sig = measure(lambda: signatures_classical.sign(priv, SAMPLE_MSG))
    verify_ms, _ = measure(lambda: signatures_classical.verify(pub, SAMPLE_MSG, sig))

    return {
        "name": "ECDSA P-256",
        "quantum_resistant": False,
        "nist_level": 3,
        "keygen_ms": keygen_ms,
        "sign_ms": sign_ms,
        "verify_ms": verify_ms,
        "pub_key_bytes": len(pub),
        "priv_key_bytes": len(priv),
        "sig_bytes": len(sig),
    }


def bench_mldsa():
    keygen_ms, (pub, priv) = measure(signatures_pq.generate_keypair)
    sign_ms, sig = measure(lambda: signatures_pq.sign(priv, SAMPLE_MSG))
    verify_ms, _ = measure(lambda: signatures_pq.verify(pub, SAMPLE_MSG, sig))

    return {
        "name": "ML-DSA-65",
        "quantum_resistant": True,
        "nist_level": 3,
        "keygen_ms": keygen_ms,
        "sign_ms": sign_ms,
        "verify_ms": verify_ms,
        "pub_key_bytes": len(pub),
        "priv_key_bytes": len(priv),
        "sig_bytes": len(sig),
    }


# ── printing ──────────────────────────────────────────────────────────────────

def _ms(v):
    return f"{v:.3f}" if v is not None else "N/A"

def _b(v):
    return str(v) if v is not None else "N/A"

def print_kem_table(ecdh, mlkem):
    ratio_pub  = mlkem["pub_key_bytes"]  / ecdh["pub_key_bytes"]
    ratio_priv = mlkem["priv_key_bytes"] / ecdh["priv_key_bytes"]

    print()
    print("=" * 66)
    print("  KEM COMPARISON  (N={} iterations, mean ms)".format(N))
    print("=" * 66)
    hdr = f"{'Metric':<30} {'ECDH P-256':>15} {'ML-KEM-768':>15}"
    print(hdr)
    print("-" * 66)
    rows = [
        ("Key generation (ms)",    _ms(ecdh["keygen_ms"]),   _ms(mlkem["keygen_ms"])),
        ("Encaps / Exchange (ms)",  _ms(ecdh["exchange_ms"]), _ms(mlkem["exchange_ms"])),
        ("Decaps (ms)",             _ms(ecdh["decaps_ms"]),   _ms(mlkem["decaps_ms"])),
        ("Public key (bytes)",      _b(ecdh["pub_key_bytes"]),  _b(mlkem["pub_key_bytes"])),
        ("Private key (bytes)",     _b(ecdh["priv_key_bytes"]), _b(mlkem["priv_key_bytes"])),
        ("Ciphertext (bytes)",      _b(ecdh["ciphertext_bytes"]),_b(mlkem["ciphertext_bytes"])),
        ("Shared secret (bytes)",   _b(ecdh["secret_bytes"]),  _b(mlkem["secret_bytes"])),
        ("NIST security level",     str(ecdh["nist_level"]),   str(mlkem["nist_level"])),
        ("Quantum-resistant",       "No",                       "Yes"),
    ]
    for label, a, b in rows:
        print(f"  {label:<28} {a:>15} {b:>15}")
    print("-" * 66)
    print(f"  {'Pub key size ratio':<28} {'1.0x':>15} {ratio_pub:>14.1f}x")
    print(f"  {'Priv key size ratio':<28} {'1.0x':>15} {ratio_priv:>14.1f}x")
    print("=" * 66)


def print_sig_table(ecdsa, mldsa):
    ratio_pub = mldsa["pub_key_bytes"] / ecdsa["pub_key_bytes"]
    ratio_sig = mldsa["sig_bytes"] / ecdsa["sig_bytes"]

    print()
    print("=" * 66)
    print("  SIGNATURE COMPARISON  (N={} iterations, mean ms)".format(N))
    print("=" * 66)
    print(f"{'Metric':<30} {'ECDSA P-256':>15} {'ML-DSA-65':>15}")
    print("-" * 66)
    rows = [
        ("Key generation (ms)",  _ms(ecdsa["keygen_ms"]),  _ms(mldsa["keygen_ms"])),
        ("Sign (ms)",            _ms(ecdsa["sign_ms"]),    _ms(mldsa["sign_ms"])),
        ("Verify (ms)",          _ms(ecdsa["verify_ms"]),  _ms(mldsa["verify_ms"])),
        ("Public key (bytes)",   _b(ecdsa["pub_key_bytes"]),  _b(mldsa["pub_key_bytes"])),
        ("Private key (bytes)",  _b(ecdsa["priv_key_bytes"]), _b(mldsa["priv_key_bytes"])),
        ("Signature (bytes)",    _b(ecdsa["sig_bytes"]),      _b(mldsa["sig_bytes"])),
        ("NIST security level",  str(ecdsa["nist_level"]),    str(mldsa["nist_level"])),
        ("Quantum-resistant",    "No",                         "Yes"),
    ]
    for label, a, b in rows:
        print(f"  {label:<28} {a:>15} {b:>15}")
    print("-" * 66)
    print(f"  {'Pub key size ratio':<28} {'1.0x':>15} {ratio_pub:>14.1f}x")
    print(f"  {'Sig size ratio':<28} {'1.0x':>15} {ratio_sig:>14.1f}x")
    print("=" * 66)
    print()


# ── charts ────────────────────────────────────────────────────────────────────

def _save_charts(ecdh, mlkem, ecdsa, mldsa, out_dir):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import matplotlib.patches as mpatches
    except ImportError:
        print("[benchmark] matplotlib not available — skipping charts")
        return

    colors = {"classical": "#4C72B0", "pq": "#DD8452"}

    # ── KEM timing chart ──────────────────────────────────────────────────────
    fig, axes = plt.subplots(1, 3, figsize=(12, 5))
    fig.suptitle("KEM Performance: ECDH P-256 vs ML-KEM-768", fontsize=14, fontweight="bold")

    metrics = [
        ("Key Generation", ecdh["keygen_ms"], mlkem["keygen_ms"]),
        ("Encapsulation / Exchange", ecdh["exchange_ms"], mlkem["exchange_ms"]),
        ("Decapsulation", 0, mlkem["decaps_ms"]),
    ]
    for ax, (title, a_val, b_val) in zip(axes, metrics):
        bars = ax.bar(["ECDH\nP-256", "ML-KEM\n768"],
                      [a_val or 0, b_val or 0],
                      color=[colors["classical"], colors["pq"]], width=0.5)
        ax.set_title(title, fontsize=10)
        ax.set_ylabel("Time (ms)")
        for bar, val in zip(bars, [a_val or 0, b_val or 0]):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.001,
                    f"{val:.3f}" if val else "N/A", ha="center", va="bottom", fontsize=8)
        ax.set_ylim(bottom=0)

    fig.tight_layout()
    path = os.path.join(out_dir, "benchmark_chart_kem_timing.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"[benchmark] saved {path}")

    # ── KEM key/ciphertext sizes ──────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(8, 5))
    fig.suptitle("KEM Key & Ciphertext Sizes (bytes)", fontsize=13, fontweight="bold")
    labels = ["Public Key", "Private Key", "Ciphertext"]
    ecdh_vals = [ecdh["pub_key_bytes"], ecdh["priv_key_bytes"], 0]
    mlkem_vals = [mlkem["pub_key_bytes"], mlkem["priv_key_bytes"], mlkem["ciphertext_bytes"]]
    x = range(len(labels))
    w = 0.35
    b1 = ax.bar([i - w/2 for i in x], ecdh_vals, w, label="ECDH P-256", color=colors["classical"])
    b2 = ax.bar([i + w/2 for i in x], mlkem_vals, w, label="ML-KEM-768", color=colors["pq"])
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels)
    ax.set_ylabel("Bytes")
    ax.legend()
    for bar in list(b1) + list(b2):
        h = bar.get_height()
        if h > 0:
            ax.text(bar.get_x() + bar.get_width()/2, h + 10, str(int(h)),
                    ha="center", va="bottom", fontsize=8)
    fig.tight_layout()
    path = os.path.join(out_dir, "benchmark_chart_kem_sizes.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"[benchmark] saved {path}")

    # ── Signature timing chart ────────────────────────────────────────────────
    fig, axes = plt.subplots(1, 3, figsize=(12, 5))
    fig.suptitle("Signature Performance: ECDSA P-256 vs ML-DSA-65", fontsize=14, fontweight="bold")
    sig_metrics = [
        ("Key Generation", ecdsa["keygen_ms"], mldsa["keygen_ms"]),
        ("Sign", ecdsa["sign_ms"], mldsa["sign_ms"]),
        ("Verify", ecdsa["verify_ms"], mldsa["verify_ms"]),
    ]
    for ax, (title, a_val, b_val) in zip(axes, sig_metrics):
        bars = ax.bar(["ECDSA\nP-256", "ML-DSA\n65"],
                      [a_val, b_val],
                      color=[colors["classical"], colors["pq"]], width=0.5)
        ax.set_title(title, fontsize=10)
        ax.set_ylabel("Time (ms)")
        for bar, val in zip(bars, [a_val, b_val]):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.001,
                    f"{val:.3f}", ha="center", va="bottom", fontsize=8)
        ax.set_ylim(bottom=0)
    fig.tight_layout()
    path = os.path.join(out_dir, "benchmark_chart_sig_timing.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"[benchmark] saved {path}")

    # ── Signature key/sig sizes ───────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(8, 5))
    fig.suptitle("Signature Key & Signature Sizes (bytes)", fontsize=13, fontweight="bold")
    labels = ["Public Key", "Private Key", "Signature"]
    ecdsa_vals = [ecdsa["pub_key_bytes"], ecdsa["priv_key_bytes"], ecdsa["sig_bytes"]]
    mldsa_vals = [mldsa["pub_key_bytes"], mldsa["priv_key_bytes"], mldsa["sig_bytes"]]
    x = range(len(labels))
    b1 = ax.bar([i - w/2 for i in x], ecdsa_vals, w, label="ECDSA P-256", color=colors["classical"])
    b2 = ax.bar([i + w/2 for i in x], mldsa_vals, w, label="ML-DSA-65", color=colors["pq"])
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels)
    ax.set_ylabel("Bytes")
    ax.legend()
    for bar in list(b1) + list(b2):
        h = bar.get_height()
        if h > 0:
            ax.text(bar.get_x() + bar.get_width()/2, h + 10, str(int(h)),
                    ha="center", va="bottom", fontsize=8)
    fig.tight_layout()
    path = os.path.join(out_dir, "benchmark_chart_sig_sizes.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"[benchmark] saved {path}")


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    print(f"\nRunning benchmarks (N={N} iterations each) ...")

    print("  [1/4] ECDH P-256 ...", end=" ", flush=True)
    ecdh = bench_ecdh()
    print("done")

    print("  [2/4] ML-KEM-768 ...", end=" ", flush=True)
    mlkem = bench_mlkem()
    print("done")

    print("  [3/4] ECDSA P-256 ...", end=" ", flush=True)
    ecdsa = bench_ecdsa()
    print("done")

    print("  [4/4] ML-DSA-65 ...", end=" ", flush=True)
    mldsa = bench_mldsa()
    print("done")

    print_kem_table(ecdh, mlkem)
    print_sig_table(ecdsa, mldsa)

    out_dir = os.path.dirname(__file__)
    results = {"n_iterations": N, "kem": {"ecdh": ecdh, "mlkem": mlkem},
               "signatures": {"ecdsa": ecdsa, "mldsa": mldsa}}
    json_path = os.path.join(out_dir, "benchmark_results.json")
    with open(json_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[benchmark] results saved to {json_path}")

    _save_charts(ecdh, mlkem, ecdsa, mldsa, out_dir)


if __name__ == "__main__":
    main()
