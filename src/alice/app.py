"""
Alice instance — port 5001.
Flask app with UI and API stubs for crypto operations.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from flask import Flask, render_template, request, jsonify
from config import ALICE_PORT, KEM_OPTIONS, SIGNATURE_OPTIONS, SYMMETRIC_OPTIONS, BOB_URL
from src.utils.logger import log_event, get_log_entries

app = Flask(__name__, template_folder="templates", static_folder="../static")
app.config["ROLE"] = "alice"
app.config["PEER_URL"] = BOB_URL

SESSION = {"established": False, "kem": None, "sig": None, "symmetric": None}


@app.route("/")
def index():
    return render_template(
        "index.html",
        role="alice",
        role_label="Alice",
        kem_options=KEM_OPTIONS,
        sig_options=SIGNATURE_OPTIONS,
        sym_options=SYMMETRIC_OPTIONS,
    )


@app.route("/api/status")
def status():
    return jsonify({
        "role": "alice",
        "session_established": SESSION["established"],
        "algorithms": {
            "kem": SESSION.get("kem"),
            "sig": SESSION.get("sig"),
            "symmetric": SESSION.get("symmetric"),
        },
    })


@app.route("/api/handshake", methods=["POST"])
def handshake():
    data = request.get_json() or {}
    kem = data.get("kem", "mlkem")
    sig = data.get("sig", "mldsa")
    symmetric = data.get("symmetric", "aes_gcm")

    # placeholder until Chunk 8 — just mark session as "attempted" for demo
    SESSION["kem"] = kem
    SESSION["sig"] = sig
    SESSION["symmetric"] = symmetric
    SESSION["established"] = False  # real handshake will set True

    log_event("handshake_init", algorithm=f"{kem}+{sig}", result="PENDING")
    return jsonify({
        "ok": True,
        "message": "Handshake initiated (crypto not yet implemented)",
        "session_established": False,
    })


@app.route("/api/send", methods=["POST"])
def send():
    data = request.get_json() or {}
    message = data.get("message", "")

    if not SESSION["established"]:
        return jsonify({"ok": False, "error": "No active session. Initiate handshake first."}), 400

    # placeholder until Chunk 9
    log_event("message_sent", data_size=len(message), result="PENDING")
    return jsonify({"ok": True, "message": "Send not implemented yet"})


@app.route("/api/receive")
def receive():
    # placeholder until Chunk 9
    return jsonify({"messages": []})


@app.route("/api/logs")
def logs():
    return jsonify({"entries": get_log_entries()})


def main():
    log_event("app_start", result="OK")
    app.run(host="0.0.0.0", port=ALICE_PORT, debug=True)


if __name__ == "__main__":
    main()
