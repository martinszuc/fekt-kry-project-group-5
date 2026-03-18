"""
Bob instance — port 5002.
Flask app with UI and API stubs for crypto operations.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from flask import Flask, render_template, request, jsonify
from config import BOB_PORT, KEM_OPTIONS, SIGNATURE_OPTIONS, SYMMETRIC_OPTIONS, ALICE_URL
from src.utils.logger import log_event, get_log_entries

app = Flask(__name__, template_folder="templates", static_folder="../static")
app.config["ROLE"] = "bob"
app.config["PEER_URL"] = ALICE_URL

SESSION = {"established": False, "kem": None, "sig": None, "symmetric": None}


@app.route("/")
def index():
    return render_template(
        "index.html",
        role="bob",
        role_label="Bob",
        kem_options=KEM_OPTIONS,
        sig_options=SIGNATURE_OPTIONS,
        sym_options=SYMMETRIC_OPTIONS,
    )


@app.route("/api/status")
def status():
    return jsonify({
        "role": "bob",
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

    SESSION["kem"] = kem
    SESSION["sig"] = sig
    SESSION["symmetric"] = symmetric
    SESSION["established"] = False

    log_event("handshake_respond", algorithm=f"{kem}+{sig}", result="PENDING")
    return jsonify({
        "ok": True,
        "message": "Handshake response (crypto not yet implemented)",
        "session_established": False,
    })


@app.route("/api/send", methods=["POST"])
def send():
    data = request.get_json() or {}
    message = data.get("message", "")

    if not SESSION["established"]:
        return jsonify({"ok": False, "error": "No active session. Initiate handshake first."}), 400

    log_event("message_sent", data_size=len(message), result="PENDING")
    return jsonify({"ok": True, "message": "Send not implemented yet"})


@app.route("/api/receive")
def receive():
    return jsonify({"messages": []})


@app.route("/api/logs")
def logs():
    return jsonify({"entries": get_log_entries()})


def main():
    log_event("app_start", result="OK")
    app.run(host="0.0.0.0", port=BOB_PORT, debug=True)


if __name__ == "__main__":
    main()
