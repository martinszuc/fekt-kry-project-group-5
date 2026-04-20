"""
Alice instance — port 5001.
Flask app with UI and API stubs for crypto operations.
"""

import sys
import os
import json
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from flask import Flask, render_template, request, jsonify
from config import ALICE_PORT, KEM_OPTIONS, SIGNATURE_OPTIONS, SYMMETRIC_OPTIONS, BOB_URL
from src.utils.logger import log_event, get_log_entries
from src.crypto.handshake import alice_client_hello, alice_finish, bob_server_hello, bob_finish, BobHandshakeState
from src.crypto.transfer import send_message, receive_message

app = Flask(__name__, template_folder="templates", static_folder="../static")
app.config["ROLE"] = "alice"
app.config["PEER_URL"] = BOB_URL

SESSION = {
    "established": False,
    "kem": None,
    "sig": None,
    "symmetric": None,
    "session_key": None,
    "my_sig_priv": None,
    "my_sig_pub": None,
    "peer_sig_pub": None,
    "messages": [],
}


def _post_json(url: str, path: str, payload: dict) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url=f"{url}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


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
    phase = data.get("phase")

    # --- 1. RESPONDER LOGIC (When Bob initiates to Alice) ---
    if phase == "client_hello":
        try:
            b_state, server_hello = bob_server_hello(data)

            # Store the responder state in Alice's session
            SESSION.update({
                "kem": server_hello.get("kem"),
                "sig": server_hello.get("sig"),
                "symmetric": server_hello.get("symmetric"),
                "session_key": b_state.session_key,
                "my_sig_priv": b_state.sig_private_key,
                "my_sig_pub": b_state.sig_public_key,
                "established": False
            })
            log_event("handshake_respond", algorithm=f"{SESSION['kem']}+{SESSION['sig']}", result="OK")
            return jsonify(server_hello)
        except Exception as e:
            log_event("handshake_failed", algorithm=f"{data.get('kem')}+{data.get('sig')}", result="FAIL")
            return jsonify({"ok": False, "error": str(e)}), 400

    if phase == "finish":
        try:
            # Reconstruct responder state to verify peer's finish
            tmp_state = BobHandshakeState(
                kem_private_key=b"", kem_public_key=b"",
                sig_private_key=SESSION["my_sig_priv"],
                sig_public_key=SESSION["my_sig_pub"],
                symmetric_algo=SESSION["symmetric"],
                session_key=SESSION["session_key"],
            )
            peer_sig_pub = bob_finish(tmp_state, data)
            SESSION["peer_sig_pub"] = peer_sig_pub
            SESSION["established"] = True
            log_event("handshake_complete", result="OK")
            return jsonify({"ok": True})
        except Exception as e:
            log_event("handshake_failed", algorithm=f"{SESSION.get('kem')}+{SESSION.get('sig')}", result="FAIL")
            return jsonify({"ok": False, "error": str(e)}), 400

    # --- 2. INITIATOR LOGIC (When Alice clicks the button) ---
    # (The code below only runs if Alice is the one starting the handshake)
    kem = data.get("kem", "mlkem")
    sig = data.get("sig", "mldsa")
    symmetric = data.get("symmetric", "aes_gcm")

    try:
        # Generate ClientHello
        a_state, hello = alice_client_hello(kem_algo=kem, sig_algo=sig, symmetric_algo=symmetric)
        log_event("handshake_init", algorithm=f"{kem}+{sig}", result="OK")

        # Send to Bob and get his ServerHello
        server_hello = _post_json(app.config["PEER_URL"], "/api/handshake", hello)

        # This is where Bob was failing before because Alice wasn't returning a server_hello
        if not server_hello.get("phase") == "server_hello":
            raise ValueError(f"Expected server_hello, got: {server_hello}")

        # Process ServerHello
        (
            session_key,
            my_sig_pub,
            my_sig_priv,
            peer_sig_pub,
            finish_msg,
        ) = alice_finish(a_state, server_hello)

        # Send Finish to Bob
        finish_resp = _post_json(app.config["PEER_URL"], "/api/handshake", finish_msg)
        if not finish_resp.get("ok"):
            raise ValueError("Peer rejected finish")

        SESSION.update({
            "kem": kem, "sig": sig, "symmetric": symmetric,
            "session_key": session_key,
            "my_sig_priv": my_sig_priv, "my_sig_pub": my_sig_pub,
            "peer_sig_pub": peer_sig_pub, "established": True
        })

        return jsonify({"ok": True, "message": "Handshake complete.", "session_established": True})
    except Exception as e:
        SESSION["established"] = False
        log_event("handshake_failed", algorithm=f"{kem}+{sig}", result="FAIL")
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/send", methods=["POST"])
def send():
    data = request.get_json() or {}
    message = data.get("message", "")

    if not SESSION["established"]:
        return jsonify({"ok": False, "error": "No active session. Initiate handshake first."}), 400

    try:
        payload = send_message(
            SESSION["session_key"],
            SESSION["my_sig_priv"],
            message,
            SESSION["symmetric"],
            SESSION["sig"],
        )
        resp = _post_json(app.config["PEER_URL"], "/api/incoming", payload)
        if resp.get("ok") is not True:
            raise ValueError(resp.get("error", "peer rejected message"))

        SESSION["messages"].append({"from": "me", "text": str(message)})
        log_event("message_sent", algorithm=f"{SESSION['symmetric']}+{SESSION['sig']}", data_size=len(message),
                  result="OK")
        return jsonify({"ok": True, "message": "Message sent securely."})
    except Exception as e:
        log_event("message_send_failed", algorithm=f"{SESSION.get('symmetric')}+{SESSION.get('sig')}", result="FAIL")
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/receive")
def receive():
    return jsonify({"messages": list(reversed(SESSION["messages"]))})


@app.route("/api/incoming", methods=["POST"])
def incoming():
    if not SESSION["established"]:
        return jsonify({"ok": False, "error": "No active session"}), 400

    payload = request.get_json() or {}
    try:
        pt = receive_message(SESSION["session_key"], SESSION["peer_sig_pub"], payload, SESSION["sig"])
        text = pt.decode("utf-8", errors="replace")
        SESSION["messages"].append({"from": "peer", "text": text})
        log_event("message_received", algorithm=f"{SESSION['symmetric']}+{SESSION['sig']}", data_size=len(pt),
                  result="OK")
        return jsonify({"ok": True})
    except Exception as e:
        log_event("message_receive_failed", algorithm=f"{SESSION.get('symmetric')}+{SESSION.get('sig')}", result="FAIL")
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/logs")
def logs():
    return jsonify({"entries": get_log_entries()})


def main():
    log_event("app_start", result="OK")
    app.run(host="0.0.0.0", port=ALICE_PORT, debug=True)


if __name__ == "__main__":
    main()
