"""
Bob instance — port 5002.
Flask app with UI and API stubs for crypto operations.
"""

import sys
import os
import json
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from flask import Flask, render_template, request, jsonify
from config import BOB_PORT, KEM_OPTIONS, SIGNATURE_OPTIONS, SYMMETRIC_OPTIONS, ALICE_URL
from src.utils.logger import log_event, get_log_entries
from src.crypto.handshake import bob_server_hello, bob_finish
from src.crypto.transfer import send_message, receive_message

app = Flask(__name__, template_folder="templates", static_folder="../static")
app.config["ROLE"] = "bob"
app.config["PEER_URL"] = ALICE_URL

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
    phase = data.get("phase")

    # Phase 2: handle Alice ClientHello (Bob acts as responder)
    if phase == "client_hello":
        try:
            b_state, server_hello = bob_server_hello(data)
            SESSION["kem"] = server_hello.get("kem")
            SESSION["sig"] = server_hello.get("sig")
            SESSION["symmetric"] = server_hello.get("symmetric")
            SESSION["session_key"] = b_state.session_key
            SESSION["my_sig_priv"] = b_state.sig_private_key
            SESSION["my_sig_pub"] = b_state.sig_public_key
            SESSION["established"] = False
            log_event("handshake_respond", algorithm=f"{SESSION['kem']}+{SESSION['sig']}", result="OK")
            return jsonify(server_hello)
        except Exception as e:
            log_event("handshake_failed", algorithm=f"{data.get('kem')}+{data.get('sig')}", result="FAIL")
            return jsonify({"ok": False, "error": str(e)}), 400

    # Phase 3: receive Alice signing public key
    if phase == "finish":
        try:
            # Reconstruct minimal state for bob_finish (we keep session_key separately)
            from src.crypto.handshake import BobHandshakeState  # local import to avoid circulars

            tmp_state = BobHandshakeState(
                kem_private_key=b"",
                kem_public_key=b"",
                sig_private_key=SESSION["my_sig_priv"],
                sig_public_key=SESSION["my_sig_pub"],
                symmetric_algo=SESSION["symmetric"],
                session_key=SESSION["session_key"],
            )
            alice_sig_pub = bob_finish(tmp_state, data)
            SESSION["peer_sig_pub"] = alice_sig_pub
            SESSION["established"] = True
            log_event("handshake_complete", algorithm=f"{SESSION['kem']}+{SESSION['sig']}+{SESSION['symmetric']}", result="OK")
            return jsonify({"ok": True})
        except Exception as e:
            log_event("handshake_failed", algorithm=f"{SESSION.get('kem')}+{SESSION.get('sig')}", result="FAIL")
            return jsonify({"ok": False, "error": str(e)}), 400

    # If user clicks handshake button on Bob UI, act as initiator (send to Alice)
    kem = data.get("kem", "mlkem")
    sig = data.get("sig", "mldsa")
    symmetric = data.get("symmetric", "aes_gcm")
    if kem not in ("ecdh", "mlkem"):
        return jsonify({"ok": False, "error": "Unsupported KEM algorithm", }), 400
    if sig not in ("ecdsa", "mldsa"):
        return jsonify({"ok": False, "error": "Unsupported signature algorithm"}), 400
    if symmetric not in ("aes_gcm", "chacha20"):
        return jsonify({"ok": False, "error": "Unsupported symmetric algorithm"}), 400

    try:
        # Import here to reuse Alice initiator logic without duplicating code
        from src.crypto.handshake import alice_client_hello, alice_finish

        a_state, hello = alice_client_hello(kem_algo=kem, sig_algo=sig, symmetric_algo=symmetric)
        log_event("handshake_init", algorithm=f"{kem}+{sig}", result="OK")
        server_hello = _post_json(app.config["PEER_URL"], "/api/handshake", hello)
        (
            session_key,
            bob_sig_pub,
            bob_sig_priv,
            alice_sig_pub,
            finish_msg,
        ) = alice_finish(a_state, server_hello)
        finish_resp = _post_json(app.config["PEER_URL"], "/api/handshake", finish_msg)
        if finish_resp.get("ok") is False:
            raise ValueError(finish_resp.get("error", "finish failed"))

        SESSION["kem"] = kem
        SESSION["sig"] = sig
        SESSION["symmetric"] = symmetric
        SESSION["session_key"] = session_key
        SESSION["my_sig_priv"] = bob_sig_priv
        SESSION["my_sig_pub"] = bob_sig_pub
        SESSION["peer_sig_pub"] = alice_sig_pub
        SESSION["established"] = True
        log_event("handshake_complete", algorithm=f"{kem}+{sig}+{symmetric}", result="OK")
        return jsonify({"ok": True, "message": "Handshake complete. Secure session established.", "session_established": True})
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
        )
        resp = _post_json(app.config["PEER_URL"], "/api/incoming", payload)
        if resp.get("ok") is not True:
            raise ValueError(resp.get("error", "peer rejected message"))

        SESSION["messages"].append({"from": "me", "text": str(message)})
        log_event("message_sent", algorithm=f"{SESSION['symmetric']}+{SESSION['sig']}", data_size=len(message), result="OK")
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
        pt = receive_message(SESSION["session_key"], SESSION["peer_sig_pub"], payload)
        text = pt.decode("utf-8", errors="replace")
        SESSION["messages"].append({"from": "peer", "text": text})
        log_event("message_received", algorithm=f"{SESSION['symmetric']}+{SESSION['sig']}", data_size=len(pt), result="OK")
        return jsonify({"ok": True})
    except Exception as e:
        log_event("message_receive_failed", algorithm=f"{SESSION.get('symmetric')}+{SESSION.get('sig')}", result="FAIL")
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/logs")
def logs():
    return jsonify({"entries": get_log_entries()})


def main():
    log_event("app_start", result="OK")
    app.run(host="0.0.0.0", port=BOB_PORT, debug=True)


if __name__ == "__main__":
    main()
