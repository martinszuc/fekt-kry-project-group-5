import sys
import os
import json
import urllib.request
import socket
from flask import Flask, render_template, request, jsonify, abort

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from config import BOB_PORT, ALICE_PORT, KEM_OPTIONS, SIGNATURE_OPTIONS, SYMMETRIC_OPTIONS
from src.utils.logger import log_event, get_log_entries
from src.crypto.handshake import bob_server_hello, bob_finish, alice_client_hello, alice_finish, BobHandshakeState
from src.crypto.transfer import send_message, receive_message

app = Flask(__name__, template_folder="templates", static_folder="../static")
app.config["ROLE"] = "bob"

SESSION = {
    "established": False, "kem": None, "sig": None, "symmetric": None,
    "session_key": None, "my_sig_priv": None, "my_sig_pub": None,
    "peer_sig_pub": None, "peer_url": None, "messages": [],
}

IS_DOCKER = (os.environ.get('DOCKER_CONTAINER') and True) or False
print("Bob. IS_DOCKER", IS_DOCKER)


def get_peer_internal_ip():
    if not IS_DOCKER: return "127.0.0.1"
    try:
        peer_name = "alice"  # Bob's peer is always alice
        return socket.gethostbyname(peer_name)
    except:
        return "127.0.0.1"


def get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"


def get_authorized_ips():
    authorized = {'127.0.0.1', 'localhost', get_lan_ip()}

    if IS_DOCKER:
        try:
            my_ip = socket.gethostbyname(socket.gethostname())
            gateway_ip = '.'.join(my_ip.split('.')[:-1]) + '.1'
            authorized.add(gateway_ip)

            peer_name = "bob" if app.config["ROLE"] == "alice" else "alice"
            authorized.add(socket.gethostbyname(peer_name))
        except:
            pass
    return authorized


WHITELIST = get_authorized_ips()


@app.before_request
def limit_remote_addr():
    public_endpoints = ['index', 'status', 'handshake', 'incoming', 'static']
    if request.endpoint in public_endpoints: return

    clean_ip = (request.remote_addr or "").replace('::ffff:', '')

    if clean_ip not in WHITELIST and not clean_ip.startswith('172.'):
        log_event("unauthorized_access_attempt", result="BLOCKED", detail=f"IP: {clean_ip}")
        abort(403)


def _post_json(url: str, path: str, payload: dict) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url=f"{url}{path}", data=data,
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


@app.route("/")
def index():
    return render_template(
        "index.html",
        role="bob", role_label="Bob",
        kem_options=KEM_OPTIONS, sig_options=SIGNATURE_OPTIONS, sym_options=SYMMETRIC_OPTIONS,
        peer_internal_ip=get_peer_internal_ip(),
        local_ip=get_lan_ip(),
        my_port=BOB_PORT, peer_port=ALICE_PORT, IS_DOCKER=IS_DOCKER
    )


@app.route("/api/status")
def status():
    return jsonify({
        "role": app.config["ROLE"],
        "session_established": SESSION["established"],
        "peer_url": SESSION.get("peer_url"),
        "algorithms": {"kem": SESSION.get("kem"), "sig": SESSION.get("sig"), "symmetric": SESSION.get("symmetric")}
    })


def reset_session():
    SESSION.update({
        "established": False,
        "kem": None,
        "sig": None,
        "symmetric": None,
        "session_key": None,
        "my_sig_priv": None,
        "my_sig_pub": None,
        "peer_sig_pub": None,
        "peer_url": None
    })
    log_event("session_reset", result="DISCONNECTED", detail="Handshake failure or manual reset")


@app.route("/api/handshake", methods=["POST"])
def handshake():
    data = request.get_json() or {}
    phase = data.get("phase")

    if phase == "client_hello":
        try:
            b_state, server_hello = bob_server_hello(data)

            peer_ip = request.remote_addr.replace('::ffff:', '')
            peer_port = ALICE_PORT if app.config["ROLE"] == "bob" else BOB_PORT

            SESSION["peer_url"] = f"http://{peer_ip}:{peer_port}"

            SESSION.update({
                "kem": server_hello.get("kem"), "sig": server_hello.get("sig"),
                "symmetric": server_hello.get("symmetric"),
                "session_key": b_state.session_key, "my_sig_priv": b_state.sig_private_key,
                "my_sig_pub": b_state.sig_public_key, "established": False
            })
            return jsonify(server_hello)
        except Exception as e:
            reset_session()
            return jsonify({"ok": False, "error": f"Client Hello Error: {str(e)}"}), 400

    if phase == "finish":
        try:
            tmp_state = BobHandshakeState(b"", b"", SESSION["my_sig_priv"], SESSION["my_sig_pub"], SESSION["symmetric"],
                                          SESSION["session_key"])
            SESSION["peer_sig_pub"] = bob_finish(tmp_state, data)
            SESSION["established"] = True
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 400

    kem, sig, symmetric, target_url = data.get("kem"), data.get("sig"), data.get("symmetric"), data.get("peer_url")
    try:
        a_state, hello = alice_client_hello(kem_algo=kem, sig_algo=sig, symmetric_algo=symmetric)
        server_hello = _post_json(target_url, "/api/handshake", hello)
        (session_key, my_sig_pub, my_sig_priv, peer_sig_pub, finish_msg) = alice_finish(a_state, server_hello)
        _post_json(target_url, "/api/handshake", finish_msg)
        SESSION.update({
            "kem": kem, "sig": sig, "symmetric": symmetric, "session_key": session_key,
            "my_sig_priv": my_sig_priv, "my_sig_pub": my_sig_pub, "peer_sig_pub": peer_sig_pub,
            "peer_url": target_url, "established": True
        })
        return jsonify({"ok": True, "message": "Handshake complete."})
    except Exception as e:
        reset_session()
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/send", methods=["POST"])
def send():
    data = request.get_json() or {}
    message, target = data.get("message", ""), SESSION.get("peer_url")
    if not SESSION["established"] or not target: return jsonify({"ok": False, "error": "No session"}), 400
    try:
        payload = send_message(SESSION["session_key"], SESSION["my_sig_priv"], message, SESSION["symmetric"],
                               SESSION["sig"])
        _post_json(target, "/api/incoming", payload)
        SESSION["messages"].append({"from": "me", "text": str(message)})
        return jsonify({"ok": True})
    except Exception as e:
        reset_session()
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/incoming", methods=["POST"])
def incoming():
    if not SESSION["established"]: return jsonify({"ok": False}), 400
    try:
        pt = receive_message(SESSION["session_key"], SESSION["peer_sig_pub"], request.get_json(), SESSION["sig"])
        SESSION["messages"].append({"from": "peer", "text": pt.decode("utf-8")})
        return jsonify({"ok": True})
    except:
        reset_session()
        return jsonify({"ok": False}), 400


@app.route("/api/receive")
def receive(): return jsonify({"messages": list(reversed(SESSION["messages"]))})


@app.route("/api/logs")
def logs(): return jsonify({"entries": get_log_entries()})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=BOB_PORT, debug=True)
