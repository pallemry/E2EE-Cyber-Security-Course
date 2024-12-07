import socket
import threading
import json
import uuid
import os
import hmac
import hashlib
import random
import time
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = '127.0.0.1'
PORT = 5000

data_lock = threading.Lock()

server_long_term_private = x25519.X25519PrivateKey.generate()
server_long_term_public = server_long_term_private.public_key()

registered_clients = {}
stored_messages = {}

client_otps = {}
session_keys = {}  # {client_id: session_key for encryption after finalize_registration}

OTP_LIFETIME = 120  # OTP valid for 120 seconds (2 minutes)

def hkdf_derive(secret, salt, info=b"E2EE"):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info
    ).derive(secret)

def recv_plain_msg(sock):
    length_bytes = sock.recv(4)
    if not length_bytes:
        return None
    msg_len = int.from_bytes(length_bytes, 'big')
    data = sock.recv(msg_len)
    if not data:
        return None
    return json.loads(data.decode('utf-8'))

def send_plain_msg(sock, msg):
    encoded = json.dumps(msg).encode('utf-8')
    sock.send(len(encoded).to_bytes(4, 'big') + encoded)

def recv_encrypted_msg(sock, session_key):
    length_bytes = sock.recv(4)
    if not length_bytes:
        return None
    msg_len = int.from_bytes(length_bytes, 'big')
    data = sock.recv(msg_len)
    if not data:
        return None
    enc_msg = json.loads(data.decode('utf-8'))
    iv = bytes.fromhex(enc_msg["iv"])
    ciphertext = bytes.fromhex(enc_msg["ciphertext"])
    aesgcm = AESGCM(session_key)
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    return json.loads(plaintext.decode('utf-8'))

def send_encrypted_msg(sock, msg, session_key):
    plaintext = json.dumps(msg).encode('utf-8')
    aesgcm = AESGCM(session_key)
    iv = os.urandom(12)
    ciphertext = aesgcm.encrypt(iv, plaintext, None)

    enc_msg = {
        "iv": iv.hex(),
        "ciphertext": ciphertext.hex()
    }
    encoded = json.dumps(enc_msg).encode('utf-8')
    sock.send(len(encoded).to_bytes(4, 'big') + encoded)

def is_otp_valid(client_id):
    data = client_otps.get(client_id)
    if not data:
        return False
    if (time.time() - data["timestamp"]) > OTP_LIFETIME:
        return False
    return True

def process_request(req, client_id):
    req_type = req.get("type")

    # Requests before finalize_registration are plaintext:
    # REQUEST_OTP, FETCH_SERVER_KEY, REGISTER, FINALIZE_REGISTRATION
    # After that, requests should be encrypted if session_key exists.

    if req_type == "REQUEST_OTP":
        otp_str = f"{random.randint(0,999999):06d}"
        otp_bytes = otp_str.encode('utf-8')
        with data_lock:
            client_otps[client_id] = {
                "otp": otp_bytes,
                "timestamp": time.time()
            }
        print(f"[SecureChannel]: OTP for {client_id} is {otp_str}")
        return {"status": "otp_provided", "otp": otp_str}, False

    elif req_type == "FETCH_SERVER_KEY":
        with data_lock:
            otp_data = client_otps.get(client_id)
        if not otp_data or not is_otp_valid(client_id):
            return {"status":"error","error":"otp_expired_or_invalid"}, False
        otp = otp_data["otp"]
        response = {
            "type":"SERVER_KEY_RESPONSE",
            "server_long_term_pub": server_long_term_public.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        }
        mac = hmac.new(otp, response["server_long_term_pub"].encode('utf-8'), hashlib.sha256).digest()
        response["mac_hex"] = mac.hex()
        return response, False

    elif req_type == "REGISTER":
        with data_lock:
            otp_data = client_otps.get(client_id)
        if not otp_data or not is_otp_valid(client_id):
            return {"status":"error","error":"otp_expired_or_invalid"}, False

        otp = otp_data["otp"]
        client_eph_pub_hex = req["client_eph_pub"]
        given_mac_hex = req["mac_hex"]

        to_mac = {
            "type":"REGISTER",
            "client_id":client_id,
            "client_eph_pub":client_eph_pub_hex
        }
        mac_check = hmac.new(otp, json.dumps(to_mac).encode('utf-8'), hashlib.sha256).digest()
        if not hmac.compare_digest(mac_check, bytes.fromhex(given_mac_hex)):
            return {"status":"error","error":"MAC_verification_failed"}, False

        client_eph_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(client_eph_pub_hex))
        server_eph_priv = x25519.X25519PrivateKey.generate()
        server_eph_pub = server_eph_priv.public_key()

        shared_secret = server_eph_priv.exchange(client_eph_pub)
        session_key = hkdf_derive(shared_secret, otp)

        # Store session_key temporarily, final after finalize
        # Actually let's store it now, we trust the ephemeral step.
        with data_lock:
            session_keys[client_id] = session_key

        resp = {
            "type":"REGISTER_RESPONSE",
            "server_eph_pub": server_eph_pub.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        }
        mac_resp = hmac.new(otp, json.dumps(resp).encode('utf-8'), hashlib.sha256).digest()
        resp["mac_hex"] = mac_resp.hex()
        return resp, False

    elif req_type == "FINALIZE_REGISTRATION":
        identity_pub_hex = req["identity_pub"]
        pre_keys_hex = req["pre_keys"]

        identity_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(identity_pub_hex))
        pre_keys = [x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(k)) for k in pre_keys_hex]

        with data_lock:
            registered_clients[client_id] = {
                "identity_pub": identity_pub,
                "pre_keys": pre_keys,
                "delivered_updates": []
            }
            if client_id in client_otps:
                del client_otps[client_id]

        return {"status":"ok"}, True

    # From here on, the request should be encrypted if we have a session_key and client is finalized.
    # If session_key not found or not registered, return error.
    with data_lock:
        if client_id not in registered_clients:
            return {"status":"error","error":"not_registered"}, False
        if client_id not in session_keys:
            return {"status":"error","error":"no_session_key"}, False

    # Encrypted requests:
    if req_type == "FETCH_KEYS":
        target_id = req["target_id"]
        with data_lock:
            target_data = registered_clients.get(target_id)
            if not target_data or not target_data["pre_keys"]:
                return {"status":"error","error":"target_not_available_or_no_pre_keys"}, True

            chosen_pre_key = target_data["pre_keys"].pop(0)
            identity_pub = target_data["identity_pub"]

        return {
            "status":"ok",
            "B_identity_pub": identity_pub.public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
            "B_one_time_pub": chosen_pre_key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
            "one_time_key_id":"0"
        }, True

    elif req_type == "SEND_MESSAGE":
        recipient = req["recipient_id"]
        msg_data = {
            "sender_id": req["sender_id"],
            "A_ephemeral_pub": req["A_ephemeral_pub"],
            "B_one_time_key_id": req["B_one_time_key_id"],
            "iv": req["iv"],
            "ciphertext": req["ciphertext"]
        }
        message_id = str(uuid.uuid4())
        with data_lock:
            if recipient not in stored_messages:
                stored_messages[recipient] = []
            stored_messages[recipient].append((message_id, msg_data))

        return {"status":"message_stored","message_id":message_id}, True

    elif req_type == "RETRIEVE_MESSAGES":
        with data_lock:
            msgs = stored_messages.get(client_id, [])
            stored_messages[client_id] = []
        out_msgs = []
        for mid, md in msgs:
            out_msgs.append({
                "message_id": mid,
                "sender_id": md["sender_id"],
                "A_ephemeral_pub": md["A_ephemeral_pub"],
                "B_one_time_key_id": md["B_one_time_key_id"],
                "iv": md["iv"],
                "ciphertext": md["ciphertext"]
            })
        return {"status":"ok","messages": out_msgs}, True

    elif req_type == "GET_DELIVERY_UPDATES":
        with data_lock:
            updates = registered_clients[client_id]["delivered_updates"]
            registered_clients[client_id]["delivered_updates"] = []
        return {"status":"ok","delivered_message_ids": updates}, True

    else:
        return {"status":"error","error":"unknown_request"}, False

def handle_client_connection(client_socket, client_address):
    print(f"[+] New connection from {client_address}")
    client_id = None
    # client_id known after first request that includes client_id.

    # We'll handle the logic:
    # 1) For initial requests (register steps), receive plaintext.
    # 2) After finalize, requests come encrypted.
    # We'll guess if encrypted or not by checking if client_id is known and session_key is available.
    # Actually, we must read plaintext first to get client_id from initial requests.

    try:
        while True:
            # We need to know if we should decrypt or read plaintext
            # If we have session_key and registered, read encrypted else plaintext
            # But what if we don't know yet?
            # We'll attempt plaintext first. If after finalize we must do encrypted.
            # We'll store a flag: after finalize -> encrypted.

            # Let's store a flag after finalize:
            if client_id in registered_clients and client_id in session_keys:
                # Encrypted phase
                req = recv_encrypted_msg(client_socket, session_keys[client_id])
            else:
                # Plaintext phase
                req = recv_plain_msg(client_socket)

            if req is None:
                break

            # Extract client_id from request if available
            if "client_id" in req:
                # Once known, store it
                if client_id is None:
                    client_id = req["client_id"]

            response, encrypt_response = process_request(req, client_id)

            if encrypt_response and client_id in session_keys:
                send_encrypted_msg(client_socket, response, session_keys[client_id])
            else:
                send_plain_msg(client_socket, response)

    except Exception as e:
        print(f"Error handling client {client_address}: {e}")
    finally:
        client_socket.close()
        print(f"[-] Connection closed for {client_address}")

def cleanup_last_run():
    # delete all json files starting with client_state
    for f in os.listdir():
        if f.startswith("client_state") and f.endswith(".json"):
            os.remove(f)

def start_server():
    cleanup_last_run()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print(f"Server listening on {HOST}:{PORT}")

    while True:
        client_socket, client_address = server_socket.accept()
        client_thread = threading.Thread(target=handle_client_connection, args=(client_socket, client_address))
        client_thread.daemon = True
        client_thread.start()

if __name__ == "__main__":
    start_server()
