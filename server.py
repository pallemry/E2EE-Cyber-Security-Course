import socket
import threading
import json
import uuid
import os
import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HOST = '127.0.0.1'
PORT = 5000

data_lock = threading.Lock()

# server long-term key
server_long_term_private = x25519.X25519PrivateKey.generate()
server_long_term_public = server_long_term_private.public_key()

# Client data structures:
# registered_clients = {
#   client_id: {
#       "identity_pub": X25519PublicKey,
#       "pre_keys": [X25519PublicKey,...],
#       "delivered_updates": []
#   }
# }
registered_clients = {}

# stored_messages = {recipient_id: [(message_id, msg_data)]}
# msg_data contains: sender_id, A_ephemeral_pub, B_one_time_key_id, iv, ciphertext
stored_messages = {}

# OTP tracking: {client_id: otp_bytes}
client_otps = {}

def hkdf_derive(secret, salt, info=b"E2EE"):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info
    ).derive(secret)

def recv_message(sock):
    length_bytes = sock.recv(4)
    if not length_bytes:
        return None
    msg_len = int.from_bytes(length_bytes, 'big')
    data = sock.recv(msg_len)
    if not data:
        return None
    return json.loads(data.decode('utf-8'))

def send_message(sock, msg):
    encoded = json.dumps(msg).encode('utf-8')
    sock.send(len(encoded).to_bytes(4, 'big') + encoded)

def process_request(request):
    req_type = request.get("type")

    if req_type == "REQUEST_OTP":
        client_id = request["client_id"]
        otp = os.urandom(16)  # 128-bit OTP
        with data_lock:
            client_otps[client_id] = otp
        # Simulate SendBySecureChannel - Just print on server side
        print(f"[SecureChannel]: OTP for {client_id} is {otp.hex()}")
        return {"status":"otp_provided","otp_hex":otp.hex()}

    elif req_type == "FETCH_SERVER_KEY":
        client_id = request["client_id"]
        # The server returns its public key and a MAC with the OTP for authenticity
        with data_lock:
            otp = client_otps.get(client_id)
        if not otp:
            return {"status":"error","error":"no_otp_for_client"}

        response = {
            "type":"SERVER_KEY_RESPONSE",
            "server_long_term_pub": server_long_term_public.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        }
        mac = hmac.new(otp, response["server_long_term_pub"].encode('utf-8'), hashlib.sha256).digest()
        response["mac_hex"] = mac.hex()
        return response

    elif req_type == "REGISTER":
        client_id = request["client_id"]
        client_eph_pub_hex = request["client_eph_pub"]
        given_mac_hex = request["mac_hex"]

        with data_lock:
            otp = client_otps.get(client_id)
        if not otp:
            return {"status":"error","error":"no_otp_for_client"}

        # Verify MAC over the request
        to_mac = {
            "type":"REGISTER",
            "client_id":client_id,
            "client_eph_pub":client_eph_pub_hex
        }
        mac_check = hmac.new(otp, json.dumps(to_mac).encode('utf-8'), hashlib.sha256).digest()
        if not hmac.compare_digest(mac_check, bytes.fromhex(given_mac_hex)):
            return {"status":"error","error":"MAC_verification_failed"}

        client_eph_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(client_eph_pub_hex))
        server_eph_priv = x25519.X25519PrivateKey.generate()
        server_eph_pub = server_eph_priv.public_key()

        # Derive session key
        shared_secret = server_eph_priv.exchange(client_eph_pub)
        session_key = hkdf_derive(shared_secret, otp)  # Not stored, just conceptual here

        # Respond with server_eph_pub and MAC
        resp = {
            "type":"REGISTER_RESPONSE",
            "server_eph_pub": server_eph_pub.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        }
        mac_resp = hmac.new(otp, json.dumps(resp).encode('utf-8'), hashlib.sha256).digest()
        resp["mac_hex"] = mac_resp.hex()
        return resp

    elif req_type == "FINALIZE_REGISTRATION":
        client_id = request["client_id"]
        identity_pub_hex = request["identity_pub"]
        pre_keys_hex = request["pre_keys"]
        # In a real scenario, we'd decrypt and verify this request with the session key from registration.
        # Here we assume trust since we are at final step of registration.

        identity_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(identity_pub_hex))
        pre_keys = [x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(k)) for k in pre_keys_hex]

        with data_lock:
            registered_clients[client_id] = {
                "identity_pub": identity_pub,
                "pre_keys": pre_keys,
                "delivered_updates": []
            }

        return {"status":"ok"}

    elif req_type == "FETCH_KEYS":
        target_id = request["target_id"]
        with data_lock:
            target_data = registered_clients.get(target_id)
            if not target_data or not target_data["pre_keys"]:
                return {"status":"error","error":"target_not_available_or_no_pre_keys"}

            chosen_pre_key = target_data["pre_keys"].pop(0)
            identity_pub = target_data["identity_pub"]

        return {
            "status":"ok",
            "B_identity_pub": identity_pub.public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
            "B_one_time_pub": chosen_pre_key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
            "one_time_key_id":"0"
        }

    elif req_type == "SEND_MESSAGE":
        recipient = request["recipient_id"]
        msg_data = {
            "sender_id": request["sender_id"],
            "A_ephemeral_pub": request["A_ephemeral_pub"],
            "B_one_time_key_id": request["B_one_time_key_id"],
            "iv": request["iv"],
            "ciphertext": request["ciphertext"]
        }
        message_id = str(uuid.uuid4())
        with data_lock:
            if recipient not in stored_messages:
                stored_messages[recipient] = []
            stored_messages[recipient].append((message_id, msg_data))

        return {"status":"message_stored","message_id":message_id}

    elif req_type == "RETRIEVE_MESSAGES":
        client_id = request["client_id"]
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
        return {"status":"ok","messages": out_msgs}

    elif req_type == "GET_DELIVERY_UPDATES":
        client_id = request["client_id"]
        with data_lock:
            updates = registered_clients[client_id]["delivered_updates"]
            registered_clients[client_id]["delivered_updates"] = []
        return {"status":"ok","delivered_message_ids": updates}

    else:
        return {"status":"error","error":"unknown_request"}

def handle_client_connection(client_socket, client_address):
    print(f"[+] New connection from {client_address}")
    try:
        while True:
            request = recv_message(client_socket)
            if request is None:
                break
            response = process_request(request)
            send_message(client_socket, response)
    except Exception as e:
        print(f"Error handling client {client_address}: {e}")
    finally:
        client_socket.close()
        print(f"[-] Connection closed for {client_address}")

def start_server():
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
