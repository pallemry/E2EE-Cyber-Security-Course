import socket
import json
import os
import sys
import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HOST = '127.0.0.1'
PORT = 5000

def hkdf_derive(secret, salt, info=b"E2EE"):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info
    ).derive(secret)

def send_msg(sock, msg):
    encoded = json.dumps(msg).encode('utf-8')
    sock.send(len(encoded).to_bytes(4, 'big') + encoded)

def recv_msg(sock):
    length_bytes = sock.recv(4)
    if not length_bytes:
        return None
    msg_len = int.from_bytes(length_bytes, 'big')
    data = sock.recv(msg_len)
    if not data:
        return None
    return json.loads(data.decode('utf-8'))

class Client:
    def __init__(self, client_id):
        self.client_id = client_id
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((HOST, PORT))

        self.otp = None
        self.server_long_term_pub = None

        # Identity keys
        self.identity_private = x25519.X25519PrivateKey.generate()
        self.identity_public = self.identity_private.public_key()

        # Pre-keys
        self.pre_keys_private = []
        self.pre_keys_public = []
        for _ in range(5):  # 5 pre-keys
            pk_priv = x25519.X25519PrivateKey.generate()
            self.pre_keys_private.append(pk_priv)
            self.pre_keys_public.append(pk_priv.public_key())

        # Known identity keys of others: {client_id: X25519PublicKey}
        self.known_identities = {}
        # Store fetched keys for sending messages without re-fetching:
        # {client_id: {"B_identity_pub": ..., "B_one_time_pub": ...}}
        self.contact_pre_keys = {}

    def request_otp(self):
        req = {"type":"REQUEST_OTP","client_id":self.client_id}
        send_msg(self.sock, req)
        resp = recv_msg(self.sock)
        if resp and resp.get("status") == "otp_provided":
            self.otp = resp["otp"].encode('utf-8')
            print(f"[*] OTP received via secure channel: {resp['otp']}")
        else:
            print("Error requesting OTP:", resp)

    def fetch_server_key(self):
        if not self.otp:
            print("Cannot fetch server key without OTP.")
            sys.exit(1)
        req = {"type":"FETCH_SERVER_KEY","client_id":self.client_id}
        send_msg(self.sock, req)
        resp = recv_msg(self.sock)
        if resp and resp.get("type") == "SERVER_KEY_RESPONSE":
            server_pub_hex = resp["server_long_term_pub"]
            mac_hex = resp["mac_hex"]
            mac_check = hmac.new(self.otp, server_pub_hex.encode('utf-8'), hashlib.sha256).digest()
            if not hmac.compare_digest(mac_check, bytes.fromhex(mac_hex)):
                print("Server public key MAC verification failed!")
                sys.exit(1)
            self.server_long_term_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(server_pub_hex))
            print("[*] Server public key verified.")
        else:
            print("Error fetching server key:", resp)

    def register_ephemeral_exchange(self):
        if not self.otp or not self.server_long_term_pub:
            print("Cannot register without OTP or server public key.")
            sys.exit(1)
        # Ephemeral exchange
        C_eph_priv = x25519.X25519PrivateKey.generate()
        C_eph_pub_hex = C_eph_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        to_mac = {
            "type":"REGISTER",
            "client_id":self.client_id,
            "client_eph_pub":C_eph_pub_hex
        }
        mac = hmac.new(self.otp, json.dumps(to_mac).encode('utf-8'), hashlib.sha256).digest()
        to_mac["mac_hex"] = mac.hex()

        send_msg(self.sock, to_mac)
        resp = recv_msg(self.sock)
        if resp and resp.get("type") == "REGISTER_RESPONSE":
            # verify MAC
            resp_no_mac = {
                "type":"REGISTER_RESPONSE",
                "server_eph_pub": resp["server_eph_pub"]
            }
            mac_check = hmac.new(self.otp, json.dumps(resp_no_mac).encode('utf-8'), hashlib.sha256).digest()
            if not hmac.compare_digest(mac_check, bytes.fromhex(resp["mac_hex"])):
                print("Server ephemeral MAC verification failed!")
                sys.exit(1)

            server_eph_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(resp["server_eph_pub"]))
            shared_secret = C_eph_priv.exchange(server_eph_pub)
            # Derive session key
            self.session_key = hkdf_derive(shared_secret, self.otp)
            print("[*] Registration ephemeral exchange complete.")
        else:
            print("Error in ephemeral exchange:", resp)

    def finalize_registration(self):
        # Send identity and pre-keys
        identity_pub_hex = self.identity_public.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        pre_keys_hex = [k.public_bytes(Encoding.Raw, PublicFormat.Raw).hex() for k in self.pre_keys_public]

        req = {
            "type":"FINALIZE_REGISTRATION",
            "client_id":self.client_id,
            "identity_pub": identity_pub_hex,
            "pre_keys": pre_keys_hex
        }
        send_msg(self.sock, req)
        resp = recv_msg(self.sock)
        print("Finalize registration response:", resp)

    def fetch_keys(self, target_id):
        req = {"type":"FETCH_KEYS","client_id":self.client_id,"target_id":target_id}
        send_msg(self.sock, req)
        resp = recv_msg(self.sock)
        if resp and resp.get("status") == "ok":
            # Store the target's identity pub
            B_id_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(resp["B_identity_pub"]))
            self.known_identities[target_id] = B_id_pub
            # Store keys for sending
            self.contact_pre_keys[target_id] = {
                "B_identity_pub": resp["B_identity_pub"],
                "B_one_time_pub": resp["B_one_time_pub"]
            }
            print(f"[*] Keys for {target_id} fetched and stored.")
            return resp
        else:
            print("Error fetching keys:", resp)
            return None

    def send_message(self, recipient_id, plaintext):
        # Use stored keys
        if recipient_id not in self.contact_pre_keys:
            print(f"Don't have keys for {recipient_id}, run fetch_keys {recipient_id} first.")
            return
        B_identity_pub_hex = self.contact_pre_keys[recipient_id]["B_identity_pub"]
        B_one_time_pub_hex = self.contact_pre_keys[recipient_id]["B_one_time_pub"]

        B_identity_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(B_identity_pub_hex))
        B_one_time_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(B_one_time_pub_hex))

        A_msg_eph_priv = x25519.X25519PrivateKey.generate()
        A_msg_eph_pub = A_msg_eph_priv.public_key()

        # Sender (A) does:
        # dh1 = A_id_priv x B_id_pub
        # dh2 = A_id_priv x B_one_time_pub
        # dh3 = A_msg_eph_priv x B_id_pub
        # dh4 = A_msg_eph_priv x B_one_time_pub
        dh1 = self.identity_private.exchange(B_identity_pub)
        dh2 = self.identity_private.exchange(B_one_time_pub)
        dh3 = A_msg_eph_priv.exchange(B_identity_pub)
        dh4 = A_msg_eph_priv.exchange(B_one_time_pub)

        master_secret = dh1 + dh2 + dh3 + dh4
        shared_key = hkdf_derive(master_secret, None, b"E2EE Client-to-Client MsgKey")

        aesgcm = AESGCM(shared_key)
        iv = os.urandom(12)
        ciphertext = aesgcm.encrypt(iv, plaintext, None)

        req = {
            "type":"SEND_MESSAGE",
            "sender_id": self.client_id,
            "recipient_id": recipient_id,
            "A_ephemeral_pub": A_msg_eph_pub.public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
            "B_one_time_key_id": "0",
            "iv": iv.hex(),
            "ciphertext": ciphertext.hex()
        }
        send_msg(self.sock, req)
        resp = recv_msg(self.sock)
        print("Send message response:", resp)

    def retrieve_messages(self):
        req = {"type":"RETRIEVE_MESSAGES","client_id":self.client_id}
        send_msg(self.sock, req)
        resp = recv_msg(self.sock)
        if resp and resp.get("status") == "ok":
            if not resp["messages"]:
                print("No new messages.")
            for msg in resp["messages"]:
                self.decrypt_message(msg)
        else:
            print("Error retrieving messages:", resp)

    def decrypt_message(self, msg):
        sender_id = msg["sender_id"]
        A_ephemeral_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(msg["A_ephemeral_pub"]))
        iv = bytes.fromhex(msg["iv"])
        ciphertext = bytes.fromhex(msg["ciphertext"])

        if sender_id not in self.known_identities:
            print(f"Don't know identity key for {sender_id}, cannot decrypt.")
            print(f"Run: fetch_keys {sender_id}, then recv again.")
            return

        sender_identity_pub = self.known_identities[sender_id]
        B_one_time_priv = self.pre_keys_private[0]  # Assuming key_id="0"

        # Receiver (B) should do:
        # dh1 = B_id_priv x A_id_pub
        # dh2 = B_one_time_priv x A_id_pub
        # dh3 = B_id_priv x A_msg_eph_pub
        # dh4 = B_one_time_priv x A_msg_eph_pub

        try:
            dh1 = self.identity_private.exchange(sender_identity_pub)
            dh2 = B_one_time_priv.exchange(sender_identity_pub)
            dh3 = self.identity_private.exchange(A_ephemeral_pub)
            dh4 = B_one_time_priv.exchange(A_ephemeral_pub)

            master_secret = dh1 + dh2 + dh3 + dh4
            shared_key = hkdf_derive(master_secret, None, b"E2EE Client-to-Client MsgKey")

            aesgcm = AESGCM(shared_key)
            plaintext = aesgcm.decrypt(iv, ciphertext, None)
            print(f"[{sender_id} -> {self.client_id}] Decrypted message: {plaintext.decode('utf-8')}")
        except Exception as e:
            print("Failed to decrypt message. Possibly invalid keys or incorrect ECDH order.")
            print("Error:", e)

def main():
    if len(sys.argv) < 2:
        client_id = input("Enter your phone number (client_id): ").strip()
    else:
        client_id = sys.argv[1]

    c = Client(client_id)

    # Registration Steps
    c.request_otp()
    c.fetch_server_key()
    c.register_ephemeral_exchange()
    c.finalize_registration()

    print("[*] Client setup complete.")
    print("Commands:")
    print("  fetch_keys <target_id>        - Fetch and store target's identity and one-time keys")
    print("  send <target_id> <message>    - Send encrypted message to target")
    print("  recv                          - Retrieve and decrypt messages")
    print("  quit                          - Exit")

    while True:
        cmd = input("Enter command: ").strip()
        if cmd == "quit":
            break
        parts = cmd.split(" ", 2)
        if parts[0] == "fetch_keys":
            if len(parts) < 2:
                print("Usage: fetch_keys <target_id>")
                continue
            target_id = parts[1]
            c.fetch_keys(target_id)
        elif parts[0] == "send":
            if len(parts) < 3:
                print("Usage: send <target_id> <message>")
                continue
            target_id = parts[1]
            message = parts[2].encode('utf-8')
            c.send_message(target_id, message)
        elif parts[0] == "recv":
            c.retrieve_messages()
        else:
            print("Unknown command")

if __name__ == "__main__":
    main()
