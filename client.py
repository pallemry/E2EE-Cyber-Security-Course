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
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

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
        self.state_file = f"client_state_{client_id}.json"

        self.otp = None
        self.server_long_term_pub = None
        self.session_key = None
        self.registered = False
        self.identity_private = None
        self.identity_public = None
        self.pre_keys_private = []
        self.pre_keys_public = []
        self.known_identities = {}
        self.contact_pre_keys = {}
        self.stored_undecrypted_msgs = []

        self._load_state()
        
        # Ensure keys are generated if not present
        if self.identity_private is None or self.identity_public is None:
            self._generate_new_identity_and_prekeys()

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((HOST, PORT))

    def _save_state(self):
        id_priv_hex = None
        if self.identity_private is not None:
            id_priv_hex = self.identity_private.private_bytes(
                Encoding.Raw,
                PrivateFormat.Raw,
                NoEncryption()
            ).hex()

        pre_keys_private_hex = [
            pk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
            for pk in self.pre_keys_private
        ]
        pre_keys_public_hex = [
            pk.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
            for pk in self.pre_keys_public
        ]

        known_identities_hex = {
            k: v.public_bytes(Encoding.Raw, PublicFormat.Raw).hex() for k, v in self.known_identities.items()
        }

        state = {
            "registered": self.registered,
            "otp": self.otp.decode('utf-8') if self.otp else None,
            "server_long_term_pub": self.server_long_term_pub.public_bytes(Encoding.Raw, PublicFormat.Raw).hex() if self.server_long_term_pub else None,
            "identity_private": id_priv_hex,
            "pre_keys_private": pre_keys_private_hex,
            "pre_keys_public": pre_keys_public_hex,
            "known_identities": known_identities_hex,
            "contact_pre_keys": self.contact_pre_keys,
            "stored_undecrypted_msgs": self.stored_undecrypted_msgs
        }

        with open(self.state_file, "w") as f:
            json.dump(state, f, indent=2)

    def _load_state(self):
        if not os.path.exists(self.state_file):
            return
        with open(self.state_file, "r") as f:
            state = json.load(f)

        self.registered = state.get("registered", False)
        otp_str = state.get("otp")
        self.otp = otp_str.encode('utf-8') if otp_str else None

        server_pub_hex = state.get("server_long_term_pub")
        if server_pub_hex:
            self.server_long_term_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(server_pub_hex))

        id_priv_hex = state.get("identity_private")
        if id_priv_hex:
            self.identity_private = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(id_priv_hex))
            self.identity_public = self.identity_private.public_key()

        pre_keys_private_hex = state.get("pre_keys_private", [])
        self.pre_keys_private = [
            x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(h))
            for h in pre_keys_private_hex
        ]

        pre_keys_public_hex = state.get("pre_keys_public", [])
        self.pre_keys_public = [
            x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(h))
            for h in pre_keys_public_hex
        ]

        known_identities_hex = state.get("known_identities", {})
        self.known_identities = {
            k: x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(v_hex))
            for k, v_hex in known_identities_hex.items()
        }

        self.contact_pre_keys = state.get("contact_pre_keys", {})
        self.stored_undecrypted_msgs = state.get("stored_undecrypted_msgs", [])

    def _generate_new_identity_and_prekeys(self):
        self.identity_private = x25519.X25519PrivateKey.generate()
        self.identity_public = self.identity_private.public_key()
        self.pre_keys_private = []
        self.pre_keys_public = []
        for _ in range(10):
            pk_priv = x25519.X25519PrivateKey.generate()
            self.pre_keys_private.append(pk_priv)
            self.pre_keys_public.append(pk_priv.public_key())

    def request_otp(self):
        if self.registered:
            print("Already registered. No need to request OTP again.")
            return
        req = {"type":"REQUEST_OTP","client_id":self.client_id}
        send_msg(self.sock, req)
        resp = recv_msg(self.sock)
        if resp and resp.get("status") == "otp_provided":
            self.otp = resp["otp"].encode('utf-8')
            print(f"[*] OTP received via secure channel: {resp['otp']}")
            self._save_state()
        else:
            print("Error requesting OTP:", resp)

    def fetch_server_key(self):
        if self.registered:
            print("Already registered, server key should be known.")
            return
        if not self.otp:
            print("Cannot fetch server key without OTP.")
            return
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
            self._save_state()
        else:
            print("Error fetching server key:", resp)

    def register_ephemeral_exchange(self):
        if self.registered:
            print("Already registered. Skipping ephemeral exchange.")
            return
        if not self.otp or not self.server_long_term_pub:
            print("Cannot register without OTP or server public key.")
            return

        # Sanity check identity keys
        if self.identity_private is None or self.identity_public is None:
            print("Error: No identity keys available.")
            return

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
            self.session_key = hkdf_derive(shared_secret, self.otp)
            print("[*] Registration ephemeral exchange complete.")
            self._save_state()
        else:
            print("Error in ephemeral exchange:", resp)

    def finalize_registration(self):
        if self.registered:
            print("Already registered. Skipping finalize registration.")
            return

        if self.identity_public is None:
            print("Error: Identity public key not set.")
            return

        identity_pub_hex = self.identity_public.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        pre_keys_hex = [k.public_bytes(Encoding.Raw, PublicFormat.Raw).hex() for k in self.pre_keys_public]

        req = {
            "type":"FINALIZE_REGISTRATION",
            "client_id": self.client_id,
            "identity_pub": identity_pub_hex,
            "pre_keys": pre_keys_hex
        }
        send_msg(self.sock, req)
        resp = recv_msg(self.sock)
        if resp and resp.get("status") == "ok":
            self.registered = True
            print("Finalize registration response:", resp)
            self._save_state()
        else:
            print("Error finalizing registration:", resp)

    def fetch_keys(self, target_id):
        req = {"type":"FETCH_KEYS","client_id":self.client_id,"target_id":target_id}
        send_msg(self.sock, req)
        resp = recv_msg(self.sock)
        if resp and resp.get("status") == "ok":
            B_id_pub_hex = resp["B_identity_pub"]
            B_id_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(B_id_pub_hex))
            self.known_identities[target_id] = B_id_pub
            self.contact_pre_keys[target_id] = {
                "B_identity_pub": B_id_pub_hex,
                "B_one_time_pub": resp["B_one_time_pub"]
            }
            print(f"[*] Keys for {target_id} fetched and stored.")
            self._save_state()
            return True
        else:
            print("Error fetching keys:", resp)
            return False

    def send_message(self, recipient_id, plaintext):
        if recipient_id not in self.contact_pre_keys:
            print(f"Don't have keys for {recipient_id}, run fetch_keys {recipient_id} first.")
            return

        if self.identity_private is None:
            print("Error: No identity private key to compute ECDH.")
            return

        B_identity_pub_hex = self.contact_pre_keys[recipient_id]["B_identity_pub"]
        B_one_time_pub_hex = self.contact_pre_keys[recipient_id]["B_one_time_pub"]

        B_identity_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(B_identity_pub_hex))
        B_one_time_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(B_one_time_pub_hex))

        A_msg_eph_priv = x25519.X25519PrivateKey.generate()
        A_msg_eph_pub = A_msg_eph_priv.public_key()

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
            msgs = resp["messages"]
            if not msgs and not self.stored_undecrypted_msgs:
                print("No new messages.")
            # Combine newly retrieved with previously stored
            all_msgs = msgs + self.stored_undecrypted_msgs
            self.stored_undecrypted_msgs = []
            undecrypted = []
            for msg in all_msgs:
                if not self.decrypt_message(msg):
                    undecrypted.append(msg)
            self.handle_undecrypted_messages(undecrypted)
        else:
            print("Error retrieving messages:", resp)

    def handle_undecrypted_messages(self, msgs):
        second_round = []
        for msg in msgs:
            sender_id = msg["sender_id"]
            if sender_id not in self.known_identities:
                print(f"Attempting to fetch keys for {sender_id} to decrypt message.")
                if not self.fetch_keys(sender_id):
                    print(f"Failed to fetch keys for {sender_id}, cannot decrypt message now.")
                    second_round.append(msg)
                    continue
            # Try decrypt again
            if not self.decrypt_message(msg):
                print("Still failed to decrypt after fetching keys, storing locally.")
                self.stored_undecrypted_msgs.append(msg)
        self._save_state()

    def decrypt_message(self, msg):
        sender_id = msg["sender_id"]

        if self.identity_private is None:
            print("Error: No identity private key available for decryption.")
            return False

        if sender_id not in self.known_identities:
            print(f"Don't know identity key for {sender_id}, cannot decrypt.")
            return False

        A_ephemeral_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(msg["A_ephemeral_pub"]))
        iv = bytes.fromhex(msg["iv"])
        ciphertext = bytes.fromhex(msg["ciphertext"])

        sender_identity_pub = self.known_identities[sender_id]
        if not self.pre_keys_private:
            print("Error: No pre-keys available for decryption.")
            return False
        B_one_time_priv = self.pre_keys_private[0]

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
            return True
        except Exception as e:
            print("Failed to decrypt message.", e)
            return False

def main():
    if len(sys.argv) < 2:
        client_id = input("Enter your phone number (client_id): ").strip()
    else:
        client_id = sys.argv[1]

    c = Client(client_id)

    print("Commands:")
    print("  register           - Run the full registration flow if not registered")
    print("  fetch_keys <id>    - Fetch keys for another client")
    print("  send <id> <msg>    - Send a message")
    print("  recv               - Retrieve and attempt to decrypt messages")
    print("  quit               - Exit")

    try:
        while True:
            cmd_line = input("Enter command: ").strip()
            if not cmd_line:
                continue
            cmd = cmd_line.split(" ", 2)

            if cmd[0] == "quit":
                c._save_state()
                break
            elif cmd[0] == "register":
                if c.registered:
                    print("Already registered.")
                else:
                    c.request_otp()
                    c.fetch_server_key()
                    c.register_ephemeral_exchange()
                    c.finalize_registration()
                    c._save_state()
            elif cmd[0] == "fetch_keys":
                if len(cmd) < 2:
                    print("Usage: fetch_keys <target_id>")
                else:
                    c.fetch_keys(cmd[1])
            elif cmd[0] == "send":
                if len(cmd) < 3:
                    print("Usage: send <target_id> <message>")
                else:
                    c.send_message(cmd[1], cmd[2].encode('utf-8'))
            elif cmd[0] == "recv":
                c.retrieve_messages()
            else:
                print("Unknown command")
    except KeyboardInterrupt:
        c._save_state()
        print("\nExiting gracefully.")

if __name__ == "__main__":
    main()