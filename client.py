import socket
import json
import os
import sys
import hmac
import hashlib
from utils import *
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
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

def send_plain_msg(sock, msg):
    encoded = json.dumps(msg).encode('utf-8')
    sock.send(len(encoded).to_bytes(4, 'big') + encoded)

def recv_plain_msg(sock):
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
        self.server_signing_public_key = None

        self.session_key = None
        self.registered = False
        self.identity_private = None
        self.identity_public = None
        self.client_signing_private_key = None
        self.client_signing_public_key = None

        self.pre_keys_private = []
        self.pre_keys_public = []
        self.known_identities = {}
        self.contact_pre_keys = {}
        self.stored_undecrypted_msgs = []

        self._load_state()

        # Ensure keys are generated if not present
        if self.identity_private is None or self.identity_public is None or self.client_signing_private_key is None:
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

        signing_priv_hex = None
        if self.client_signing_private_key is not None:
            signing_priv_hex = self.client_signing_private_key.private_bytes(
                Encoding.Raw, PrivateFormat.Raw, NoEncryption()
            ).hex()

        signing_pub_hex = None
        if self.client_signing_public_key is not None:
            signing_pub_hex = self.client_signing_public_key.public_bytes(
                Encoding.Raw, PublicFormat.Raw
            ).hex()

        server_signing_pub_hex = None
        if self.server_signing_public_key is not None:
            server_signing_pub_hex = self.server_signing_public_key.public_bytes(
                Encoding.Raw, PublicFormat.Raw
            ).hex()
            
        session_key_hex = None
        if self.session_key is not None:
            session_key_hex = self.session_key.hex()

        state = {
            "registered": self.registered,
            "otp": self.otp.decode('utf-8') if self.otp else None,
            "server_long_term_pub": self.server_long_term_pub.public_bytes(Encoding.Raw, PublicFormat.Raw).hex() if self.server_long_term_pub else None,
            "server_signing_public_key": server_signing_pub_hex,
            "identity_private": id_priv_hex,
            "client_signing_private_key": signing_priv_hex,
            "client_signing_public_key": signing_pub_hex,
            "pre_keys_private": pre_keys_private_hex,
            "pre_keys_public": pre_keys_public_hex,
            "known_identities": known_identities_hex,
            "contact_pre_keys": self.contact_pre_keys,
            "stored_undecrypted_msgs": self.stored_undecrypted_msgs,
            "session_key": session_key_hex
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

        server_signing_pub_hex = state.get("server_signing_public_key")
        if server_signing_pub_hex:
            self.server_signing_public_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(server_signing_pub_hex))

        id_priv_hex = state.get("identity_private")
        if id_priv_hex:
            self.identity_private = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(id_priv_hex))
            self.identity_public = self.identity_private.public_key()

        client_signing_priv_hex = state.get("client_signing_private_key")
        if client_signing_priv_hex:
            self.client_signing_private_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(client_signing_priv_hex))
        client_signing_pub_hex = state.get("client_signing_public_key")
        if client_signing_pub_hex:
            self.client_signing_public_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(client_signing_pub_hex))

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
        
        session_key_hex = state.get("session_key")
        if session_key_hex:
            self.session_key = bytes.fromhex(session_key_hex)

    def _generate_new_identity_and_prekeys(self, num_pre_keys=10):
        self.identity_private = x25519.X25519PrivateKey.generate()
        self.identity_public = self.identity_private.public_key()
        # Derive Ed25519 key from X25519 key
        self.client_signing_private_key, self.client_signing_public_key = derive_ed25519_from_x25519(self.identity_private)
        
        self.pre_keys_private = []
        self.pre_keys_public = []
        for _ in range(num_pre_keys):
            pk_priv = x25519.X25519PrivateKey.generate()
            self.pre_keys_private.append(pk_priv)
            self.pre_keys_public.append(pk_priv.public_key())

    def _send_request(self, req, signed=True):
        if self.session_key:
            if not self.server_signing_public_key and signed:
                print("Error: Server signing key not known.")
                return
            # Use digital signature here
            send_encrypted_msg(self.sock, req, self.session_key, self.client_signing_private_key if signed else None)
            return recv_encrypted_msg(self.sock, self.session_key, self.server_signing_public_key if signed else None)
        else:
            send_plain_msg(self.sock, req)
            return recv_plain_msg(self.sock)

    def request_otp(self):
        if self.registered:
            print("Already registered.")
            return
        req = {"type":"REQUEST_OTP","client_id":self.client_id}
        resp = self._send_request(req)
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
        resp = self._send_request(req)
        if resp and resp.get("type") == "SERVER_KEY_RESPONSE":
            server_x25519_pub_hex = resp["server_long_term_pub"]
            server_ed25519_pub_key_hex = resp["server_signing_pub"]
            mac_hex = resp["mac_hex"]

            # Validate the MAC
            mac_check = hmac.new(self.otp, server_x25519_pub_hex.encode('utf-8'), hashlib.sha256).digest()
            if not hmac.compare_digest(mac_check, bytes.fromhex(mac_hex)):
                print("Server public key MAC verification failed!")
                sys.exit(1)

            # Derive the Ed25519 public key from the X25519 public key
            server_x25519_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(server_x25519_pub_hex))
            # Verify the Ed25519 public key
            server_ed25519_pub_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(server_ed25519_pub_key_hex))

            self.server_long_term_pub = server_x25519_pub
            self.server_signing_public_key = server_ed25519_pub_key
            print(f"[*] Server public key for signs: {server_ed25519_pub_key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()}")
            print("[*] Server public and signing keys derived and verified.")
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
        
        resp = self._send_request(to_mac, signed=False)
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
        
        if not self.server_signing_public_key:
            print("Error: Server signing public key not set.")
            return
        
        if not self.client_signing_public_key:
            print("Error: Client signing public key not set.")
            return

        identity_pub_hex = self.identity_public.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        pre_keys_hex = [k.public_bytes(Encoding.Raw, PublicFormat.Raw).hex() for k in self.pre_keys_public]
        signing_pub_hex = self.client_signing_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

        req = {
            "type":"FINALIZE_REGISTRATION",
            "client_id": self.client_id,
            "identity_pub": identity_pub_hex,
            "pre_keys": pre_keys_hex,
            "signing_pub": signing_pub_hex
        }
        resp = self._send_request(req, signed=False)
        if resp and resp.get("status") == "ok":
            self.registered = True
            # Now subsequent requests will use session_key encryption
            print("Finalize registration response:", resp)
            self._save_state()
        else:
            print("Error finalizing registration:", resp)

    def fetch_keys(self, target_id):
        req = {"type":"FETCH_KEYS","client_id":self.client_id,"target_id":target_id}
        resp = self._send_request(req)
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
            # Attempt to fetch keys if not already known using fetch_keys
            print(f"Don't have keys for {recipient_id}, running fetch_keys {recipient_id}...")
            success = self.fetch_keys(recipient_id)
            if not success:
                print(f"Failed to fetch keys for {recipient_id}, cannot send message.")
            else:
                print(f"Keys fetched for {recipient_id}, retrying message send.")
                self.send_message(recipient_id, plaintext)
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
        resp = self._send_request(req)
        print("Send message response:", resp)

    def retrieve_messages(self):
        req = {"type":"RETRIEVE_MESSAGES","client_id":self.client_id}
        resp = self._send_request(req)
        if resp and resp.get("status") == "ok":
            msgs = resp["messages"]
            if not msgs and not self.stored_undecrypted_msgs:
                print("No new messages.")
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

    def reconnect_with_server(self):
        if not self.registered:
            print("Client is not registered. Please register first.")
            return

        # Send a reconnection request
        req = {
            "type": "RECONNECT",
            "client_id": self.client_id
        }
        send_plain_msg(self.sock, req)

        # Expect a challenge from the server
        resp = recv_plain_msg(self.sock)
        if resp and resp.get("type") == "CHALLENGE" and self.session_key:
            challenge = resp["challenge"]
            print("Received challenge from server.")

            # Compute the response using the session key or signing key
            if self.client_signing_private_key:
                challenge_response = self.client_signing_private_key.sign(challenge.encode('utf-8')).hex()
            else:
                # Fallback using HMAC with session key
                challenge_response = hmac.new(self.session_key, challenge.encode('utf-8'), hashlib.sha256).hexdigest()

            # Send the response back to the server
            response = {
                "type": "CHALLENGE_RESPONSE",
                "client_id": self.client_id,
                "challenge_response": challenge_response
            }
            
            final_resp = self._send_request(response)
            
            if final_resp and final_resp.get("status") == "ok":
                print("Reconnection successful.")
            else:
                print("Reconnection failed:", final_resp.get("error") if final_resp else "Unknown error")
        else:
            print("Unexpected response from server during reconnection.")


def main():
    if len(sys.argv) < 2:
        client_id = None
        while client_id is None:
            entered_id = input("Enter your phone number (client_id) in the format +123456789: ").strip()
            if is_valid_phone_number(entered_id):
                client_id = entered_id
            else:
                print("Invalid phone number. Please try again.")
    else:
        client_id = sys.argv[1]
        if not is_valid_phone_number(client_id):
            print("Error: Invalid phone number provided via command line.")
            sys.exit(1)

    c = Client(client_id)

    if c.registered:
        print("Client already registered, making connection with server")
        # mechanishm to reconnect with server, if the client is already registered
        c.reconnect_with_server()
        

    print("Commands:")
    print("  register           - Run the full registration flow if not registered")
    print("  fetch_keys <id>    - Fetch keys for another client")
    print("  send <id> <msg>    - Send a message")
    print("  recv               - Retrieve and attempt to decrypt messages")
    print("  quit               - Exit")

    try:
        while True:
            cmd_line = input("> ").strip()
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