import json
import os
import socket
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

def derive_ed25519_from_x25519(x25519_private_key):
    """
    Derive an Ed25519 private key from an X25519 private key.
    :param x25519_private_key: X25519 private key object.
    :return: Tuple of (Ed25519 private key, Ed25519 public key).
    """
    # Get the raw bytes of the X25519 private key
    x25519_private_bytes = x25519_private_key.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption()
    )
    # Derive the Ed25519 seed using SHA-512
    seed = hashes.Hash(hashes.SHA512())
    seed.update(x25519_private_bytes)
    ed25519_seed = seed.finalize()[:32]
    # Generate the Ed25519 private and public keys
    ed25519_private_key = ed25519.Ed25519PrivateKey.from_private_bytes(ed25519_seed)
    ed25519_public_key = ed25519_private_key.public_key()
    return ed25519_private_key, ed25519_public_key


def derive_ed25519_from_x25519_public(x25519_public_key):
    """
    Derive an Ed25519 public key from an X25519 public key.
    :param x25519_public_key: X25519 public key object.
    :return: Ed25519 public key object.
    """
    # Get the raw bytes of the X25519 public key
    x25519_public_bytes = x25519_public_key.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw
    )
    # Derive the Ed25519 public key using SHA-512
    derived_pub_key = hashes.Hash(hashes.SHA512())
    derived_pub_key.update(x25519_public_bytes)
    ed25519_public_bytes = derived_pub_key.finalize()[:32]
    return ed25519.Ed25519PublicKey.from_public_bytes(ed25519_public_bytes)

if __name__ == '__main__':        
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    def hex(p):
        return p.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    # compare the derived public key with the original public key
    print("What the server expects:", hex(derive_ed25519_from_x25519(priv)[1]))
    print("What the client expects:", hex(derive_ed25519_from_x25519_public(pub))) 

def send_encrypted_msg(sock: socket.socket, msg, session_key, signing_private_key=None):
    # Serialize payload
    plaintext = json.dumps(msg).encode('utf-8')
    if signing_private_key is not None:
        # Sign the plaintext
        signature = signing_private_key.sign(plaintext)
        signature_hex = signature.hex()
    else:
        signature_hex = None

    to_encrypt = {
        "payload": msg
    }
    if signature_hex is not None:
        to_encrypt["signature"] = signature_hex

    final_plaintext = json.dumps(to_encrypt).encode('utf-8')
    aesgcm = AESGCM(session_key)
    iv = os.urandom(12)
    ciphertext = aesgcm.encrypt(iv, final_plaintext, None)

    enc_msg = {
        "iv": iv.hex(),
        "ciphertext": ciphertext.hex()
    }
    encoded = json.dumps(enc_msg).encode('utf-8')
    sock.send(len(encoded).to_bytes(4, 'big') + encoded)

def recv_encrypted_msg(sock, session_key, expected_signing_pub=None):
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
    final_plaintext = aesgcm.decrypt(iv, ciphertext, None)
    to_decrypt = json.loads(final_plaintext.decode('utf-8'))

    payload = to_decrypt["payload"]
    signature_hex = to_decrypt.get("signature")

    # If we have a signing public key expected and a signature present, verify it
    if expected_signing_pub is not None and signature_hex is not None:
        signature = bytes.fromhex(signature_hex)
        expected_signing_pub.verify(signature, json.dumps(payload).encode('utf-8'))

    return payload
