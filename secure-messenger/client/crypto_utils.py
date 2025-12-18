import base64
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()

def load_public_key_from_pem(pem: str):
    return load_pem_public_key(pem.encode())

def rsa_encrypt_oaep(public_key, data: bytes) -> bytes:
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def aesgcm_encrypt(key: bytes, data: bytes):
    aes = AESGCM(key)
    nonce = os.urandom(12)  # 12 bytes = 96-bit nonce (correct for GCM)
    ct_with_tag = aes.encrypt(nonce, data, None)
    return nonce, ct_with_tag[:-16], ct_with_tag[-16:]

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()

