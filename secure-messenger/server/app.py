from fastapi import FastAPI, Header, HTTPException
from crypto_utils import *
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = FastAPI()
API_KEY = "Cinnamoroll"

private_key, public_key = generate_rsa_keypair()
sessions = {}

@app.get("/public-key")
def get_public_key():
    return {"public_key_pem": serialize_public_key(public_key)}

@app.post("/handshake")
def handshake(data: dict, x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=403)

    client_id = data["client_id"]
    enc_key = b64d(data["enc_key"])
    aes_key = rsa_decrypt_oaep(private_key, enc_key)
    sessions[client_id] = aes_key
    return {"message": f"Session established for {client_id}"}

@app.post("/message")
def message(data: dict, x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=403)

    client_id = data["client_id"]
    if client_id not in sessions:
        raise HTTPException(status_code=400)

    aes_key = sessions[client_id]
    nonce = b64d(data["nonce"])
    ciphertext = b64d(data["ciphertext"])
    tag = b64d(data["tag"])
    recv_mac = b64d(data["hmac"])

    mac = hmac_sha256(aes_key, nonce + ciphertext + tag)
    if mac != recv_mac:
        raise HTTPException(status_code=400, detail="HMAC mismatch")

    aes = AESGCM(aes_key)
    plaintext = aes.decrypt(nonce, ciphertext + tag, None)
    return {"decrypted_student_json": plaintext.decode()}
