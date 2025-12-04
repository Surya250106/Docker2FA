import base64
import os
import time
import pyotp
import hashlib
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

app = FastAPI()

PRIVATE_KEY_PATH = "student_private.pem"
DATA_DIR = "/data" 
SEED_FILE = os.path.join(DATA_DIR, "seed.txt")

os.makedirs(DATA_DIR, exist_ok=True)

class DecryptRequest(BaseModel):
    encrypted_seed: str

class VerifyRequest(BaseModel):
    code: str

def get_totp_object():
    """
    Reads the seed from file, converts Hex to Base32, and returns a TOTP object.
    """
    if not os.path.exists(SEED_FILE):
        raise FileNotFoundError("Seed file not found. Please decrypt seed first.")

    with open(SEED_FILE, "r") as f:
        hex_seed = f.read().strip()

    try:
        seed_bytes = bytes.fromhex(hex_seed)
    except ValueError:
         raise ValueError("Seed file does not contain valid hex data")

    base32_seed = base64.b32encode(seed_bytes).decode('utf-8')

    return pyotp.TOTP(base32_seed, digits=6, interval=30, digest=hashlib.sha1)

def decrypt_seed_logic(encrypted_seed_b64: str):
    if not os.path.exists(PRIVATE_KEY_PATH):
        raise FileNotFoundError(f"Could not find {PRIVATE_KEY_PATH}")

    with open(PRIVATE_KEY_PATH, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

    encrypted_seed_b64 = encrypted_seed_b64.strip()
    ciphertext = base64.b64decode(encrypted_seed_b64)

    decrypted_bytes = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    decrypted_seed = decrypted_bytes.decode('utf-8')
    
    if len(decrypted_seed) != 64:
        raise ValueError("Decrypted seed length is not 64 characters")
    
    return decrypted_seed

# --- ENDPOINTS ---

@app.post("/decrypt-seed")
async def decrypt_seed_endpoint(request: DecryptRequest):
    try:
        seed = decrypt_seed_logic(request.encrypted_seed)
        with open(SEED_FILE, "w") as f:
            f.write(seed)
        return {"status": "ok"}
    except Exception as e:
        print(f"Decrypt Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Decryption failed")

@app.get("/generate-2fa")
async def generate_2fa():
    """
    Endpoint 2: Generate current TOTP code and remaining validity time.
    """
    try:
        totp = get_totp_object()
        current_code = totp.now()
        
        valid_for = 30 - int(time.time() % 30)
        
        return {
            "code": current_code,
            "valid_for": valid_for
        }
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")
    except Exception as e:
        print(f"Generation Error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/verify-2fa")
async def verify_2fa(request: VerifyRequest):
    """
    Endpoint 3: Verify a provided code against the stored seed.
    """
    try:
        if not request.code:
            raise HTTPException(status_code=400, detail="Missing code")

        totp = get_totp_object()
        
        is_valid = totp.verify(request.code, valid_window=1)
        
        return {"valid": is_valid}
        
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")
    except Exception as e:
        print(f"Verification Error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/")
def health_check():
    return {"status": "running"}