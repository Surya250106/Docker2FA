from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
import uvicorn
import os

# Import the utility functions from previous steps
from cryptography_utils import load_private_key, decrypt_seed, generate_totp_code_and_time, verify_totp_code
from storage_utils import read_seed, write_seed

# --- Pydantic Models for Request/Response Schemas ---

class DecryptSeedRequest(BaseModel):
    encrypted_seed: str

class VerifyCodeRequest(BaseModel):
    code: str

class CodeResponse(BaseModel):
    code: str
    valid_for: int

class StatusResponse(BaseModel):
    status: str

class ValidResponse(BaseModel):
    valid: bool

# --- FastAPI Application ---

app = FastAPI(title="PKI-2FA Microservice")
PRIVATE_KEY = None # Will be loaded on startup

@app.on_event("startup")
def load_keys_and_init():
    """Load the private key once when the application starts."""
    global PRIVATE_KEY
    try:
        # NOTE: The path must be relative to the container's working directory,
        # which is usually set to /app or similar in the Dockerfile.
        # We assume student_private.pem is accessible at the root of the app.
        PRIVATE_KEY = load_private_key("student_private.pem")
        print("✅ Student private key loaded successfully.")
    except Exception as e:
        print(f"🛑 Error loading private key: {e}")
        # In a real app, this would be a fatal error, but we proceed to allow
        # the API to start and respond with HTTP 500 on /decrypt-seed attempts.

# --- Endpoint 1: POST /decrypt-seed ---

@app.post("/decrypt-seed", response_model=StatusResponse, status_code=status.HTTP_200_OK)
def decrypt_and_store_seed(request: DecryptSeedRequest):
    """Accepts and decrypts the base64-encoded seed, storing the hex seed persistently."""
    
    if PRIVATE_KEY is None:
         raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "Private key not loaded. Cannot decrypt."}
        )
    
    try:
        # 1. Decrypt using RSA/OAEP-SHA256
        hex_seed = decrypt_seed(request.encrypted_seed, PRIVATE_KEY)
        
        # 2. Store persistently at /data/seed.txt
        if not write_seed(hex_seed):
             raise IOError("Failed to write seed to persistent storage.")

        return {"status": "ok"}
        
    except (ValueError, RuntimeError, IOError) as e:
        # Catches Base64 errors, decryption failures, and file I/O errors
        print(f"🛑 Decryption or Storage Error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "Decryption failed or storage error occurred."}
        )

# --- Endpoint 2: GET /generate-2fa ---

@app.get("/generate-2fa", response_model=CodeResponse, status_code=status.HTTP_200_OK)
def generate_2fa_code():
    """Reads seed, generates current TOTP code and remaining validity time."""
    
    hex_seed = read_seed()
    if hex_seed is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "Seed not decrypted yet or /data/seed.txt unavailable."}
        )
        
    try:
        # 1. Generate code and remaining seconds
        code, valid_for = generate_totp_code_and_time(hex_seed)
        
        # 2. Return code and time remaining
        return CodeResponse(code=code, valid_for=valid_for)
        
    except ValueError as e:
        # Catches errors like invalid hex format during conversion
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": f"TOTP generation failed: {e}"}
        )

# --- Endpoint 3: POST /verify-2fa ---

@app.post("/verify-2fa", response_model=ValidResponse, status_code=status.HTTP_200_OK)
def verify_2fa_code(request: VerifyCodeRequest):
    """Accepts a code and verifies it against the stored seed with ±1 period tolerance."""
    
    # Input validation (FastAPI/Pydantic handles basic type check, but we check content)
    if not request.code or len(request.code) != 6 or not request.code.isdigit():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "Invalid code format. Must be a 6-digit string."}
        )

    hex_seed = read_seed()
    if hex_seed is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "Seed not decrypted yet or /data/seed.txt unavailable."}
        )
        
    try:
        # 1. Verify code with ±1 period tolerance (valid_window=1)
        is_valid = verify_totp_code(hex_seed, request.code, valid_window=1)
        
        # 2. Return validation result
        return ValidResponse(valid=is_valid)
        
    except ValueError as e:
        # Catches errors like invalid hex format during conversion
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": f"TOTP verification setup failed: {e}"}
        )

# --- Execution Entry Point (for Docker) ---

# This block is used when the container starts the API server
if __name__ == "__main__":
    # The server must bind to 0.0.0.0 for access within Docker
    uvicorn.run(app, host="0.0.0.0", port=8080)