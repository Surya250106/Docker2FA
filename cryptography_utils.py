from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import re
import os

# Define the file paths (assuming this utility is imported by the API server)
PRIVATE_KEY_PATH = "student_private.pem"

def load_private_key(file_path: str = PRIVATE_KEY_PATH):
    """Loads the student private key from a PEM file."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Private key file not found: {file_path}")

    with open(file_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None, # Key must not be encrypted
            backend=default_backend()
        )
    return private_key

def decrypt_seed(encrypted_seed_b64: str, private_key) -> str:
    """
    Decrypts base64-encoded encrypted seed using RSA/OAEP with SHA-256.

    Args:
        encrypted_seed_b64: Base64-encoded ciphertext.
        private_key: RSA private key object.

    Returns:
        Decrypted 64-character hex seed string.
    """
    try:
        # 1. Base64 decode the encrypted seed string
        encrypted_bytes = base64.b64decode(encrypted_seed_b64)
    except base64.binascii.Error:
        raise ValueError("Encrypted seed is not valid Base64.")

    # 2. RSA/OAEP decrypt with SHA-256
    oaep_padding = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )

    try:
        decrypted_bytes = private_key.decrypt(
            encrypted_bytes,
            oaep_padding
        )
    except Exception as e:
        # Catch specific crypto errors (e.g., DecryptionError) if possible, or general Exception
        raise RuntimeError(f"RSA Decryption Failed: {e}")

    # 3. Decode bytes to UTF-8 string (the seed is a string of hex characters)
    hex_seed = decrypted_bytes.decode('utf-8')

    # 4. Validate: must be 64-character hex string
    if len(hex_seed) != 64 or not re.fullmatch(r'[0-9a-fA-F]{64}', hex_seed):
        raise ValueError("Decrypted data is not a valid 64-character hex seed.")

    # 5. Return the hex seed (ensure it's lowercase for consistency, although not strictly required)
    return hex_seed.lower()

# You can add the signing and re-encryption functions here later (Step 13)

import pyotp
import base64
import time
# ... (rest of the imports and functions from Step 2.1 above) ...

def hex_to_base32(hex_seed: str) -> str:
    """
    Converts a 64-character hexadecimal seed string to a Base32 encoded string.
    This is required by the TOTP standard.
    """
    # 1. Convert hex seed string to bytes
    try:
        seed_bytes = bytes.fromhex(hex_seed)
    except ValueError:
        raise ValueError("Invalid hexadecimal seed string.")

    # 2. Convert bytes to Base32 encoding
    # pyotp expects a string, so we decode the base64 output
    base32_seed_bytes = base64.b32encode(seed_bytes)
    base32_seed = base32_seed_bytes.decode('utf-8').rstrip('=') # Remove padding for common TOTP libraries

    return base32_seed

def generate_totp_code_and_time(hex_seed: str) -> tuple[str, int]:
    """
    Generates the current TOTP code and the time remaining in the period.

    Args:
        hex_seed: 64-character hex string.

    Returns:
        A tuple of (6-digit TOTP code, seconds remaining in period).
    """
    base32_seed = hex_to_base32(hex_seed)

    # 1. Create TOTP object with required parameters
    # pyotp defaults to SHA1, 30s period, 6 digits, but we set them explicitly
    totp = pyotp.TOTP(
        base32_seed,
        digits=6,
        interval=30,
        digest=hashes.SHA1 # pyotp expects hashes.SHA1, not hashes.SHA1()
    )

    # 2. Generate current TOTP code
    current_code = totp.now()

    # 3. Calculate remaining seconds in current period
    # Current UTC time (seconds since epoch)
    current_time = time.time()
    
    # Calculate seconds into the current 30-second period (0-29)
    # The current code is valid until second 29 of the period.
    seconds_in_period = int(current_time) % 30
    valid_for = 30 - seconds_in_period
    
    return current_code, valid_for

def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    """
    Verifies a TOTP code with time window tolerance.

    Args:
        hex_seed: 64-character hex string.
        code: 6-digit code to verify.
        valid_window: Number of periods before/after to accept (default 1 = ±30s).

    Returns:
        True if code is valid, False otherwise.
    """
    base32_seed = hex_to_base32(hex_seed)
    
    # 1. Create TOTP object
    totp = pyotp.TOTP(
        base32_seed,
        digits=6,
        interval=30,
        digest=hashes.SHA1 # Use SHA1 as per standard
    )

    # 2. Verify code with time window tolerance (±1 period)
    # pyotp's verify() method accepts a window parameter
    is_valid = totp.verify(
        code, 
        valid_window=valid_window
    )
    
    return is_valid