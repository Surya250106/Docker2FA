import requests
import json
import os

# --- Configuration ---
STUDENT_ID = "23MH1A05G7"  # <-- REPLACE with your actual student ID
GITHUB_REPO_URL = "https://github.com/Surya250106/Docker2FA"  # <-- REPLACE with your exact GitHub URL
API_URL = "https://eajeyq4r3zljoq4rpovy2nthda0vtjqf.lambda-url.ap-south-1.on.aws"
PUBLIC_KEY_FILE = "student_public.pem"
OUTPUT_FILE = "encrypted_seed.txt"

def get_public_key_pem(file_path: str) -> str:
    """Reads the public key and prepares it for the JSON payload."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Public key file not found: {file_path}")
    
    with open(file_path, 'r') as f:
        # Read the entire PEM file content
        public_key_content = f.read()
    
    # Most HTTP clients/servers handle multi-line strings in JSON properly,
    # but the API instructions emphasize a single line with escaped newlines (\n).
    # We will trust the requests library to handle the JSON encoding correctly,
    # which includes preserving the newlines in the multi-line string.
    return public_key_content.strip()

def request_encrypted_seed():
    """Requests the encrypted seed from the instructor API."""
    print(f"Attempting to read public key from {PUBLIC_KEY_FILE}...")
    try:
        public_key_content = get_public_key_pem(PUBLIC_KEY_FILE)
    except FileNotFoundError as e:
        print(f"ERROR: {e}")
        print("Please ensure you have completed Step 1.2.")
        return

    # 1. Prepare the JSON request body
    payload = {
        "student_id": STUDENT_ID,
        "github_repo_url": GITHUB_REPO_URL,
        "public_key": public_key_content
    }

    # CRITICAL CHECK: Verify the configuration is not the default placeholder
    if STUDENT_ID == "YOUR_STUDENT_ID" or GITHUB_REPO_URL == "https://github.com/yourusername/your-repo-name":
        print("🛑 ERROR: Please update STUDENT_ID and GITHUB_REPO_URL in the script before running!")
        return
    
    print(f"Sending request to API for Student ID: {STUDENT_ID}")
    print(f"Using GitHub URL: {GITHUB_REPO_URL}")

    # 2. Send the POST request
    try:
        response = requests.post(API_URL, json=payload, timeout=10)
        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)

        data = response.json()

        # 3. Parse and save the encrypted seed
        if data.get("status") == "success" and "encrypted_seed" in data:
            encrypted_seed = data["encrypted_seed"]
            
            # Save the seed to the output file
            with open(OUTPUT_FILE, "w") as f:
                f.write(encrypted_seed.strip())
            
            print(f"✅ Successfully received encrypted seed.")
            print(f"   Seed saved to {OUTPUT_FILE}. DO NOT COMMIT THIS FILE.")
            print(f"   Seed length: {len(encrypted_seed.strip())} characters.")

        else:
            print(f"🛑 API Error Response: {data.get('error', 'Unknown error')}")

    except requests.exceptions.RequestException as e:
        print(f"🛑 Network/API Request Failed: {e}")
        print("Check API_URL, network connection, and ensure public key is valid.")

if __name__ == "__main__":
    request_encrypted_seed()