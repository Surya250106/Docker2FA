#!/usr/bin/env python3

import sys
import os
import datetime
# Assuming cryptography_utils and storage_utils are accessible in the PATH 
# or are copied to /app, allowing relative import if the cwd is /app.
try:
    from cryptography_utils import generate_totp_code_and_time
    from storage_utils import SEED_FILE_PATH
except ImportError:
    # Fallback/Debug if imports fail in the cron environment
    sys.stderr.write("ERROR: Failed to import necessary utilities.\n")
    sys.exit(1)

def run_cron_job():
    """Reads the seed, generates TOTP, and logs it with a UTC timestamp."""
    
    # 1. Read hex seed from persistent storage
    if not os.path.exists(SEED_FILE_PATH):
        sys.stderr.write(f"{datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} - ERROR: Seed file not found at {SEED_FILE_PATH}. Run /decrypt-seed first.\n")
        return
    
    try:
        with open(SEED_FILE_PATH, 'r') as f:
            hex_seed = f.read().strip()
    except Exception as e:
        sys.stderr.write(f"{datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} - ERROR reading seed file: {e}\n")
        return

    if not hex_seed:
        sys.stderr.write(f"{datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} - ERROR: Seed file is empty.\n")
        return

    try:
        # 2. Generate current TOTP code (we ignore valid_for here, only need the code)
        code, _ = generate_totp_code_and_time(hex_seed)
        
        # 3. Get current UTC timestamp
        timestamp_utc = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        
        # 4. Output formatted line to stdout (which cron redirects to /cron/last_code.txt)
        print(f"{timestamp_utc} - 2FA Code: {code}")

    except Exception as e:
        sys.stderr.write(f"{datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} - FATAL TOTP GENERATION ERROR: {e}\n")

if __name__ == "__main__":
    run_cron_job()