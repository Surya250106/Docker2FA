import os

SEED_FILE_PATH = "/data/seed.txt"

def read_seed() -> str | None:
    """Reads the hex seed from the persistent volume location."""
    if not os.path.exists(SEED_FILE_PATH):
        return None
    try:
        with open(SEED_FILE_PATH, 'r') as f:
            return f.read().strip()
    except IOError:
        return None

def write_seed(hex_seed: str) -> bool:
    """Writes the decrypted hex seed to the persistent volume location."""
    # Ensure the /data directory exists before writing
    os.makedirs(os.path.dirname(SEED_FILE_PATH), exist_ok=True)
    try:
        with open(SEED_FILE_PATH, 'w') as f:
            f.write(hex_seed)
        return True
    except IOError:
        return False