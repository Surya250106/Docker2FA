from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def generate_rsa_keypair(key_size: int = 4096):
    """
    Generates an RSA 4096-bit key pair with public exponent 65537
    and saves them to student_private.pem and student_public.pem in PEM format.
    """
    # 1. Generate the private key
    # Required parameters: 4096 bits, public exponent 65537
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    
    # Get the corresponding public key
    public_key = private_key.public_key()
    
    # 2. Serialize and save the private key (student_private.pem)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        # Use NoEncryption since the key MUST be readable by the Docker container
        # for decryption and signing without a passphrase.
        encryption_algorithm=serialization.NoEncryption()
    )
    
    with open("student_private.pem", "wb") as f:
        f.write(private_pem)
    
    print("✅ Created student_private.pem (4096-bit, PKCS8 format)")
    
    # 3. Serialize and save the public key (student_public.pem)
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    with open("student_public.pem", "wb") as f:
        f.write(public_pem)
        
    print("✅ Created student_public.pem (4096-bit, SubjectPublicKeyInfo format)")
    
    # Returning the key objects might be useful for Step 13, but the PEM files
    # are the core requirement for saving/submission.
    return private_key, public_key

if __name__ == "__main__":
    generate_rsa_keypair(key_size=4096)