from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

def generate_keys():
    """Generate RSA public/private key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_message(message, public_key):
    """Encrypt a message using the public key."""
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def decrypt_message(encrypted_message, private_key):
    """Decrypt a message using the private key."""
    decrypted = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

def main():
    print(" Asymmetric Encryption (RSA) Demo")
    print("===================================")
    print("Key Principles:")
    print("- Encryption uses the PUBLIC KEY (shared with others)")
    print("- Decryption uses the PRIVATE KEY (kept secret)")
    print("===================================\n")
    
    private_key, public_key = generate_keys()

    # Serialize keys to PEM format (for storage/sharing)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    print("\n Public Key (Share this for ENCRYPTION):")
    print(public_pem.decode())
    print("\n Private Key (Keep this SECRET for DECRYPTION):")
    print(private_pem.decode())

    # Encrypt
    message = input("\nEnter a message to encrypt (using PUBLIC key): ")
    encrypted = encrypt_message(message, public_key)
    print("\n Message encrypted with PUBLIC KEY:")
    print("Encrypted Bytes:", encrypted)

    # Decrypt
    input("\nPress Enter to decrypt (using PRIVATE key)...")
    decrypted = decrypt_message(encrypted, private_key)
    print("\n Message decrypted with PRIVATE KEY:")
    print("Original Message:", decrypted)

if __name__ == "__main__":
    main()