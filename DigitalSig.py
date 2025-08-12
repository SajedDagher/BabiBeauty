from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization  # <-- Missing import added
from cryptography.hazmat.backends import default_backend
import base64

def generate_keys():
    """Generate RSA private and public keys."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def sign_message(message, private_key):
    """Sign a message using the private key (SHA-256 + PSS padding)."""
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()  # Base64 for easy sharing

def verify_signature(message, signature, public_key):
    """Verify the signature using the public key."""
    try:
        signature_bytes = base64.b64decode(signature.encode())
        public_key.verify(
            signature_bytes,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Verification error: {e}")  # Debugging
        return False

def serialize_key(key, is_private=False):
    """Convert key to PEM format."""
    if is_private:
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
    else:
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

def deserialize_key(key_str, is_private=False):
    """Load key from PEM string."""
    try:
        if is_private:
            return serialization.load_pem_private_key(
                key_str.encode(),
                password=None,
                backend=default_backend()
            )
        else:
            return serialization.load_pem_public_key(
                key_str.encode(),
                backend=default_backend()
            )
    except Exception as e:
        print(f"Key deserialization error: {e}")  # Debugging
        return None

def main():
    print(" Digital Signature Demo (RSA-PSS)")
    print("----------------------------------")
    print("1. Sign a message (with private key)")
    print("2. Verify a signature (with public key)")
    print("3. Exit")
    
    private_key, public_key = None, None
    
    while True:
        choice = input("\nChoose action (1/2/3): ").strip()
        
        if choice == "1":
            # Generate keys and sign
            private_key, public_key = generate_keys()
            message = input("Enter message to sign: ")
            
            signature = sign_message(message, private_key)
            pub_key_str = serialize_key(public_key)
            priv_key_str = serialize_key(private_key, is_private=True)
            
            print("\n Message signed successfully!")
            print(f" Message: {message}")
            print(f" Signature (Base64): {signature}")
            print(f"\nPublic Key (Share for verification):\n{pub_key_str}")
            print(f"\n Private Key (Keep secret!):\n{priv_key_str}")
        
        elif choice == "2":
            # Verify signature
            message = input("Enter original message: ")
            signature = input("Enter signature (Base64): ").strip()
            pub_key_str = input("Paste sender's public key (PEM):\n").strip()
            
            public_key = deserialize_key(pub_key_str)
            if not public_key:
                print(" Invalid public key format!")
                continue
            
            is_valid = verify_signature(message, signature, public_key)
            if is_valid:
                print("\nSignature is VALID. Message is authentic and unaltered.")
            else:
                print("\n Signature is INVALID. Message may be corrupted or forged!")
        
        elif choice == "3":
            print("Exiting...")
            break
        
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()