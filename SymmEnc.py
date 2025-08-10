from cryptography.fernet import Fernet

def generate_key():
    """Generate a symmetric key for encryption."""
    return Fernet.generate_key()

def encrypt_message(message, key):
    """Encrypt a message using the key."""
    fernet = Fernet(key)
    return fernet.encrypt(message.encode())

def decrypt_message(encrypted_message, key):
    """Decrypt a message using the key."""
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_message).decode()

def main():
    while True:
        print("\n Menu:")
        print("1. Encrypt a message")
        print("2. Decrypt a message")
        print("3. Exit")
        choice = input("Choose an option (1/2/3): ")

        if choice == "1":
            # Encrypt
            message = input("Enter the message to encrypt: ")
            key = generate_key()
            encrypted = encrypt_message(message, key)
            print("\nncryption Successful!")
            print(f" Key: {key.decode()}")
            print(f" Encrypted Message: {encrypted.decode()}")

        elif choice == "2":
            # Decrypt
            encrypted_input = input("Enter the encrypted message: ").strip()
            key_input = input("Enter the secret key: ").strip()
            
            try:
                decrypted = decrypt_message(encrypted_input.encode(), key_input.encode())
                print("\nDecryption Successful!")
                print(f" Original Message: {decrypted}")
            except Exception as e:
                print(f"\nError: {e} (Invalid key or message!)")

        elif choice == "3":
            print("Exiting...")
            break

        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()