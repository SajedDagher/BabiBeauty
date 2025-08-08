from cryptography.fernet import Fernet

def generate_key():
    return Fernet.generate_key()


def encrypt_message(message, key):
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())
    return encrypted_message


def decrypt_message(encrypted_message, key):
    fernet = Fernet(key)
    decrypted_message = fernet.decrypt(encrypted_message).decode()
    return decrypted_message


if __name__ == "__main__":
    key = generate_key()
    print("Shared Secret Key:", key.decode())

    message = "Hello, this is a secret message!"
    print("Original Message:", message)

    encrypted = encrypt_message(message, key)
    print("Encrypted Message:", encrypted)

    decrypted = decrypt_message(encrypted, key)
    print("Decrypted Message:", decrypted)