# client/crypto_utils.py
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet

def load_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def sign_file(private_key, data):
    return private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

def encrypt_file_with_key(key, data):
    return Fernet(key).encrypt(data)

def decrypt_file_with_key(key, encrypted_data):
    return Fernet(key).decrypt(encrypted_data)
