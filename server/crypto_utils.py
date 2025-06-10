from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet
import os

def generate_symmetric_key():
    return Fernet.generate_key()

def encrypt_with_symmetric_key(key, data):
    return Fernet(key).encrypt(data)

def decrypt_with_symmetric_key(key, encrypted_data):
    return Fernet(key).decrypt(encrypted_data)

def sign_data(private_key_pem, data):
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    return private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())

def verify_signature(public_key_pem, data, signature):
    public_key = serialization.load_pem_public_key(public_key_pem)
    try:
        public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False
