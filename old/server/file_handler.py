# server/file_handler.py
import os
from crypto_utils import encrypt_with_symmetric_key, decrypt_with_symmetric_key

ENCRYPTED_FOLDER = 'server_files/'
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)

def store_file(filename, encrypted_data):
    with open(os.path.join(ENCRYPTED_FOLDER, filename), 'wb') as f:
        f.write(encrypted_data)

def retrieve_file(filename):
    path = os.path.join(ENCRYPTED_FOLDER, filename)
    if not os.path.exists(path):
        return None
    with open(path, 'rb') as f:
        return f.read()

def delete_file(filename):
    path = os.path.join(ENCRYPTED_FOLDER, filename)
    if os.path.exists(path):
        os.remove(path)
        return True
    return False
