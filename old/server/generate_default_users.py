# server/generate_default_users.py
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

default_users = {
    "admin1": "admin",
    "maint1": "maintainer",
    "guest1": "guest",
    "guest2": "guest",
    "guest3": "guest"
}

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PRIVATE_KEYS_DIR = os.path.join(BASE_DIR, "keys", "private_keys")
PUBLIC_KEYS_DIR = os.path.join(BASE_DIR, "keys", "public_keys")

os.makedirs(PRIVATE_KEYS_DIR, exist_ok=True)
os.makedirs(PUBLIC_KEYS_DIR, exist_ok=True)

def generate_keys(username):
    print(f"🔧 تولید کلید برای {username}...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    priv_path = os.path.join(PRIVATE_KEYS_DIR, f"{username}_private.pem")
    pub_path = os.path.join(PUBLIC_KEYS_DIR, f"{username}_public.pem")

    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))

    with open(pub_path, "wb") as f:
        f.write(private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    return pub_path

if __name__ == "__main__":
    print("🔑 در حال تولید کلیدها برای کاربران اولیه...")
    for user in default_users:
        path = generate_keys(user)
        print(f"✅ کلید برای {user} ساخته شد: {path}")
