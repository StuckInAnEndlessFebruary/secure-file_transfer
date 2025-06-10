# client/user_keygen.py
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

def generate_keys(username):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # ذخیره کلید خصوصی
    priv_path = f"../keys/private_keys/{username}_private.pem"
    os.makedirs(os.path.dirname(priv_path), exist_ok=True)
    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # ذخیره کلید عمومی
    public_key = private_key.public_key()
    pub_path = f"../keys/public_keys/{username}_public.pem"
    os.makedirs(os.path.dirname(pub_path), exist_ok=True)
    with open(pub_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(f"کلیدها برای {username} تولید شدند.")

if __name__ == "__main__":
    uname = input("نام کاربری:")
    generate_keys(uname)
