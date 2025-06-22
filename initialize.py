import os
import shutil
import secrets
import sqlite3
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from hashlib import sha256
from server import init_db
import sys

DB = 'server_data.db'
LOG_FILE = 'initialize.txt'

class DualLogger:
    def __init__(self, filename):
        self.terminal = sys.stdout
        self.log = open(filename, 'w', encoding='utf-8')

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)

    def flush(self):
        self.terminal.flush()
        self.log.flush()

# جایگزین کردن خروجی پیش‌فرض با DualLogger
sys.stdout = DualLogger(LOG_FILE)


def initialize_system():
    print("Initializing system...")

    # 1) پاکسازی پوشه‌ها و فایل‌های قبلی
    for path in ('server_keys', 'client_keys', 'server_files'):
        if os.path.exists(path):
            shutil.rmtree(path)
    if os.path.exists(DB):
        os.remove(DB)

    # 2) ایجاد ساختار پوشه‌ها
    os.makedirs('server_keys', exist_ok=True)
    os.makedirs('client_keys', exist_ok=True)
    os.makedirs('server_files', exist_ok=True)

    # 3) تولید کلید SDEK (در صورت نیاز)
    sdek = secrets.token_bytes(32)
    with open(os.path.join('server_keys', 'sdek.key'), 'wb') as f:
        f.write(sdek)
    print("SDEK generated and saved.")

    # 4) مقداردهی اولیه دیتابیس
    init_db()

    # 5) ایجاد کاربران پیش‌فرض
    create_default_users()

    print("\nSystem initialized successfully!")
    print("Default users created with their passwords and key-pairs.")
    print("Passwords are printed below. Private keys are in 'client_keys/'.")


def create_default_users():
    print("Creating default users...")
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()

    default_users = [
        {'username': 'admin', 'role': 'admin'},
        {'username': 'maintainer', 'role': 'maintainer'},
        {'username': 'guest1', 'role': 'guest'}
    ]

    for user in default_users:
        username = user['username']
        role = user['role']
        password = secrets.token_urlsafe(12)

        # تولید کلید خصوصی و عمومی
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # سریال‌سازی کلیدها
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        # هش رمز عبور
        hashed_password = sha256(password.encode()).hexdigest()

        try:
            cursor.execute(
                "INSERT INTO users (username, password, role, public_key) VALUES (?, ?, ?, ?)",
                (username, hashed_password, role, public_pem)
            )
            print(f"  • User: {username}, Password: {password}")

            # ذخیره کلید خصوصی
            with open(os.path.join('client_keys', f"{username}_private.pem"), 'wb') as f:
                f.write(private_pem)

        except sqlite3.IntegrityError:
            print(f"User {username} already exists.")
        except Exception as e:
            print(f"Error creating user {username}: {e}")

    conn.commit()
    conn.close()
    print("Default users processed.")


if __name__ == '__main__':
    initialize_system()
