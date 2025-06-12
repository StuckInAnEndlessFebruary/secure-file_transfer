# server/database.py
import sqlite3

def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'guest',
            public_key TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def add_user(username, password, role, public_key):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("INSERT INTO users VALUES (?, ?, ?, ?)", (username, password, role, public_key))
    conn.commit()
    conn.close()

def get_user(username):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    conn.close()
    return user

def update_role(username, new_role):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("UPDATE users SET role = ? WHERE username = ?", (new_role, username))
    conn.commit()
    conn.close()


import os

def init_default_users():
    if os.path.exists("users.db"):
        return  # دیتابیس وجود دارد → نیازی به ایجاد نیست

    print("⚙ ایجاد دیتابیس و افزودن کاربران اولیه...")

    init_db()

    default_users = {
        "admin1": ("1234", "admin"),
        "maint1": ("1234", "maintainer"),
        "guest1": ("1234", "guest"),
        "guest2": ("1234", "guest"),
        "guest3": ("1234", "guest")
    }

    for username, (password, role) in default_users.items():
        try:
            with open(f"../keys/public_keys/{username}_public.pem", "rb") as f:
                pub_key_pem = f.read()
                add_user(username, password, role, pub_key_pem)
                print(f"✅ کاربر {username} با نقش {role} افزوده شد.")
        except Exception as e:
            print(f"❌ خطا در افزودن {username}: {e}")
