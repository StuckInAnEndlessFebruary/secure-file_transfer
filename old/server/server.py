# server/server.py
import socket
import threading
from database import init_db, get_user, add_user, update_role
from auth import authenticate, authorize
from crypto_utils import *
from file_handler import store_file, retrieve_file, delete_file

HOST = 'localhost'
PORT = 12345

def handle_client(conn, addr):
    print(f"[+] اتصال از {addr}")
    
    # مرحله ثبت‌نام یا ورود
    conn.send(b"login or register?")
    choice = conn.recv(1024).decode()

    conn.send(b"username:")
    username = conn.recv(1024).decode()

    conn.send(b"password:")
    password = conn.recv(1024).decode()

    if choice == "register":
        conn.send(b"Send your public key PEM:")
        pub_key = conn.recv(2048).decode()
        try:
            add_user(username, password, "guest", pub_key)
            conn.send(b"Registration successful.")
        except:
            conn.send(b"Username already exists.")
            conn.close()
            return
    elif choice == "login":
        if not authenticate(username, password):
            conn.send(b"Authentication failed.")
            conn.close()
            return
        conn.send(b"Login successful.")

    # ایجاد symmetric key و ارسال
    session_key = generate_symmetric_key()
    conn.send(session_key)

    # شروع حلقه فرمان
    while True:
        conn.send(b"Enter command:")
        cmd = conn.recv(1024).decode()

        if cmd.startswith("upload"):
            _, filename = cmd.split()
            if not authorize(username, "upload"):
                conn.send(b"Unauthorized.")
                continue

            conn.send(b"Send signed+encrypted file")
            data = conn.recv(1000000)
            store_file(filename, data)
            conn.send(b"Upload successful.")

        elif cmd.startswith("download"):
            _, filename = cmd.split()
            if not authorize(username, "download"):
                conn.send(b"Unauthorized.")
                continue

            data = retrieve_file(filename)
            if not data:
                conn.send(b"File not found.")
                continue
            conn.send(data)

        elif cmd.startswith("delete"):
            _, filename = cmd.split()
            if not authorize(username, "delete"):
                conn.send(b"Unauthorized.")
                continue

            if delete_file(filename):
                conn.send(b"File deleted.")
            else:
                conn.send(b"File not found.")

        elif cmd.startswith("change_role"):
            if not authorize(username, "change_role"):
                conn.send(b"Unauthorized.")
                continue
            _, target_user, new_role = cmd.split()
            update_role(target_user, new_role)
            conn.send(b"Role updated.")

        elif cmd == "exit":
            conn.send(b"Goodbye.")
            break

    conn.close()

def start_server():
    init_db()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen()
    print(f"[*] Server listening on {HOST}:{PORT}")

    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()

from database import init_default_users
...
if __name__ == "__main__":
    print("now server:")
    init_default_users()  # ← اضافه کردن کاربران اولیه
    start_server()
