# client/client.py
import socket
from crypto_utils import *
import os

HOST = 'localhost'
PORT = 12345

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    print(s.recv(1024).decode())  # login or register?
    s.send(input("(login/register): ").encode())

    username = input("Username: ")
    s.send(username.encode())

    password = input("Password: ")
    s.send(password.encode())

    msg = s.recv(1024).decode()
    print(msg)

    if msg == "Send your public key PEM:":
        with open(f"../keys/public_keys/{username}_public.pem", "rb") as f:
            s.send(f.read())
        print(s.recv(1024).decode())

    elif msg == "Authentication failed.":
        return

    # دریافت کلید متقارن از سرور
    session_key = s.recv(1024)
    print("[+] Session key received.")

    while True:
        command = input("Command (upload/download/delete/change_role/exit): ")
        s.send(command.encode())

        if command.startswith("upload"):
            _, filename = command.split()
            path = f"./uploads/{filename}"

            if not os.path.exists(path):
                print("File not found.")
                continue

            s_msg = s.recv(1024).decode()
            if s_msg != "Send signed+encrypted file":
                print(s_msg)
                continue

            with open(path, 'rb') as f:
                data = f.read()

            priv_key = load_private_key(f"../keys/private_keys/{username}_private.pem")
            signed = sign_file(priv_key, data)
            combined = signed + b"::" + data
            encrypted = encrypt_file_with_key(session_key, combined)

            s.send(encrypted)
            print(s.recv(1024).decode())

        elif command.startswith("download"):
            _, filename = command.split()
            data = s.recv(1000000)
            if data.startswith(b"File not found"):
                print("File not found.")
                continue

            decrypted = decrypt_file_with_key(session_key, data)
            signature, file_content = decrypted.split(b"::")

            # خواندن کلید عمومی کاربر آپلودکننده — در حالت واقعی باید مشخص باشد
            pub_key_path = f"../keys/public_keys/{username}_public.pem"
            with open(pub_key_path, "rb") as f:
                pub_key = serialization.load_pem_public_key(f.read())

            try:
                pub_key.verify(signature, file_content, padding.PKCS1v15(), hashes.SHA256())
                print("✔ Signature valid.")
            except:
                print("✘ Signature invalid!")

            with open(f"./downloads/{filename}", 'wb') as f:
                f.write(file_content)
                print("File saved.")

        elif command.startswith("delete") or command.startswith("change_role"):
            print(s.recv(1024).decode())

        elif command == "exit":
            print(s.recv(1024).decode())
            break

if __name__ == "__main__":
    main()
