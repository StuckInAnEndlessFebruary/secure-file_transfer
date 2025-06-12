#client.py
import socket
import json
import os
import base64
import hashlib
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from getpass import getpass

# تنظیمات کلاینت
HOST = '127.0.0.1'
PORT = 65432
CLIENT_KEYS_FOLDER = 'client_keys'

class FileClient:
    def __init__(self):
        self.username = None
        self.role = None
        self.private_key = None
        self.public_key = None
        self.sym_key = None
        self.conn = None
    
    def start(self):
        print("\n=== Secure File Transfer System ===")
        while True:
            print("\n1. Login")
            print("2. Sign Up")
            print("3. Exit")
            choice = input("Select option: ")
            
            if choice == '1':
                if self.login():
                    self.main_menu()
            elif choice == '2':
                self.signup()
            elif choice == '3':
                print("Goodbye!")
                break
            else:
                print("Invalid option")

    def login(self):
        print("\n=== Login ===")
        username = input("Username: ")
        password = getpass("Password: ")
        
        # بارگذاری کلید عمومی برای احراز هویت
        try:
            with open(f'{CLIENT_KEYS_FOLDER}/{username}_private.pem', 'rb') as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
            self.public_key = self.private_key.public_key()
        except:
            print("No key found for this user. Please sign up first.")
            return False
        
        auth_data = {
            'action': 'login',
            'username': username,
            'password': password,
            'public_key': self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        }
        
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.conn.connect((HOST, PORT))
            self.conn.sendall(json.dumps(auth_data).encode())
            
            response = json.loads(self.conn.recv(4096).decode())
            if response['status'] == 'success':
                self.username = username
                self.role = response['role']
                
                # رمزگشایی کلید متقارن
                encrypted_sym_key = base64.b64decode(response['sym_key'])
                self.sym_key = self.private_key.decrypt(
                    encrypted_sym_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                print(f"Logged in as {username} ({self.role})")
                return True
            else:
                print(f"Login failed: {response['message']}")
                self.conn.close()
                return False
        except Exception as e:
            print(f"Connection error: {str(e)}")
            return False

    def signup(self):
        print("\n=== Sign Up ===")
        username = input("Choose username: ")
        password = getpass("Choose password: ")
        confirm_password = getpass("Confirm password: ")
        
        if password != confirm_password:
            print("Passwords don't match!")
            return
        
        # تولید کلیدهای RSA برای کاربر جدید
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        # ذخیره کلید خصوصی محلی
        os.makedirs(CLIENT_KEYS_FOLDER, exist_ok=True)
        with open(f'{CLIENT_KEYS_FOLDER}/{username}_private.pem', 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        auth_data = {
            'action': 'signup',
            'username': username,
            'password': password,
            'public_key': public_key
        }
        
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            conn.connect((HOST, PORT))
            conn.sendall(json.dumps(auth_data).encode())
            
            response = json.loads(conn.recv(4096).decode())
            if response['status'] == 'success':
                print("Registration successful! You can now login.")
            else:
                print(f"Registration failed: {response['message']}")
        except Exception as e:
            print(f"Connection error: {str(e)}")
        finally:
            conn.close()

    def main_menu(self):
        while True:
            print(f"\n=== Main Menu ({self.username} - {self.role}) ===")
            print("1. Upload File")
            print("2. Download File")
            print("3. List Files")
            print("4. Delete File")
            if self.role == 'admin':
                print("5. User Management")
            print("6. Logout")
            
            choice = input("Select option: ")
            
            if choice == '6':
                self.logout()
                break
            
            try:
                if choice == '1':
                    self.upload_file()
                elif choice == '2':
                    self.download_file()
                elif choice == '3':
                    self.list_files()
                elif choice == '4':
                    self.delete_file()
                elif choice == '5' and self.role == 'admin':
                    self.user_management()
                else:
                    print("Invalid option")
            except Exception as e:
                print(f"Error: {str(e)}")

    def upload_file(self):
        file_path = input("Enter file path to upload: ")
        if not os.path.exists(file_path):
            print("File not found!")
            return
        
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # امضا کردن فایل
        signature = self.private_key.sign(
            file_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # رمزنگاری فایل با کلید متقارن
        encrypted_file_data = self.encrypt_with_sym_key(file_data)
        
        request = {
            'action': 'upload',
            'filename': os.path.basename(file_path),
            'file_data': base64.b64encode(encrypted_file_data).decode(),
            'signature': base64.b64encode(signature).decode(),
            'conn': self.conn
        }
        
        response = self.send_request(request)
        if response['status'] == 'success':
            print(f"File uploaded successfully! File ID: {response['file_id']}")
        else:
            print(f"Upload failed: {response['message']}")

    def download_file(self):
        file_id = input("Enter file ID to download: ")
        
        request = {
            'action': 'download',
            'file_id': int(file_id),
            'conn': self.conn
        }
        
        response = self.send_request(request)
        if response['status'] == 'success':
            file_data = base64.b64decode(response['file_data'])
            signature = base64.b64decode(response['signature'])
            owner = response['owner']
            
            # بارگذاری کلید عمومی مالک فایل
            pub_key_request = {
                'action': 'get_user_pubkey',
                'username': owner,
                'conn': self.conn
            }
            pub_key_response = self.send_request(pub_key_request)
            
            if pub_key_response['status'] == 'success':
                owner_pub_key = serialization.load_pem_public_key(
                    pub_key_response['public_key'].encode(),
                    backend=default_backend()
                )
                
                try:
                    owner_pub_key.verify(
                        signature,
                        file_data,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    
                    save_path = input(f"Enter path to save '{response['filename']}': ")
                    with open(save_path, 'wb') as f:
                        f.write(file_data)
                    print("File downloaded and verified successfully!")
                except:
                    print("Warning: File integrity check failed!")
            else:
                print("Failed to verify file signature")
        else:
            print(f"Download failed: {response['message']}")

    def list_files(self):
        request = {
            'action': 'list_files',
            'conn': self.conn
        }
        
        response = self.send_request(request)
        if response['status'] == 'success':
            print("\nAvailable Files:")
            for file in response['files']:
                print(f"ID: {file['file_id']}, Name: {file['filename']}, Owner: {file['owner']}")
        else:
            print(f"Error: {response['message']}")

    def delete_file(self):
        file_id = input("Enter file ID to delete: ")
        
        request = {
            'action': 'delete_file',
            'file_id': int(file_id),
            'conn': self.conn
        }
        
        response = self.send_request(request)
        if response['status'] == 'success':
            print("File deleted successfully!")
        else:
            print(f"Deletion failed: {response['message']}")

    def user_management(self):
        while True:
            print("\n=== User Management ===")
            print("1. List Users")
            print("2. Update User Role")
            print("3. Delete User")
            print("4. Back to Main Menu")
            
            choice = input("Select option: ")
            
            if choice == '4':
                break
            
            try:
                if choice == '1':
                    self.list_users()
                elif choice == '2':
                    self.update_user_role()
                elif choice == '3':
                    self.delete_user()
                else:
                    print("Invalid option")
            except Exception as e:
                print(f"Error: {str(e)}")

    def list_users(self):
        request = {
            'action': 'list_users',
            'conn': self.conn
        }
        
        response = self.send_request(request)
        if response['status'] == 'success':
            print("\nUsers:")
            for user in response['users']:
                print(f"Username: {user['username']}, Role: {user['role']}")
        else:
            print(f"Error: {response['message']}")

    def update_user_role(self):
        username = input("Enter username to update: ")
        new_role = input("Enter new role (admin/maintainer/guest): ")
        
        if new_role not in ['admin', 'maintainer', 'guest']:
            print("Invalid role")
            return
        
        request = {
            'action': 'update_role',
            'username': username,
            'role': new_role,
            'conn': self.conn
        }
        
        response = self.send_request(request)
        if response['status'] == 'success':
            print("User role updated successfully!")
        else:
            print(f"Error: {response['message']}")

    def delete_user(self):
        username = input("Enter username to delete: ")
        
        request = {
            'action': 'delete_user',
            'username': username,
            'conn': self.conn
        }
        
        response = self.send_request(request)
        if response['status'] == 'success':
            print("User deleted successfully!")
        else:
            print(f"Error: {response['message']}")

    def logout(self):
        if self.conn:
            self.conn.close()
        self.username = None
        self.role = None
        self.sym_key = None
        print("Logged out successfully")

    def send_request(self, request):
        encrypted_request = self.encrypt_with_sym_key(json.dumps(request).encode())
        self.conn.sendall(encrypted_request)
        
        encrypted_response = self.conn.recv(4096)
        response = json.loads(self.decrypt_with_sym_key(encrypted_response).decode())
        return response

    def encrypt_with_sym_key(self, data):
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(self.sym_key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext

    def decrypt_with_sym_key(self, data):
        iv = data[:16]
        tag = data[16:32]
        ciphertext = data[32:]
        cipher = Cipher(
            algorithms.AES(self.sym_key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

if __name__ == '__main__':
    client = FileClient()
    client.start()