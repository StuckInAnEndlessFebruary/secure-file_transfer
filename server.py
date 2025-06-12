#server.py
import socket
import threading
import sqlite3
import os
import json
import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from getpass import getpass
import secrets

# تنظیمات سرور
HOST = '127.0.0.1'
PORT = 65432
DATABASE = 'file_server.db'
SERVER_KEY_FOLDER = 'server_keys'
FILES_FOLDER = 'server_files'
DEFAULT_ADMIN = {'username': 'admin', 'password': 'Admin@123', 'role': 'admin'}
DEFAULT_MAINTAINER = {'username': 'maintainer', 'password': 'Maintainer@123', 'role': 'maintainer'}
DEFAULT_GUESTS = [
    {'username': 'guest1', 'password': 'Guest1@123', 'role': 'guest'},
    {'username': 'guest2', 'password': 'Guest2@123', 'role': 'guest'},
    {'username': 'guest3', 'password': 'Guest3@123', 'role': 'guest'}
]

# ایجاد پوشه‌های مورد نیاز
os.makedirs(SERVER_KEY_FOLDER, exist_ok=True)
os.makedirs(FILES_FOLDER, exist_ok=True)

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_bytes(16)
    else:
        salt = bytes.fromhex(salt)
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return password_hash.hex(), salt.hex()

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            public_key TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'guest'
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            file_id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            owner TEXT NOT NULL,
            signature TEXT NOT NULL,
            FOREIGN KEY (owner) REFERENCES users(username)
        )
    ''')
    
    # ایجاد کاربران پیش‌فرض
    default_users = [
        {
            'username': 'admin',
            'password': 'Admin@123',
            'role': 'admin'
        },
        {
            'username': 'maintainer',
            'password': 'Maintainer@123',
            'role': 'maintainer'
        },
        {
            'username': 'guest1',
            'password': 'Guest1@123',
            'role': 'guest'
        },
        {
            'username': 'guest2',
            'password': 'Guest2@123',
            'role': 'guest'
        },
        {
            'username': 'guest3',
            'password': 'Guest3@123',
            'role': 'guest'
        }
    ]
    
    # ایجاد پوشه client_keys اگر وجود ندارد
    os.makedirs('client_keys', exist_ok=True)
    
    for user in default_users:
        # هش کردن رمز عبور
        salt = secrets.token_bytes(16)
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            user['password'].encode(),
            salt,
            100000
        )
        
        # تولید کلیدهای RSA برای کاربر
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # ذخیره کلید عمومی در پایگاه داده
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        # ذخیره کلید خصوصی در پوشه client_keys
        private_key_file = os.path.join('client_keys', f"{user['username']}_private.pem")
        with open(private_key_file, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        try:
            cursor.execute(
                'INSERT INTO users VALUES (?, ?, ?, ?, ?)',
                (
                    user['username'],
                    password_hash.hex(),
                    salt.hex(),
                    public_key,
                    user['role']
                )
            )
            print(f"User {user['username']} created successfully.")
        except sqlite3.IntegrityError:
            print(f"User {user['username']} already exists, skipping...")
            continue
    
    conn.commit()
    conn.close()
    
    print("Database initialization completed.")
    print("Default users created:")
    print("- admin (Admin@123)")
    print("- maintainer (Maintainer@123)")
    print("- guest1 (Guest1@123)")
    print("- guest2 (Guest2@123)")
    print("- guest3 (Guest3@123)")
def generate_server_keys():
    if not os.path.exists(SERVER_KEY_FOLDER):
        os.makedirs(SERVER_KEY_FOLDER)
    
    if not os.path.exists(f'{SERVER_KEY_FOLDER}/server_private.pem'):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        with open(f'{SERVER_KEY_FOLDER}/server_private.pem', 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        public_key = private_key.public_key()
        with open(f'{SERVER_KEY_FOLDER}/server_public.pem', 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print("Server keys generated successfully!")
class UserManager:
    @staticmethod
    def verify_login(username, password):
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash, salt, role FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return None
        
        stored_hash, salt, role = result
        input_hash, _ = hash_password(password, salt)
        
        if input_hash == stored_hash:
            return role
        return None

    @staticmethod
    def add_user(username, password, public_key):
        password_hash, salt = hash_password(password)
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        try:
            cursor.execute(
                'INSERT INTO users VALUES (?, ?, ?, ?, ?)',
                (username, password_hash, salt, public_key, 'guest')
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()

    @staticmethod
    def get_user_role(username):
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT role FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None

    @staticmethod
    def get_all_users():
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT username, role FROM users')
        users = cursor.fetchall()
        conn.close()
        return users

    @staticmethod
    def update_user_role(username, new_role):
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET role = ? WHERE username = ?', (new_role, username))
        conn.commit()
        conn.close()

    @staticmethod
    def delete_user(username):
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM users WHERE username = ?', (username,))
        conn.commit()
        conn.close()

class FileManager:
    @staticmethod
    def add_file(filename, owner, signature):
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO files (filename, owner, signature) VALUES (?, ?, ?)',
            (filename, owner, signature)
        )
        file_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return file_id

    @staticmethod
    def get_file(file_id):
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM files WHERE file_id = ?', (file_id,))
        file_info = cursor.fetchone()
        conn.close()
        return file_info

    @staticmethod
    def get_all_files():
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM files')
        files = cursor.fetchall()
        conn.close()
        return files

    @staticmethod
    def delete_file(file_id, username):
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('SELECT owner FROM files WHERE file_id = ?', (file_id,))
        owner = cursor.fetchone()
        
        if owner and (owner[0] == username or UserManager.get_user_role(username) == 'admin'):
            cursor.execute('DELETE FROM files WHERE file_id = ?', (file_id,))
            conn.commit()
            conn.close()
            
            try:
                os.remove(f'{FILES_FOLDER}/{file_id}')
                return True
            except:
                return False
        conn.close()
        return False

class FileServer:
    def __init__(self):
        self.sessions = {}
        self.load_server_keys()

    def load_server_keys(self):
        with open(f'{SERVER_KEY_FOLDER}/server_private.pem', 'rb') as f:
            self.server_private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        
        with open(f'{SERVER_KEY_FOLDER}/server_public.pem', 'rb') as f:
            self.server_public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )

    def start(self):
        init_db()
        generate_server_keys()
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            s.listen()
            print(f"Server listening on {HOST}:{PORT}")
            
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr)).start()

    def handle_client(self, conn, addr):
        print(f"New connection from {addr}")
        try:
            auth_data = conn.recv(4096)
            if not auth_data:
                conn.close()
                return
                
            auth_data = json.loads(auth_data.decode())
            action = auth_data.get('action')
            
            if action == 'login':
                username = auth_data['username']
                password = auth_data['password']
                role = UserManager.verify_login(username, password)
                
                if role:
                    sym_key = os.urandom(32)
                    self.sessions[conn] = {'username': username, 'sym_key': sym_key}
                    
                    user_pub_key = serialization.load_pem_public_key(
                        auth_data['public_key'].encode(),
                        backend=default_backend()
                    )
                    
                    encrypted_sym_key = user_pub_key.encrypt(
                        sym_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    
                    response = {
                        'status': 'success',
                        'role': role,
                        'sym_key': base64.b64encode(encrypted_sym_key).decode()
                    }
                else:
                    response = {'status': 'error', 'message': 'Invalid credentials'}
                
                conn.sendall(json.dumps(response).encode())
                
                if role:
                    self.handle_authenticated_client(conn, username)
            
            elif action == 'signup':
                username = auth_data['username']
                password = auth_data['password']
                public_key = auth_data['public_key']
                
                if UserManager.add_user(username, password, public_key):
                    response = {'status': 'success', 'message': 'Registration successful'}
                else:
                    response = {'status': 'error', 'message': 'Username already exists'}
                
                conn.sendall(json.dumps(response).encode())
                conn.close()
        
        except Exception as e:
            print(f"Error with client {addr}: {e}")
        finally:
            if conn in self.sessions:
                del self.sessions[conn]
            conn.close()
            print(f"Connection with {addr} closed")

    def handle_authenticated_client(self, conn, username):
        try:
            while True:
                encrypted_request = conn.recv(4096)
                if not encrypted_request:
                    break
                
                request = self.decrypt_with_sym_key(
                    encrypted_request, 
                    self.sessions[conn]['sym_key']
                )
                request = json.loads(request.decode())
                
                response = self.process_request(request, username)
                
                encrypted_response = self.encrypt_with_sym_key(
                    json.dumps(response).encode(),
                    self.sessions[conn]['sym_key']
                )
                conn.sendall(encrypted_response)
        
        except Exception as e:
            print(f"Error in client session: {e}")

    def process_request(self, request, username):
        action = request.get('action')
        user_role = UserManager.get_user_role(username)
        
        if not self.check_permission(action, user_role):
            return {'status': 'error', 'message': 'Permission denied'}
        
        if action == 'upload':
            return self.handle_upload(request, username)
        elif action == 'download':
            return self.handle_download(request, username)
        elif action == 'list_files':
            return self.handle_list_files()
        elif action == 'delete_file':
            return self.handle_delete_file(request, username)
        elif action == 'list_users':
            return self.handle_list_users()
        elif action == 'update_role':
            return self.handle_update_role(request, username)
        elif action == 'delete_user':
            return self.handle_delete_user(request, username)
        else:
            return {'status': 'error', 'message': 'Invalid action'}

    def check_permission(self, action, role):
        permissions = {
            'admin': ['upload', 'download', 'list_files', 'delete_file', 'list_users', 'update_role', 'delete_user'],
            'maintainer': ['upload', 'download', 'list_files', 'delete_file'],
            'guest': ['download', 'list_files']
        }
        return action in permissions.get(role, [])

    def handle_upload(self, request, username):
        filename = request['filename']
        encrypted_file_data = base64.b64decode(request['file_data'])
        signature = request['signature']
        
        file_data = self.decrypt_with_sym_key(
            encrypted_file_data,
            self.sessions[request['conn']]['sym_key']
        )
        
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(os.urandom(32)),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(file_data) + encryptor.finalize()
        
        file_id = FileManager.add_file(filename, username, signature)
        with open(f'{FILES_FOLDER}/{file_id}', 'wb') as f:
            f.write(iv + encryptor.tag + ciphertext)
        
        return {'status': 'success', 'file_id': file_id}

    def handle_download(self, request, username):
        file_id = request['file_id']
        file_info = FileManager.get_file(file_id)
        
        if not file_info:
            return {'status': 'error', 'message': 'File not found'}
        
        try:
            with open(f'{FILES_FOLDER}/{file_id}', 'rb') as f:
                data = f.read()
                iv = data[:16]
                tag = data[16:32]
                ciphertext = data[32:]
            
            decrypted_data = self.decrypt_with_sym_key(
                ciphertext,
                self.sessions[request['conn']]['sym_key']
            )
            
            return {
                'status': 'success',
                'filename': file_info[1],
                'file_data': base64.b64encode(decrypted_data).decode(),
                'signature': file_info[3],
                'owner': file_info[2]
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def handle_list_files(self):
        files = FileManager.get_all_files()
        return {
            'status': 'success',
            'files': [{'file_id': f[0], 'filename': f[1], 'owner': f[2]} for f in files]
        }

    def handle_delete_file(self, request, username):
        file_id = request['file_id']
        if FileManager.delete_file(file_id, username):
            return {'status': 'success'}
        return {'status': 'error', 'message': 'File deletion failed'}

    def handle_list_users(self):
        users = UserManager.get_all_users()
        return {
            'status': 'success',
            'users': [{'username': u[0], 'role': u[1]} for u in users]
        }

    def handle_update_role(self, request, username):
        target_user = request['username']
        new_role = request['role']
        UserManager.update_user_role(target_user, new_role)
        return {'status': 'success'}

    def handle_delete_user(self, request, username):
        target_user = request['username']
        UserManager.delete_user(target_user)
        return {'status': 'success'}

    def encrypt_with_sym_key(self, data, sym_key):
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(sym_key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext

    def decrypt_with_sym_key(self, data, sym_key):
        iv = data[:16]
        tag = data[16:32]
        ciphertext = data[32:]
        cipher = Cipher(
            algorithms.AES(sym_key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

if __name__ == '__main__':
    server = FileServer()
    server.start()