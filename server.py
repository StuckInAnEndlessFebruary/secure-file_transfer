# server.py
import socket
import threading
import sqlite3
import os
import json
import hashlib
import base64
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

HOST = '127.0.0.1'
PORT = 65432
DATABASE = 'file_server.db'
SERVER_KEY_FOLDER = 'server_keys'
FILES_FOLDER = 'server_files'

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_bytes(16)
    else:
        salt = bytes.fromhex(salt)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return pwd_hash.hex(), salt.hex()

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            public_key TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'guest'
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS files (
            file_id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            owner TEXT NOT NULL,
            signature TEXT NOT NULL,
            FOREIGN KEY(owner) REFERENCES users(username)
        )
    ''')
    conn.commit()
    conn.close()

def generate_server_keys():
    os.makedirs(SERVER_KEY_FOLDER, exist_ok=True)
    priv_path = os.path.join(SERVER_KEY_FOLDER, 'server_private.pem')
    pub_path = os.path.join(SERVER_KEY_FOLDER, 'server_public.pem')
    if not os.path.exists(priv_path):
        priv = rsa.generate_private_key(65537, 2048, default_backend())
        with open(priv_path, 'wb') as f:
            f.write(priv.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            ))
        with open(pub_path, 'wb') as f:
            f.write(priv.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print("Server keys generated.")

class UserManager:
    @staticmethod
    def verify_login(u, p):
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute('SELECT password_hash, salt, role, public_key FROM users WHERE username=?', (u,))
        row = c.fetchone()
        conn.close()
        if not row:
            return None, None
        stored, salt, role, pub = row
        h, _ = hash_password(p, salt)
        return (role, pub) if h == stored else (None, None)

    @staticmethod
    def add_user(u, p, pubkey_pem):
        h, salt = hash_password(p)
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        try:
            c.execute(
                'INSERT INTO users(username,password_hash,salt,public_key,role) VALUES (?,?,?,?,?)',
                (u, h, salt, pubkey_pem, 'guest')
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()

    @staticmethod
    def get_user_pubkey(u):
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute('SELECT public_key FROM users WHERE username=?', (u,))
        row = c.fetchone()
        conn.close()
        return row[0] if row else None

    @staticmethod
    def get_user_role(u):
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute('SELECT role FROM users WHERE username=?', (u,))
        row = c.fetchone()
        conn.close()
        return row[0] if row else None

    @staticmethod
    def list_users():
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute('SELECT username,role FROM users')
        rows = c.fetchall()
        conn.close()
        return rows

    @staticmethod
    def update_role(u, r):
        conn = sqlite3.connect(DATABASE)
        conn.execute('UPDATE users SET role=? WHERE username=?', (r, u))
        conn.commit()
        conn.close()

    @staticmethod
    def delete_user(u):
        conn = sqlite3.connect(DATABASE)
        conn.execute('DELETE FROM users WHERE username=?', (u,))
        conn.commit()
        conn.close()

class FileManager:
    @staticmethod
    def add_file(name, owner, sig):
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute('INSERT INTO files(filename,owner,signature) VALUES (?,?,?)',
                  (name, owner, sig))
        fid = c.lastrowid
        conn.commit()
        conn.close()
        return fid

    @staticmethod
    def get_file(fid):
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute('SELECT file_id,filename,owner,signature FROM files WHERE file_id=?', (fid,))
        row = c.fetchone()
        conn.close()
        return row

    @staticmethod
    def list_files():
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute('SELECT file_id,filename,owner FROM files')
        rows = c.fetchall()
        conn.close()
        return rows

    @staticmethod
    def delete_file(fid, user):
        info = FileManager.get_file(fid)
        if not info:
            return False
        owner = info[2]
        role = UserManager.get_user_role(user)
        if user != owner and role != 'admin':
            return False
        conn = sqlite3.connect(DATABASE)
        conn.execute('DELETE FROM files WHERE file_id=?', (fid,))
        conn.commit()
        conn.close()
        path = os.path.join(FILES_FOLDER, str(fid))
        if os.path.exists(path):
            os.remove(path)
        return True

class FileServer:
    def __init__(self):
        os.makedirs(FILES_FOLDER, exist_ok=True)
        self.sessions = {}
        self._load_keys()

    def _load_keys(self):
        with open(os.path.join(SERVER_KEY_FOLDER,'server_private.pem'),'rb') as f:
            self.priv = serialization.load_pem_private_key(f.read(), None, default_backend())
        with open(os.path.join(SERVER_KEY_FOLDER,'server_public.pem'),'rb') as f:
            self.pub = serialization.load_pem_public_key(f.read(), default_backend())

    def start(self):
        init_db()
        generate_server_keys()
        with socket.socket() as s:
            s.bind((HOST, PORT))
            s.listen()
            print(f"Listening on {HOST}:{PORT}")
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self._handle, args=(conn,)).start()

    def _handle(self, conn):
        try:
            raw = conn.recv(8192)
            auth = json.loads(raw.decode())
            act = auth.get('action')
            if act == 'login':
                role, user_pub = UserManager.verify_login(auth['username'], auth['password'])
                if not role:
                    conn.sendall(json.dumps({'status':'error','message':'Invalid credentials'}).encode())
                    return
                # ارسال کلید متقارن
                sym = secrets.token_bytes(32)
                user_pub_key = serialization.load_pem_public_key(user_pub.encode(), default_backend())
                enc_sym = user_pub_key.encrypt(
                    sym, padding.OAEP(padding.MGF1(hashes.SHA256()),hashes.SHA256(),None)
                )
                conn.sendall(json.dumps({
                    'status':'success','role':role,
                    'sym_key': base64.b64encode(enc_sym).decode()
                }).encode())
                self.sessions[conn] = {'user': auth['username'], 'sym': sym}
                self._session_loop(conn)
            elif act == 'signup':
                ok = UserManager.add_user(auth['username'], auth['password'], auth['public_key'])
                msg = 'success' if ok else 'error'
                conn.sendall(json.dumps({'status':msg}).encode())
        except Exception as e:
            print("Error:", e)
        finally:
            if conn in self.sessions:
                del self.sessions[conn]
            conn.close()

    def _session_loop(self, conn):
        sym = self.sessions[conn]['sym']
        user = self.sessions[conn]['user']
        while True:
            enc_req = conn.recv(8192)
            if not enc_req:
                break
            req_json = self._decrypt(enc_req, sym)
            req = json.loads(req_json.decode())
            resp = self._dispatch(req, user)
            enc_resp = self._encrypt(json.dumps(resp).encode(), sym)
            conn.sendall(enc_resp)

    def _dispatch(self, req, user):
        act = req.get('action')
        role = UserManager.get_user_role(user)
        perms = {
            'admin': {'upload','download','list_files','delete_file','list_users','update_role','delete_user'},
            'maintainer':{'upload','download','list_files','delete_file'},
            'guest':{'download','list_files'}
        }
        if act not in perms.get(role,()):
            return {'status':'error','message':'Permission denied'}

        if act == 'upload':
            return self._upload(req, user)
        if act == 'download':
            return self._download(req)
        if act == 'list_files':
            files = FileManager.list_files()
            return {'status':'success','files':[{'file_id':f[0],'filename':f[1],'owner':f[2]} for f in files]}
        if act == 'delete_file':
            ok = FileManager.delete_file(req['file_id'], user)
            return {'status':'success'} if ok else {'status':'error','message':'Delete failed'}
        if act == 'list_users':
            users = UserManager.list_users()
            return {'status':'success','users':[{'username':u,'role':r} for u,r in users]}
        if act == 'update_role':
            UserManager.update_role(req['username'], req['role'])
            return {'status':'success'}
        if act == 'delete_user':
            UserManager.delete_user(req['username'])
            return {'status':'success'}
        if act == 'get_user_pubkey':
            pub = UserManager.get_user_pubkey(req['username'])
            if pub:
                return {'status':'success','public_key':pub}
            else:
                return {'status':'error','message':'No such user'}
        return {'status':'error','message':'Unknown action'}

    def _upload(self, req, user):
        fname = req['filename']
        file_data = req['file_data']  # بایت خام پس از دیکد Base64
        signature = req['signature']
        # رمزنگاری نهایی با IV و tag
        iv = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES(self.sessions[next(iter(self.sessions))]['sym']),
                        modes.GCM(iv), backend=default_backend())
        enc = cipher.encryptor().update(file_data) + cipher.encryptor().finalize()
        blob = iv + cipher.encryptor().tag + enc

        fid = FileManager.add_file(fname, user, signature)
        with open(os.path.join(FILES_FOLDER,str(fid)), 'wb') as f:
            f.write(blob)
        return {'status':'success','file_id':fid}

    def _download(self, req):
        fid = req['file_id']
        info = FileManager.get_file(fid)
        if not info:
            return {'status':'error','message':'Not found'}
        path = os.path.join(FILES_FOLDER,str(fid))
        with open(path,'rb') as f:
            blob = f.read()
        iv, tag, ct = blob[:12], blob[12:28], blob[28:]
        cipher = Cipher(algorithms.AES(self.sessions[next(iter(self.sessions))]['sym']),
                        modes.GCM(iv, tag), backend=default_backend())
        data = cipher.decryptor().update(ct) + cipher.decryptor().finalize()

        return {
            'status':'success',
            'filename': info[1],
            'file_data': data,
            'signature': info[3],
            'owner': info[2]
        }

    def _encrypt(self, data, sym):
        iv = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES(sym), modes.GCM(iv), backend=default_backend())
        ct = cipher.encryptor().update(data) + cipher.encryptor().finalize()
        return iv + cipher.encryptor().tag + ct

    def _decrypt(self, blob, sym):
        iv, tag, ct = blob[:12], blob[12:28], blob[28:]
        cipher = Cipher(algorithms.AES(sym), modes.GCM(iv, tag), backend=default_backend())
        return cipher.decryptor().update(ct) + cipher.decryptor().finalize()

if __name__ == '__main__':
    FileServer().start()
