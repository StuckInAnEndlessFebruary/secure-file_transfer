import socket
import threading
import sqlite3
import os
import json
import base64
import time
from hashlib import sha256
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets

DB = 'server_data.db'
KEYS_DIR = 'server_files'
SYM_KEY_SIZE = 32
LOG_FILE = 'server.log'

FAILED_LOGIN_LIMIT = 3
BLOCK_DURATION = 300  # seconds (5 minutes)
failed_logins = {}  # {username: [count, last_attempt_time]}

def init_db():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                        username TEXT PRIMARY KEY,
                        password TEXT,
                        role TEXT,
                        public_key TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS files (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        filename TEXT,
                        owner TEXT,
                        data BLOB,
                        signature TEXT)''')
        conn.commit()

def log_event(message):
    with open(LOG_FILE, 'a') as f:
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S %Z')

        f.write(f"[{now} UTC] {message}\n")

class FileServer:
    def __init__(self):
        self.sym_keys = {}  # session_key[username]
        os.makedirs(KEYS_DIR, exist_ok=True)
        init_db()

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('0.0.0.0', 65432))
            s.listen()
            print("Server listening...")
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self.handle_client, args=(conn,)).start()

    def recv_json(self, conn):
        try:
            return json.loads(conn.recv(16384).decode())
        except:
            return {}

    def handle_client(self, conn):
        user = None
        try:
            auth = self.recv_json(conn)
            if auth.get('action') == 'signup':
                self.handle_signup(conn, auth)
                conn.close()
                return
            elif auth.get('action') == 'login':
                user = self.handle_login(conn, auth)
                if not user:
                    conn.close()
                    return
            else:
                conn.close()
                return

            while True:
                blob = conn.recv(65536)
                if not blob:
                    break
                data = self._decrypt(blob, self.sym_keys[user])
                req = json.loads(data.decode())
                resp = self.handle_request(req, user)
                conn.sendall(self._encrypt(json.dumps(resp).encode(), self.sym_keys[user]))
        except Exception as e:
            print(f"[!] Error: {e}")
        finally:
            conn.close()

    def handle_signup(self, conn, data):
        with sqlite3.connect(DB) as db:
            cur = db.cursor()
            try:
                cur.execute("INSERT INTO users VALUES (?, ?, ?, ?)",
                    (data['username'], sha256(data['password'].encode()).hexdigest(), 'guest', data['public_key']))
                db.commit()
                conn.sendall(json.dumps({'status': 'success'}).encode())
                log_event(f"User signed up: {data['username']}")
            except:
                conn.sendall(json.dumps({'status': 'fail'}).encode())

    def handle_login(self, conn, data):
        u = data['username']
        now = time.time()

        if u in failed_logins:
            count, last_time = failed_logins[u]
            if count >= FAILED_LOGIN_LIMIT and now - last_time < BLOCK_DURATION:
                conn.sendall(json.dumps({'status': 'blocked'}).encode())
                return None
            elif now - last_time >= BLOCK_DURATION:
                failed_logins[u] = [0, 0]

        with sqlite3.connect(DB) as db:
            cur = db.cursor()
            cur.execute("SELECT password, role, public_key FROM users WHERE username=?", (u,))
            row = cur.fetchone()
            if not row or row[0] != sha256(data['password'].encode()).hexdigest():
                failed_logins[u] = failed_logins.get(u, [0, 0])
                failed_logins[u][0] += 1
                failed_logins[u][1] = now
                conn.sendall(json.dumps({'status': 'fail'}).encode())
                log_event(f"Failed login attempt for user: {u}")
                return None

            failed_logins[u] = [0, 0]  # reset on successful login
            sym = secrets.token_bytes(SYM_KEY_SIZE)
            pub_key = serialization.load_pem_public_key(data['public_key'].encode(), backend=default_backend())
            enc_sym = pub_key.encrypt(sym, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
            self.sym_keys[u] = sym
            conn.sendall(json.dumps({
                'status': 'success',
                'role': row[1],
                'sym_key': base64.b64encode(enc_sym).decode()
            }).encode())
            log_event(f"User logged in: {u}")
            return u

    def _encrypt(self, data, key):
        iv = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(data) + encryptor.finalize()
        return iv + encryptor.tag + ct

    def _decrypt(self, blob, key):
        iv = blob[:12]
        tag = blob[12:28]
        ct = blob[28:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ct) + decryptor.finalize()

    def handle_request(self, req, user):
        action = req.get('action')
        if action == 'upload':
            log_event(f"{user} uploaded a file: {req.get('filename')}")
            return self.upload_file(req, user)
        elif action == 'list_files':
            return self.list_files()
        elif action == 'download':
            log_event(f"{user} downloaded file ID: {req.get('file_id')}")
            return self.download_file(req)
        elif action == 'delete_file':
            result = self.delete_file(req, user)
            if result.get('status') == 'success':
                log_event(f"{user} deleted file ID: {req.get('file_id')}")
            return result
        elif action == 'list_users':
            return self.list_users()
        elif action == 'update_role':
            log_event(f"{user} updated role of {req.get('username')} to {req.get('role')}")
            return self.update_user_role(req)
        elif action == 'delete_user':
            log_event(f"{user} deleted user: {req.get('username')}")
            return self.delete_user(req)
        elif action == 'get_user_pubkey':
            return self.get_user_pubkey(req)
        else:
            return {'status': 'invalid'}

    def upload_file(self, req, user):
        with sqlite3.connect(DB) as db:
            cur = db.cursor()
            cur.execute("INSERT INTO files (filename, owner, data, signature) VALUES (?, ?, ?, ?)", (
                req['filename'], user,
                base64.b64decode(req['file_data']),
                req['signature']
            ))
            db.commit()
            return {'status': 'success', 'file_id': cur.lastrowid}

    def list_files(self):
        with sqlite3.connect(DB) as db:
            cur = db.cursor()
            cur.execute("SELECT id, filename, owner FROM files")
            files = cur.fetchall()
            return {'files': [f"{f[0]} - {f[1]} (owner: {f[2]})" for f in files]}

    def download_file(self, req):
        fid = req.get('file_id')
        with sqlite3.connect(DB) as db:
            cur = db.cursor()
            cur.execute("SELECT filename, owner, data, signature FROM files WHERE id=?", (fid,))
            row = cur.fetchone()
            if not row:
                return {'status': 'fail'}
            return {
                'status': 'success',
                'filename': row[0],
                'owner': row[1],
                'file_data': base64.b64encode(row[2]).decode(),
                'signature': row[3]
            }

    def delete_file(self, req, user):
        fid = req.get('file_id')
        with sqlite3.connect(DB) as db:
            cur = db.cursor()
            cur.execute("SELECT owner FROM files WHERE id=?", (fid,))
            row = cur.fetchone()
            if not row:
                return {'status': 'fail'}
            owner = row[0]
            cur.execute("SELECT role FROM users WHERE username=?", (user,))
            role = cur.fetchone()[0]
            if user != owner and role != 'admin':
                return {'status': 'unauthorized'}
            cur.execute("DELETE FROM files WHERE id=?", (fid,))
            db.commit()
            return {'status': 'success'}

    def list_users(self):
        with sqlite3.connect(DB) as db:
            cur = db.cursor()
            cur.execute("SELECT username, role FROM users")
            return {'users': [f"{u[0]} - {u[1]}" for u in cur.fetchall()]}

    def update_user_role(self, req):
        with sqlite3.connect(DB) as db:
            cur = db.cursor()
            cur.execute("UPDATE users SET role=? WHERE username=?", (req['role'], req['username']))
            db.commit()
            return {'status': 'success'}

    def delete_user(self, req):
        with sqlite3.connect(DB) as db:
            cur = db.cursor()
            cur.execute("DELETE FROM users WHERE username=?", (req['username'],))
            db.commit()
            return {'status': 'success'}

    def get_user_pubkey(self, req):
        with sqlite3.connect(DB) as db:
            cur = db.cursor()
            cur.execute("SELECT public_key FROM users WHERE username=?", (req['username'],))
            row = cur.fetchone()
            if not row:
                return {'status': 'fail'}
            return {'status': 'success', 'public_key': row[0]}

if __name__ == '__main__':
    FileServer().start()
