# client.py
import socket
import json
import os
import base64
import secrets
from getpass import getpass
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

HOST = '127.0.0.1'
PORT = 65432
KEYS_DIR = 'client_keys'

class FileClient:
    def __init__(self):
        self.conn = None
        self.sym_key = None
        self.username = None
        self.private_key = None

    def start(self):
        while True:
            print("\n1) Login\n2) Sign Up\n3) Exit")
            cmd = input("> ")
            if cmd=='1' and self.login(): self.menu()
            elif cmd=='2': self.signup()
            elif cmd=='3': break

    def login(self):
        u = input("Username: ")
        p = getpass("Password: ")
        try:
            with open(os.path.join(KEYS_DIR, f"{u}_private.pem"), 'rb') as f:
                self.private_key = serialization.load_pem_private_key(f.read(), None, default_backend())
        except:
            print("No key; signup first."); return False

        pub = self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        auth = {'action':'login','username':u,'password':p,'public_key':pub}
        self.conn = socket.socket()
        self.conn.connect((HOST,PORT))
        self.conn.sendall(json.dumps(auth).encode())
        resp = json.loads(self.conn.recv(4096).decode())
        if resp.get('status')!='success':
            print("Login failed"); self.conn.close(); return False
        self.role = resp.get('role')
        enc_sym = base64.b64decode(resp['sym_key'])
        self.sym_key = self.private_key.decrypt(enc_sym,
            padding.OAEP(padding.MGF1(hashes.SHA256()),hashes.SHA256(),None))
        self.username = u
        print("Logged in.")
        return True

    def signup(self):
        u = input("New username: ")
        p = getpass("New password: ")
        if p != getpass("Confirm: "):
            print("Mismatch"); return
        priv = rsa.generate_private_key(65537,2048,default_backend())
        pub_pem = priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        os.makedirs(KEYS_DIR,exist_ok=True)
        with open(os.path.join(KEYS_DIR,f"{u}_private.pem"),'wb') as f:
            f.write(priv.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
        auth={'action':'signup','username':u,'password':p,'public_key':pub_pem}
        s=socket.socket(); s.connect((HOST,PORT))
        s.sendall(json.dumps(auth).encode())
        r=json.loads(s.recv(4096).decode())
        print("OK" if r.get('status')=='success' else "Fail")
        s.close()

    def menu(self):
        while True:
            print()
            if self.role == "admin":
                print("1) Upload 2) Download 3) List 4) Delete 5) Users(ADM) 6) Logout")
            elif self.role == "maintainer":
                print("1) Upload 2) Download 3) List 4) Delete 5) Logout")
            elif self.role == "guest":
                print("1) Download 2) List 3) Logout")
            else:
                print("Unknown role. Logging out.")
                return

            c = input("> ").strip()

            if self.role == "admin":
                if c == '1': self.upload()
                elif c == '2': self.download()
                elif c == '3': self.list_files()
                elif c == '4': self.delete_file()
                elif c == '5': self.manage_users()
                elif c == '6': break
            elif self.role == "maintainer":
                if c == '1': self.upload()
                elif c == '2': self.download()
                elif c == '3': self.list_files()
                elif c == '4': self.delete_file()
                elif c == '5': break
            elif self.role == "guest":
                if c == '1': self.download()
                elif c == '2': self.list_files()
                elif c == '3': break

    def _send(self, req):
        blob = self._encrypt(json.dumps(req).encode())
        self.conn.sendall(blob)
        resp = self.conn.recv(16384)
        return json.loads(self._decrypt(resp).decode())

    def _encrypt(self, data):
        iv = secrets.token_bytes(12)
        cipher = Cipher(
            algorithms.AES(self.sym_key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ct = encryptor.update(data) + encryptor.finalize()
        tag = encryptor.tag
        return iv + tag + ct

    def _decrypt(self, data):
        iv = data[:12]
        tag = data[12:28]
        ct = data[28:]
        cipher = Cipher(
            algorithms.AES(self.sym_key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(ct) + decryptor.finalize()

    def upload(self):
        path = input("Path: ")
        if not os.path.exists(path):
            print("No file"); return
        with open(path,'rb') as f: data = f.read()
        sig = self.private_key.sign(
            data,
            padding.PSS(padding.MGF1(hashes.SHA256()),padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        req = {
            'action':'upload',
            'filename':os.path.basename(path),
            'file_data': base64.b64encode(data).decode('utf-8'),
            'signature': base64.b64encode(sig).decode('utf-8')
        }
        r = self._send(req)
        print("Uploaded ID:", r.get('file_id'))

    def list_files(self):
        r = self._send({'action':'list_files'})
        for f in r.get('files',[]): print(f)

    def download(self):
        try:
            fid = int(input("File ID: "))
        except ValueError:
            print("Invalid ID."); return
        r = self._send({'action':'download','file_id':fid})
        if r.get('status')!='success':
            print("Error"); return
        owner = r['owner']
        key_resp = self._send({'action':'get_user_pubkey','username':owner})
        if key_resp.get('status')!='success':
            print("No key"); return
        owner_pub = serialization.load_pem_public_key(
            key_resp['public_key'].encode(), default_backend())
        try:
            file_data_bytes = base64.b64decode(r['file_data'])
            sig = base64.b64decode(r['signature'])
        except Exception as e:
            print(f"Decode error: {e}"); return
        try:
            owner_pub.verify(sig, file_data_bytes,
                padding.PSS(padding.MGF1(hashes.SHA256()),padding.PSS.MAX_LENGTH),
                hashes.SHA256())
            print("Signature OK")
        except Exception as e:
            print(f"Bad signature: {e}")
            return
        save = input("Save as: ")
        try:
            with open(save,'wb') as f:
                f.write(file_data_bytes)
            print("Saved.")
        except IOError as e:
            print(f"Error saving file: {e}")

    def delete_file(self):
        try:
            fid = int(input("ID to delete: "))
        except ValueError:
            print("Invalid ID"); return
        r = self._send({'action':'delete_file','file_id':fid})
        print("Deleted" if r.get('status')=='success' else "Fail")

    def manage_users(self):
        while True:
            print("\nU: list, R: role, D: del, B: back")
            c = input("> ").upper()
            if c=='B': break
            if c=='U':
                r = self._send({'action':'list_users'})
                for u in r.get('users', []): print(u)
            if c=='R':
                u = input("User? "); nr = input("New role? ")
                r = self._send({'action':'update_role','username':u,'role':nr})
                print("Updated." if r.get('status') == 'success' else "Failed.")
            if c=='D':
                u = input("User? ")
                r = self._send({'action':'delete_user','username':u})
                print("Deleted." if r.get('status') == 'success' else "Failed.")

if __name__ == '__main__':
    FileClient().start()
