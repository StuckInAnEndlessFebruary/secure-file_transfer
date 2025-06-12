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
        # کلید جدید
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
            print("\n1) Upload 2) Download 3) List 4) Delete 5) Users(ADM) 6) Logout")
            c = input("> ")
            if c=='6': self.conn.close(); break
            if c=='1': self.upload()
            if c=='3': self.list_files()
            if c=='2': self.download()
            if c=='4': self.delete_file()
            if c=='5': self.manage_users()

    def _send(self, req):
        blob = self._encrypt(json.dumps(req).encode())
        self.conn.sendall(blob)
        resp = self.conn.recv(8192)
        return json.loads(self._decrypt(resp).decode())

    def _encrypt(self, data):
        iv = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES(self.sym_key), modes.GCM(iv), default_backend())
        ct = cipher.encryptor().update(data) + cipher.encryptor().finalize()
        return iv + cipher.encryptor().tag + ct

    def _decrypt(self, blob):
        iv, tag, ct = blob[:12], blob[12:28], blob[28:]
        cipher = Cipher(algorithms.AES(self.sym_key), modes.GCM(iv, tag), default_backend())
        return cipher.decryptor().update(ct) + cipher.decryptor().finalize()

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
            'file_data': data,
            'signature': base64.b64encode(sig).decode()
        }
        r = self._send(req)
        print("Uploaded ID:", r.get('file_id'))

    def list_files(self):
        r = self._send({'action':'list_files'})
        for f in r.get('files',[]): print(f)

    def download(self):
        fid = int(input("File ID: "))
        r = self._send({'action':'download','file_id':fid})
        if r.get('status')!='success':
            print("Err"); return
        owner = r['owner']
        # دریافت کلید عمومی مالک
        key_resp = self._send({'action':'get_user_pubkey','username':owner})
        if key_resp.get('status')!='success':
            print("No key"); return
        owner_pub = serialization.load_pem_public_key(
            key_resp['public_key'].encode(), default_backend())
        data = r['file_data']
        sig = base64.b64decode(r['signature'])
        try:
            owner_pub.verify(sig, data,
                padding.PSS(padding.MGF1(hashes.SHA256()),padding.PSS.MAX_LENGTH),
                hashes.SHA256())
            print("Signature OK")
        except:
            print("Bad sig")
        save = input("Save as: ")
        with open(save,'wb') as f: f.write(data)
        print("Saved.")

    def delete_file(self):
        fid = int(input("ID to del: "))
        r = self._send({'action':'delete_file','file_id':fid})
        print("Deleted" if r.get('status')=='success' else "Fail")

    def manage_users(self):
        # فقط برای admin
        while True:
            print("\nU: list, R: role, D: del, B: back")
            c = input("> ").upper()
            if c=='B': break
            if c=='U':
                r = self._send({'action':'list_users'})
                print(r.get('users'))
            if c=='R':
                u = input("User? "); nr = input("Role? ")
                self._send({'action':'update_role','username':u,'role':nr})
            if c=='D':
                u = input("User? ")
                self._send({'action':'delete_user','username':u})

if __name__ == '__main__':
    FileClient().start()
