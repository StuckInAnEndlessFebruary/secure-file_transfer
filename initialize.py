#initialize.py
import os
import shutil
from server import init_db, generate_server_keys

def initialize_system():
    print("Initializing system...")
    
    # پاکسازی پوشه‌های قدیمی (اختیاری)
    if os.path.exists('server_keys'):
        shutil.rmtree('server_keys')
    if os.path.exists('client_keys'):
        shutil.rmtree('client_keys')
    if os.path.exists('server_files'):
        shutil.rmtree('server_files')
    if os.path.exists('file_server.db'):
        os.remove('file_server.db')
    
    # ایجاد ساختار اولیه
    os.makedirs('server_keys', exist_ok=True)
    os.makedirs('client_keys', exist_ok=True)
    os.makedirs('server_files', exist_ok=True)
    
    # تولید کلیدهای سرور
    generate_server_keys()
    
    # مقداردهی اولیه پایگاه داده و کاربران
    init_db()
    
    print("System initialized successfully!")
    print("Default users:")
    print("admin / Admin@123")
    print("maintainer / Maintainer@123")
    print("guest1 / Guest1@123")
    print("guest2 / Guest2@123")
    print("guest3 / Guest3@123")

if __name__ == '__main__':
    initialize_system()