# initialize.py
import os
import shutil
from server import init_db, generate_server_keys

def initialize_system():
    print("Initializing system...")

    # 1) پاکسازی پوشه‌ها و فایل‌های قبلی
    for path in ('server_keys', 'client_keys', 'server_files'):
        if os.path.exists(path):
            shutil.rmtree(path)
    if os.path.exists('file_server.db'):
        os.remove('file_server.db')

    # 2) ایجاد ساختار پوشه‌ها
    os.makedirs('server_keys', exist_ok=True)
    os.makedirs('client_keys', exist_ok=True)
    os.makedirs('server_files', exist_ok=True)

    # 3) تولید کلیدهای سرور
    generate_server_keys()

    # 4) مقداردهی اولیه دیتابیس و کاربران پیش‌فرض
    init_db()

    print("\nSystem initialized successfully!")
    print("Default users created with their key-pairs:")
    print("  • admin      / Admin@123")
    print("  • maintainer / Maintainer@123")
    print("  • guest1     / Guest1@123")
    print("  • guest2     / Guest2@123")
    print("  • guest3     / Guest3@123")

if __name__ == '__main__':
    initialize_system()
