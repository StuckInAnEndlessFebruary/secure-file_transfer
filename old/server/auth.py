# server/auth.py
from database import get_user

roles = {
    "admin": ["upload", "download", "delete", "change_role"],
    "maintainer": ["upload", "download_own", "download"],
    "guest": ["download"]
}

def authenticate(username, password):
    user = get_user(username)
    if user and user[1] == password:
        return True
    return False

def authorize(username, action):
    user = get_user(username)
    if user:
        role = user[2]
        return action in roles.get(role, [])
    return False
