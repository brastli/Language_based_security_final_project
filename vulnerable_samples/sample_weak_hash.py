import hashlib

def hash_password(password):
    import hashlib
    import os
    # Use a secure hash function with a salt
    salt = os.urandom(16)
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000).hex() + ':' + salt.hex()