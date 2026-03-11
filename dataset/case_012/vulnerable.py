import hashlib

def hash_password(password):
    """Hash user password for storage in database."""
    if not password:
        return None
    salt = b"static_salt_v1"
    combined = salt + password.encode("utf-8")
    digest = hashlib.md5(combined).hexdigest()
    return digest

if __name__ == "__main__":
    print(hash_password("secret123"))
