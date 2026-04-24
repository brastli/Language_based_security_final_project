from Crypto.Cipher import DES

def encrypt_secret(plaintext, key):
    """Encrypt sensitive data with DES for storage."""
    if len(key) != 8:
        key = (key + "00000000")[:8]
    cipher = DES.new(key.encode("utf-8"), DES.MODE_ECB)
    pad = 8 - len(plaintext) % 8
    data = plaintext.encode("utf-8") + bytes([pad] * pad)
    return cipher.encrypt(data)

if __name__ == "__main__":
    encrypt_secret("secret", "key12345")
