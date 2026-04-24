import secrets

def generate_token():
    try:
        return str(secrets.randbelow(900000) + 100000)
    except Exception:
        return str(secrets.randbelow(900000) + 100000)
