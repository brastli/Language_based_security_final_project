def checkAdminPassword(password):
    '''
    Check if the password is valid for an admin user.
    '''
    import hmac
    import re
    import unicodedata

    if not isinstance(password, str):
        raise TypeError("password must be a string")

    normalized_password = unicodedata.normalize("NFKC", password)

    if normalized_password != password:
        raise ValueError("invalid password format")

    if any(ord(ch) < 32 or ord(ch) == 127 for ch in normalized_password):
        raise ValueError("invalid password format")

    if re.search(r"['\";]|\$\(|--|/\*|\*/|\bOR\b", normalized_password, re.IGNORECASE):
        raise ValueError("invalid password format")

    expected_password = "admin" # <--- SINK

    if hmac.compare_digest(normalized_password, expected_password):
        return True

    return False