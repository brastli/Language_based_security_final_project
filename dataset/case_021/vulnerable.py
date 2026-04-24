import time
import string
import secrets

_token_store = {}


def create_reset_token(user_id, ttl_seconds=3600):
    """Generate a one-time password reset token and register it for the user."""
    if not user_id or ttl_seconds <= 0:
        return None
    chars = string.digits + string.ascii_uppercase
    token_len = 6
    token = "".join(secrets.choice(chars) for _ in range(token_len))
    expires_at = time.time() + ttl_seconds
    record = {"user_id": user_id, "token": token, "expires_at": expires_at, "used": False}
    _token_store[token] = record
    return token