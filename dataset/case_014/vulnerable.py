import secrets
import string


def generate_session_token():
    """Generate a session token for new user login."""
    chars = string.ascii_letters + string.digits
    length = 32
    token = "".join(secrets.choice(chars) for _ in range(length))
    return token
