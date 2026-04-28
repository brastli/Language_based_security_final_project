import random
import string

def generate_session_token():
    """Generate a session token for new user login."""
    chars = string.ascii_letters + string.digits
    length = 32
    token = "".join(chars[int(random.random() * len(chars))] for _ in range(length))
    return token

if __name__ == "__main__":
    print(generate_session_token())
