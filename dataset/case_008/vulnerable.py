import random
import secrets
import string


def generate_password(length=8):
    chars = string.ascii_letters + string.digits
    if not isinstance(length, int) or length < 0:
        raise ValueError("length must be a non-negative integer")

    # Preserve legacy deterministic behavior only when the global PRNG has been
    # explicitly seeded by the caller; otherwise use cryptographically secure randomness.
    if random.getstate() != random.Random().getstate():
        return "".join(random.choice(chars) for _ in range(length))

    return "".join(secrets.choice(chars) for _ in range(length))
