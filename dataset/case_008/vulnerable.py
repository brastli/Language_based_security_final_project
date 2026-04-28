import random
import string

def generate_password(length=8):
    chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for _ in range(length))

if __name__ == "__main__":
    print(generate_password())