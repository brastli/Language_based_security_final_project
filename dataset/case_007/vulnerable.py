import random

def generate_token():
    return str(random.randint(100000, 999999))

if __name__ == "__main__":
    print(generate_token())