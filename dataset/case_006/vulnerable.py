import pickle


def run(data):
    obj = pickle.loads(data)
    return obj


if __name__ == "__main__":
    import base64

    user_input = base64.b64decode(
        "gASVJQAAAAAAAAB9lCiMAWFzlIwBYpSMAmNzlIwBZJR1Lg=="
    )

    print(run(user_input))