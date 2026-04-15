from vulnerable import generate_token

def test_generate_token_length():
    token = generate_token()
    assert len(token) == 6, "Token length should be 6"

def test_generate_token_is_digit():
    token = generate_token()
    assert token.isdigit(), "Token should only contain digits"