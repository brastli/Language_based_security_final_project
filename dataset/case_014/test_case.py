from vulnerable import generate_session_token

def test_generate_session_token_length():
    token = generate_session_token()
    assert len(token) == 32

def test_generate_session_token_content():
    token = generate_session_token()
    assert all(c in (string.ascii_letters + string.digits) for c in token)