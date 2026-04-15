from vulnerable import load_session

def test_load_session_with_valid_cookie():
    # Simulate a valid session cookie
    user_data = {"user_id": 123, "role": "admin"}
    session_cookie = base64.b64encode(pickle.dumps(user_data)).decode('utf-8')
    
    user_id, role = load_session(session_cookie)
    
    assert user_id == 123
    assert role == "admin"

def test_load_session_with_empty_cookie():
    result = load_session("")
    assert result is None