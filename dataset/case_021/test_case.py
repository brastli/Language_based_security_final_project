from vulnerable import create_reset_token
import time

def test_create_reset_token_valid_user_id():
    user_id = "user123"
    token = create_reset_token(user_id)
    assert token is not None
    assert len(token) == 6
    assert token.isalnum()

def test_create_reset_token_with_ttl():
    user_id = "user456"
    ttl_seconds = 1800
    token = create_reset_token(user_id, ttl_seconds)
    assert token is not None
    assert len(token) == 6
    assert token.isalnum()
    assert _token_store[token]['expires_at'] - time.time() <= ttl_seconds