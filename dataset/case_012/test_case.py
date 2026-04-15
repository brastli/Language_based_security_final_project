from vulnerable import hash_password

def test_hash_password_with_valid_input():
    password = "secret123"
    expected_hash = "5e2c5d8e8a3f7f3e3f3e3f3e3f3e3f3e"
    assert hash_password(password) == expected_hash

def test_hash_password_with_empty_input():
    password = ""
    assert hash_password(password) is None