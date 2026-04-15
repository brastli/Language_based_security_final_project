from vulnerable import generate_password

def test_generate_password_default_length():
    password = generate_password()
    assert len(password) == 8
    assert all(c.isalnum() for c in password)

def test_generate_password_custom_length():
    length = 12
    password = generate_password(length)
    assert len(password) == length
    assert all(c.isalnum() for c in password)