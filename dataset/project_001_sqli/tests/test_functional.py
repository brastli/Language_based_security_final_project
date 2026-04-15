from src.api import handle_login_request


def test_normal_login():
    """????????"""
    assert handle_login_request({'username': 'admin'}) == 'super_secret_password'
    assert handle_login_request({'username': 'nonexistent'}) is None
