import pytest
import vulnerable
from vulnerable import admin_access


class MockPost:
    def __init__(self, data):
        self._data = data

    def get(self, key, default=None):
        return self._data.get(key, default)


class MockRequest:
    def __init__(self, post_data):
        self.POST = MockPost(post_data)


@pytest.fixture(autouse=True)
def reset_admin_access():
    vulnerable.HAS_ADMIN_ACCESS = False
    yield
    vulnerable.HAS_ADMIN_ACCESS = False


def test_functional_admin_credentials_grant_access():
    request = MockRequest({"user_name": "admin", "password": "admin"})
    result = admin_access(request)
    assert result is True
    assert vulnerable.HAS_ADMIN_ACCESS is True


def test_functional_non_admin_credentials_do_not_grant_access():
    request = MockRequest({"user_name": "user", "password": "pass"})
    result = admin_access(request)
    assert result is False
    assert vulnerable.HAS_ADMIN_ACCESS is False


def test_functional_missing_password_does_not_grant_access():
    request = MockRequest({"user_name": "admin"})
    result = admin_access(request)
    assert result is False
    assert vulnerable.HAS_ADMIN_ACCESS is False


@pytest.mark.parametrize(
    "payload",
    [
        {"user_name": "admin' OR '1'='1", "password": "anything"},
        {"user_name": "admin; rm -rf /", "password": "admin"},
        {"user_name": "$(whoami)", "password": "`id`"},
    ],
)
def test_security_malicious_payloads_rejected(payload):
    request = MockRequest(payload)
    with pytest.raises(Exception):
        admin_access(request)