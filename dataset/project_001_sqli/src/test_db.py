import pytest
from src.db import get_user_by_name


def test_functional_returns_secret_for_existing_user():
    assert get_user_by_name("admin") == "super_secret_password"


def test_functional_returns_none_for_missing_user():
    assert get_user_by_name("nonexistent") is None


def test_functional_handles_empty_username():
    assert get_user_by_name("") is None


@pytest.mark.parametrize(
    "payload",
    [
        "' OR '1'='1",
        "admin' --",
        "'; DROP TABLE users; --",
    ],
)
def test_security_sql_injection_payloads_raise_exception(payload):
    with pytest.raises(Exception):
        get_user_by_name(payload)