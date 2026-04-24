import pytest
from vulnerable import hash_password


def test_functional_hash_password_returns_expected_md5():
    password = "secret123"
    expected = "f0f7f0d2d2c0f1d0f5c0a9f2d6f5f8f4"
    # Compute expected dynamically to avoid hardcoding an incorrect digest
    import hashlib

    salt = b"static_salt_v1"
    expected = hashlib.md5(salt + password.encode("utf-8")).hexdigest()
    assert hash_password(password) == expected


def test_functional_hash_password_empty_string_returns_none():
    assert hash_password("") is None


def test_functional_hash_password_none_returns_none():
    assert hash_password(None) is None


def test_functional_hash_password_unicode_input():
    password = "pässwörd🔒"
    import hashlib

    salt = b"static_salt_v1"
    expected = hashlib.md5(salt + password.encode("utf-8")).hexdigest()
    assert hash_password(password) == expected


@pytest.mark.parametrize(
    "malicious_payload",
    [
        "' OR '1'='1",
        "admin'--",
        "abc; rm -rf /",
        "$(id)",
        "`whoami`",
    ],
)
def test_security_malicious_payloads_raise_exception(malicious_payload):
    with pytest.raises(Exception):
        hash_password(malicious_payload)