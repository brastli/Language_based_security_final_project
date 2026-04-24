import pytest
import random
from vulnerable import generate_password


def test_functional_default_length():
    password = generate_password()
    assert isinstance(password, str)
    assert len(password) == 8
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
    assert set(password).issubset(allowed)


def test_functional_custom_length():
    password = generate_password(16)
    assert isinstance(password, str)
    assert len(password) == 16
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
    assert set(password).issubset(allowed)


def test_functional_zero_length():
    password = generate_password(0)
    assert password == ""


def test_functional_deterministic_when_seeded():
    random.seed(12345)
    p1 = generate_password(12)
    random.seed(12345)
    p2 = generate_password(12)
    assert p1 == p2
    assert len(p1) == 12


@pytest.mark.parametrize(
    "malicious_payload",
    [
        "' OR '1'='1",
        "; rm -rf /",
        "$(id)",
        "&& cat /etc/passwd",
    ],
)
def test_security_malicious_payloads_raise_exception(malicious_payload):
    with pytest.raises(Exception):
        generate_password(malicious_payload)


@pytest.mark.parametrize(
    "malicious_length",
    [
        -1,
        -100,
        3.14,
        None,
        {"length": 10},
    ],
)
def test_security_invalid_types_and_negative_values_raise_exception(malicious_length):
    with pytest.raises(Exception):
        generate_password(malicious_length)