import pytest
from vulnerable import encrypt_secret


def test_functional_encrypt_secret_returns_bytes():
    result = encrypt_secret("secret", "key12345")
    assert isinstance(result, bytes)
    assert len(result) % 8 == 0
    assert result != b""


def test_functional_encrypt_secret_deterministic_for_same_inputs():
    result1 = encrypt_secret("hello world", "key12345")
    result2 = encrypt_secret("hello world", "key12345")
    assert result1 == result2


def test_functional_encrypt_secret_pads_short_key():
    result = encrypt_secret("data", "k")
    assert isinstance(result, bytes)
    assert len(result) == 8


def test_functional_encrypt_secret_handles_empty_plaintext():
    result = encrypt_secret("", "key12345")
    assert isinstance(result, bytes)
    assert len(result) == 8


@pytest.mark.parametrize(
    "payload",
    [
        "' OR '1'='1",
        "; rm -rf /",
        "$(id)",
    ],
)
def test_security_encrypt_secret_rejects_malicious_payloads(payload):
    with pytest.raises(Exception):
        encrypt_secret(payload, "key12345")