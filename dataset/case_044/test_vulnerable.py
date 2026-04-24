import pytest
from vulnerable import generateCryptoKey


def test_functional_generateCryptoKey_returns_int():
    key = generateCryptoKey()
    assert isinstance(key, int)


def test_functional_generateCryptoKey_bit_length():
    key = generateCryptoKey()
    assert 0 <= key < 2**128
    assert key.bit_length() <= 128


def test_functional_generateCryptoKey_multiple_calls_produce_values():
    keys = [generateCryptoKey() for _ in range(10)]
    assert all(isinstance(k, int) for k in keys)
    assert all(0 <= k < 2**128 for k in keys)
    assert len(set(keys)) >= 1


@pytest.mark.parametrize(
    "payload",
    [
        "1; DROP TABLE keys;--",
        "$(rm -rf /)",
        "`cat /etc/passwd`",
    ],
)
def test_security_generateCryptoKey_rejects_malicious_payloads(payload):
    with pytest.raises(Exception):
        generateCryptoKey(payload)