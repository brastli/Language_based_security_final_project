import pytest
from vulnerable import getSessionID


def test_functional_returns_int():
    session_id = getSessionID()
    assert isinstance(session_id, int)


def test_functional_returns_32bit_non_negative():
    session_id = getSessionID()
    assert 0 <= session_id < 2**32


def test_functional_multiple_calls_produce_values():
    ids = [getSessionID() for _ in range(10)]
    assert all(isinstance(i, int) for i in ids)
    assert all(0 <= i < 2**32 for i in ids)


@pytest.mark.parametrize(
    "malicious_payload",
    [
        "1 OR 1=1",
        "'; DROP TABLE sessions; --",
        "$(rm -rf /)",
    ],
)
def test_security_malicious_payloads_rejected(malicious_payload):
    with pytest.raises(Exception):
        getSessionID(malicious_payload)