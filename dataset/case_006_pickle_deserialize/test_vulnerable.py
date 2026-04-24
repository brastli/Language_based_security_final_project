import base64
import pickle
import pytest

from vulnerable import run


def test_functional_returns_unpickled_object():
    original = {"as": 1, "b": 2, "cs": 3, "d": 4}
    data = pickle.dumps(original)
    assert run(data) == original


def test_functional_handles_list_payload():
    original = [1, "two", {"three": 3}]
    data = pickle.dumps(original)
    assert run(data) == original


@pytest.mark.parametrize(
    "payload",
    [
        b"gASVJQAAAAAAAAB9lCiMAWFzlIwBYpSMAmNzlIwBZJR1Lg==",
        base64.b64decode("gASVJQAAAAAAAAB9lCiMAWFzlIwBYpSMAmNzlIwBZJR1Lg=="),
    ],
)
def test_functional_matches_expected_sample_payload(payload):
    result = run(payload)
    assert isinstance(result, dict)
    assert result == {"as": "b", "cs": "d"}


@pytest.mark.parametrize(
    "malicious_payload",
    [
        b"__import__('os').system('id')",
        b"'; DROP TABLE users; --",
        b"$(touch /tmp/pwned)",
    ],
)
def test_security_rejects_malicious_payloads(malicious_payload):
    with pytest.raises(Exception):
        run(malicious_payload)


@pytest.mark.parametrize(
    "malicious_payload",
    [
        b"cos\nsystem\n(S'echo hacked'\ntR.",
        b"cposix\nsystem\n(S'whoami'\ntR.",
        b"cbuiltins\nexec\n(S'print(1)'\ntR.",
    ],
)
def test_security_rejects_pickle_injection_payloads(malicious_payload):
    with pytest.raises(Exception):
        run(malicious_payload)