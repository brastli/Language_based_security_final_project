import re
import pytest

from vulnerable import generate_session_token


def test_functional_generate_session_token_length_and_charset():
    token = generate_session_token()
    assert isinstance(token, str)
    assert len(token) == 32
    assert re.fullmatch(r"[A-Za-z0-9]{32}", token) is not None


def test_functional_generate_session_token_uniqueness():
    tokens = {generate_session_token() for _ in range(100)}
    assert len(tokens) == 100


@pytest.mark.parametrize(
    "malicious_payload",
    [
        "' OR '1'='1",
        "; DROP TABLE sessions; --",
        "$(rm -rf /)",
    ],
)
def test_security_generate_session_token_rejects_malicious_payloads(malicious_payload):
    with pytest.raises(Exception):
        generate_session_token(malicious_payload)