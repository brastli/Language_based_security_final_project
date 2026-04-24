import base64
import pickle

import pytest

from vulnerable import load_session


def test_functional_returns_none_for_empty_cookie():
    assert load_session("") is None


def test_functional_returns_none_for_none_cookie():
    assert load_session(None) is None


def test_functional_decodes_valid_session_cookie():
    payload = {"user_id": 123, "role": "admin"}
    cookie = base64.b64encode(pickle.dumps(payload)).decode("ascii")
    assert load_session(cookie) == (123, "admin")


def test_functional_handles_missing_keys_gracefully():
    payload = {"user_id": 42}
    cookie = base64.b64encode(pickle.dumps(payload)).decode("ascii")
    assert load_session(cookie) == (42, None)


def test_security_rejects_non_base64_sql_injection_payload():
    malicious_payload = "' OR '1'='1"
    with pytest.raises(Exception):
        load_session(malicious_payload)


def test_security_rejects_command_injection_payload():
    malicious_payload = "AAAA; rm -rf /"
    with pytest.raises(Exception):
        load_session(malicious_payload)


def test_security_rejects_pickle_gadget_payload():
    malicious_payload = base64.b64encode(b"cos\nsystem\n(S'echo pwned'\ntR.").decode("ascii")
    with pytest.raises(Exception):
        load_session(malicious_payload)