import pytest
from vulnerable import process_request


class DummyRequest:
    def __init__(self, get_dict):
        self.GET = get_dict


def test_functional_redirects_on_correct_password(monkeypatch):
    called = {}

    def fake_redirect(target):
        called["target"] = target
        return f"redirect:{target}"

    monkeypatch.setattr("vulnerable.redirect", fake_redirect)

    request = DummyRequest({"password": "myPa55word"})
    result = process_request(request)

    assert called["target"] == "login"
    assert result == "redirect:login"


def test_functional_no_redirect_on_incorrect_password(monkeypatch):
    def fake_redirect(target):
        raise AssertionError("redirect should not be called for incorrect password")

    monkeypatch.setattr("vulnerable.redirect", fake_redirect)

    request = DummyRequest({"password": "wrong-password"})
    result = process_request(request)

    assert result is None


def test_functional_missing_password_raises_keyerror():
    request = DummyRequest({})
    with pytest.raises(KeyError):
        process_request(request)


@pytest.mark.parametrize(
    "payload",
    [
        "' OR '1'='1",
        "myPa55word; rm -rf /",
        "$(id)",
    ],
)
def test_security_malicious_payloads_do_not_authenticate(monkeypatch, payload):
    def fake_redirect(target):
        raise AssertionError("redirect should not be called for malicious payloads")

    monkeypatch.setattr("vulnerable.redirect", fake_redirect)

    request = DummyRequest({"password": payload})
    result = process_request(request)

    assert result is None


@pytest.mark.parametrize(
    "payload",
    [
        "'; DROP TABLE users; --",
        "&& cat /etc/passwd",
        "`reboot`",
    ],
)
def test_security_malicious_payloads_missing_or_invalid_handling(payload):
    request = DummyRequest({"password": payload})
    result = process_request(request)
    assert result is None