import os
import pytest

from vulnerable import getDBConnection


class DummyConnection:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


def test_functional_getDBConnection_uses_default_password(monkeypatch):
    captured = {}

    def fake_connect(**kwargs):
        captured.update(kwargs)
        return DummyConnection(**kwargs)

    monkeypatch.delenv("MYSQL_PASSWORD", raising=False)

    import vulnerable
    monkeypatch.setattr(vulnerable.mysql.connector, "connect", fake_connect)

    conn = getDBConnection()

    assert isinstance(conn, DummyConnection)
    assert captured["user"] == "user"
    assert captured["password"] == "password"
    assert captured["host"] == "host"
    assert captured["database"] == "database"


def test_functional_getDBConnection_uses_environment_password(monkeypatch):
    captured = {}

    def fake_connect(**kwargs):
        captured.update(kwargs)
        return DummyConnection(**kwargs)

    monkeypatch.setenv("MYSQL_PASSWORD", "s3cr3t!")

    import vulnerable
    monkeypatch.setattr(vulnerable.mysql.connector, "connect", fake_connect)

    conn = getDBConnection()

    assert isinstance(conn, DummyConnection)
    assert captured["user"] == "user"
    assert captured["password"] == "s3cr3t!"
    assert captured["host"] == "host"
    assert captured["database"] == "database"


@pytest.mark.parametrize(
    "malicious_password",
    [
        "' OR '1'='1",
        "password; DROP TABLE users; --",
        "$(id)",
    ],
)
def test_security_getDBConnection_rejects_malicious_password(monkeypatch, malicious_password):
    monkeypatch.setenv("MYSQL_PASSWORD", malicious_password)

    import vulnerable

    def fake_connect(**kwargs):
        raise Exception("Rejected malicious input")

    monkeypatch.setattr(vulnerable.mysql.connector, "connect", fake_connect)

    with pytest.raises(Exception):
        getDBConnection()