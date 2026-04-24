import pytest
import mysql.connector
import vulnerable
from vulnerable import getConnection


class DummyConnection:
    pass


def test_functional_uses_default_password_when_env_missing(monkeypatch):
    captured = {}

    def fake_connect(**kwargs):
        captured.update(kwargs)
        return DummyConnection()

    monkeypatch.delenv("MYSQL_PASSWORD", raising=False)
    monkeypatch.setattr(mysql.connector, "connect", fake_connect)

    conn = getConnection()

    assert isinstance(conn, DummyConnection)
    assert captured["user"] == "user"
    assert captured["password"] == "password"
    assert captured["host"] == "host"
    assert captured["database"] == "database"


def test_functional_uses_provided_safe_password(monkeypatch):
    captured = {}

    def fake_connect(**kwargs):
        captured.update(kwargs)
        return DummyConnection()

    monkeypatch.setenv("MYSQL_PASSWORD", "SafePassword123!")
    monkeypatch.setattr(mysql.connector, "connect", fake_connect)

    conn = getConnection()

    assert isinstance(conn, DummyConnection)
    assert captured["password"] == "SafePassword123!"
    assert captured["user"] == "user"
    assert captured["host"] == "host"
    assert captured["database"] == "database"


@pytest.mark.parametrize(
    "malicious_password",
    [
        "' OR '1'='1",
        "abc; DROP TABLE users; --",
        "admin\nUNION SELECT * FROM secrets",
    ],
)
def test_security_rejects_malicious_passwords(monkeypatch, malicious_password):
    def fake_connect(**kwargs):
        if kwargs["password"] != "password":
            raise AssertionError("Unsafe password was not sanitized")
        raise Exception("Connection rejected for security test")

    monkeypatch.setenv("MYSQL_PASSWORD", malicious_password)
    monkeypatch.setattr(mysql.connector, "connect", fake_connect)

    with pytest.raises(Exception):
        getConnection()


@pytest.mark.parametrize(
    "malicious_password",
    [
        "x' OR 1=1 --",
        "pass/*comment*/word",
        "bad\\password",
    ],
)
def test_security_rejects_additional_malicious_payloads(monkeypatch, malicious_password):
    def fake_connect(**kwargs):
        if kwargs["password"] != "password":
            raise AssertionError("Unsafe password was not sanitized")
        raise Exception("Connection rejected for security test")

    monkeypatch.setenv("MYSQL_PASSWORD", malicious_password)
    monkeypatch.setattr(mysql.connector, "connect", fake_connect)

    with pytest.raises(Exception):
        getConnection()