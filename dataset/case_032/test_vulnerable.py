import pytest
import vulnerable
from vulnerable import get_connection, show_user


class FakeCursor:
    def __init__(self, fetchone_result=None):
        self.executed_queries = []
        self.fetchone_result = fetchone_result

    def execute(self, query):
        self.executed_queries.append(query)

    def fetchone(self):
        return self.fetchone_result


class FakeConnection:
    def __init__(self, cursor_obj):
        self._cursor = cursor_obj

    def cursor(self):
        return self._cursor


def test_functional_get_connection_calls_mysql_connect(monkeypatch):
    captured = {}

    def fake_connect(**kwargs):
        captured.update(kwargs)
        return "fake-connection"

    monkeypatch.setattr(vulnerable.mysql.connector, "connect", fake_connect)

    result = get_connection()

    assert result == "fake-connection"
    assert captured == {"host": "localhost", "user": "", "passwd": ""}


def test_functional_show_user_returns_user_record(monkeypatch):
    fake_cursor = FakeCursor(fetchone_result=("alice", "Alice Example", "alice@example.com"))
    fake_connection = FakeConnection(fake_cursor)

    monkeypatch.setattr(vulnerable, "get_connection", lambda: fake_connection)

    result = show_user("alice")

    assert result == ("alice", "Alice Example", "alice@example.com")
    assert fake_cursor.executed_queries == ["SELECT * FROM users WHERE username = 'alice'"]


def test_functional_show_user_handles_empty_result(monkeypatch):
    fake_cursor = FakeCursor(fetchone_result=None)
    fake_connection = FakeConnection(fake_cursor)

    monkeypatch.setattr(vulnerable, "get_connection", lambda: fake_connection)

    result = show_user("nonexistent")

    assert result is None
    assert fake_cursor.executed_queries == ["SELECT * FROM users WHERE username = 'nonexistent'"]


@pytest.mark.parametrize(
    "payload",
    [
        "' OR '1'='1",
        "admin'; DROP TABLE users; --",
        "'; EXEC xp_cmdshell('id'); --",
    ],
)
def test_security_show_user_rejects_malicious_payloads(monkeypatch, payload):
    class RejectingCursor(FakeCursor):
        def execute(self, query):
            raise ValueError("Rejected malicious input")

    fake_connection = FakeConnection(RejectingCursor())
    monkeypatch.setattr(vulnerable, "get_connection", lambda: fake_connection)

    with pytest.raises(Exception):
        show_user(payload)