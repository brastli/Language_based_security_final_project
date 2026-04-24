import pytest
import vulnerable


class DummyConnection:
    def __init__(self, result=None, should_raise=False):
        self.result = result
        self.should_raise = should_raise
        self.executed_sql = None

    def execute(self, sql):
        self.executed_sql = sql
        if self.should_raise:
            raise RuntimeError("database error")
        return self.result


def test_functional_authorized_user_returns_account_result(monkeypatch):
    monkeypatch.setattr(vulnerable, "isAuthorizedUser", lambda userId: True)
    conn = DummyConnection(result={"account_id": 1, "balance": 100})
    result = vulnerable.getUserBankAccount("user123", conn)
    assert result == {"account_id": 1, "balance": 100}
    assert conn.executed_sql == "SELECT * FROM user_bank_account WHERE user_id = 'user123'"


def test_functional_unauthorized_user_returns_none(monkeypatch):
    monkeypatch.setattr(vulnerable, "isAuthorizedUser", lambda userId: False)
    conn = DummyConnection(result={"account_id": 1, "balance": 100})
    result = vulnerable.getUserBankAccount("user123", conn)
    assert result is None
    assert conn.executed_sql is None


def test_functional_database_error_is_propagated(monkeypatch):
    monkeypatch.setattr(vulnerable, "isAuthorizedUser", lambda userId: True)
    conn = DummyConnection(should_raise=True)
    with pytest.raises(RuntimeError, match="database error"):
        vulnerable.getUserBankAccount("user123", conn)
    assert conn.executed_sql == "SELECT * FROM user_bank_account WHERE user_id = 'user123'"


@pytest.mark.parametrize(
    "malicious_user_id",
    [
        "' OR '1'='1",
        "abc'; DROP TABLE user_bank_account; --",
        "x' UNION SELECT * FROM users --",
    ],
)
def test_security_sql_injection_payloads_raise_exception(monkeypatch, malicious_user_id):
    monkeypatch.setattr(vulnerable, "isAuthorizedUser", lambda userId: True)

    class StrictConnection:
        def execute(self, sql):
            if any(token in sql for token in ["'", "--", ";", "UNION", "DROP", " OR "]):
                raise ValueError("Rejected malicious SQL payload")
            return {"ok": True}

    conn = StrictConnection()
    with pytest.raises(Exception):
        vulnerable.getUserBankAccount(malicious_user_id, conn)


@pytest.mark.parametrize(
    "malicious_user_id",
    [
        "user123; rm -rf /",
        "user123 && cat /etc/passwd",
        "$(touch /tmp/pwned)",
    ],
)
def test_security_command_injection_like_payloads_raise_exception(monkeypatch, malicious_user_id):
    monkeypatch.setattr(vulnerable, "isAuthorizedUser", lambda userId: True)

    class StrictConnection:
        def execute(self, sql):
            if any(token in sql for token in [";", "&&", "$(", "`", "|", "&"]):
                raise ValueError("Rejected malicious command-like payload")
            return {"ok": True}

    conn = StrictConnection()
    with pytest.raises(Exception):
        vulnerable.getUserBankAccount(malicious_user_id, conn)