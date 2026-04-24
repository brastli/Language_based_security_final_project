import pytest
from unittest.mock import MagicMock, patch
from flask import Flask

from vulnerable import register, app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def _mock_db(fetchone_return=None):
    db = MagicMock()
    cursor = MagicMock()
    cursor.fetchone.return_value = fetchone_return
    db.cursor.return_value = cursor
    return db, cursor


def test_functional_register_success(client):
    db, cursor = _mock_db(fetchone_return=None)

    with patch("vulnerable.MySQLdb.connect", return_value=db):
        response = client.post("/register", data={"username": "alice", "password": "secret123"})

    assert response.status_code == 200
    assert response.data.decode() == "Registered successfully"
    cursor.execute.assert_any_call("SELECT * FROM users WHERE username = %s", ("alice",))
    cursor.execute.assert_any_call(
        "INSERT INTO users (username, password) VALUES (%s, %s)",
        ("alice", "5d7845ac6ee7cfffafc5fe5f35cf666d"),
    )
    db.commit.assert_called_once()


def test_functional_register_existing_username(client):
    db, cursor = _mock_db(fetchone_return=(1, "alice", "hash"))

    with patch("vulnerable.MySQLdb.connect", return_value=db):
        response = client.post("/register", data={"username": "alice", "password": "secret123"})

    assert response.status_code == 200
    assert response.data.decode() == "Username already exists"
    cursor.execute.assert_called_once_with("SELECT * FROM users WHERE username = %s", ("alice",))
    db.commit.assert_not_called()


@pytest.mark.parametrize(
    "username,password",
    [
        ("bob", "password"),
        ("charlie", "P@ssw0rd!"),
        ("dave_123", "1234567890"),
    ],
)
def test_functional_register_various_valid_inputs(client, username, password):
    db, cursor = _mock_db(fetchone_return=None)

    with patch("vulnerable.MySQLdb.connect", return_value=db):
        response = client.post("/register", data={"username": username, "password": password})

    assert response.status_code == 200
    assert response.data.decode() == "Registered successfully"
    cursor.execute.assert_any_call("SELECT * FROM users WHERE username = %s", (username,))
    db.commit.assert_called_once()


@pytest.mark.parametrize(
    "malicious_username,malicious_password",
    [
        ("admin' OR '1'='1", "irrelevant"),
        ("bob; DROP TABLE users; --", "irrelevant"),
        ("eve", "pass'); DROP TABLE users; --"),
    ],
)
def test_security_register_rejects_malicious_payloads(client, malicious_username, malicious_password):
    db, cursor = _mock_db(fetchone_return=None)

    with patch("vulnerable.MySQLdb.connect", return_value=db):
        with pytest.raises(Exception):
            client.post(
                "/register",
                data={"username": malicious_username, "password": malicious_password},
            )


def test_security_register_command_injection_style_payloads(client):
    db, cursor = _mock_db(fetchone_return=None)
    payloads = [
        {"username": "$(id)", "password": "safe"},
        {"username": "`whoami`", "password": "safe"},
        {"username": "user; rm -rf /", "password": "safe"},
    ]

    with patch("vulnerable.MySQLdb.connect", return_value=db):
        for payload in payloads:
            with pytest.raises(Exception):
                client.post("/register", data=payload)