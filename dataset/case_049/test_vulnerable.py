import base64
from unittest.mock import MagicMock, patch

import pytest

from vulnerable import checkPassword


def _make_db_mock(fetchone_result):
    db = MagicMock()
    cursor = MagicMock()
    cursor.fetchone.return_value = fetchone_result
    db.cursor.return_value = cursor
    return db, cursor


def test_functional_valid_password_matches():
    stored = base64.b64encode(b"secret123").decode("ascii")
    db, cursor = _make_db_mock((stored,))

    with patch("vulnerable.MySQLdb.connect", return_value=db) as mock_connect:
        assert checkPassword(42, b"secret123") is True

    mock_connect.assert_called_once_with(host="localhost", user="root", passwd="", db="test")
    cursor.execute.assert_called_once_with("SELECT password FROM users WHERE userid = %s", (42,))
    cursor.close.assert_called_once()
    db.close.assert_called_once()


def test_functional_valid_password_does_not_match():
    stored = base64.b64encode(b"secret123").decode("ascii")
    db, cursor = _make_db_mock((stored,))

    with patch("vulnerable.MySQLdb.connect", return_value=db):
        assert checkPassword(42, b"wrongpass") is False

    cursor.close.assert_called_once()
    db.close.assert_called_once()


def test_functional_user_not_found_returns_false():
    db, cursor = _make_db_mock(None)

    with patch("vulnerable.MySQLdb.connect", return_value=db):
        assert checkPassword(999, b"anything") is False

    cursor.execute.assert_called_once_with("SELECT password FROM users WHERE userid = %s", (999,))
    cursor.close.assert_called_once()
    db.close.assert_called_once()


def test_functional_invalid_stored_password_encoding_returns_false():
    db, cursor = _make_db_mock(("not-valid-base64!!",))

    with patch("vulnerable.MySQLdb.connect", return_value=db):
        assert checkPassword(1, b"secret123") is False

    cursor.close.assert_called_once()
    db.close.assert_called_once()


@pytest.mark.parametrize(
    "malicious_password",
    [
        b"abc\x00def",
        b"abc; DROP TABLE users;--",
        b"abc$()",
    ],
)
def test_security_malicious_password_payloads_rejected(malicious_password):
    db, cursor = _make_db_mock((base64.b64encode(b"secret123").decode("ascii"),))

    with patch("vulnerable.MySQLdb.connect", return_value=db):
        with pytest.raises(Exception):
            checkPassword(1, malicious_password)

    cursor.execute.assert_not_called()
    cursor.close.assert_not_called()
    db.close.assert_not_called()


@pytest.mark.parametrize(
    "malicious_password",
    [
        "abc' OR '1'='1",
        12345,
        None,
    ],
)
def test_security_invalid_password_types_rejected(malicious_password):
    db, cursor = _make_db_mock((base64.b64encode(b"secret123").decode("ascii"),))

    with patch("vulnerable.MySQLdb.connect", return_value=db):
        with pytest.raises(Exception):
            checkPassword(1, malicious_password)

    cursor.execute.assert_not_called()
    cursor.close.assert_not_called()
    db.close.assert_not_called()