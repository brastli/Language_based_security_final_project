import pytest
from unittest.mock import MagicMock, patch

from vulnerable import get_connection, remove_user


def test_functional_get_connection_returns_mysql_connection():
    mock_connection = MagicMock(name="connection")
    with patch("vulnerable.mysql.connector.connect", return_value=mock_connection) as mock_connect:
        result = get_connection()

    mock_connect.assert_called_once_with(host="localhost", user="", passwd="")
    assert result is mock_connection


def test_functional_remove_user_executes_expected_delete_query():
    mock_cursor = MagicMock(name="cursor")
    mock_connection = MagicMock(name="connection")
    mock_connection.cursor.return_value = mock_cursor

    with patch("vulnerable.get_connection", return_value=mock_connection) as mock_get_connection:
        remove_user("alice")

    mock_get_connection.assert_called_once_with()
    mock_connection.cursor.assert_called_once_with()
    mock_cursor.execute.assert_called_once_with("DELETE FROM users WHERE username = 'alice'")


@pytest.mark.parametrize(
    "malicious_username",
    [
        "' OR '1'='1",
        "admin'; DROP TABLE users; --",
        "x' OR 1=1 --",
    ],
)
def test_security_remove_user_rejects_malicious_payloads(malicious_username):
    mock_cursor = MagicMock(name="cursor")
    mock_connection = MagicMock(name="connection")
    mock_connection.cursor.return_value = mock_cursor

    with patch("vulnerable.get_connection", return_value=mock_connection):
        with pytest.raises(Exception):
            remove_user(malicious_username)