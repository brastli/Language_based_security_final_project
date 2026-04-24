import pytest
from pathlib import Path
from unittest.mock import patch, mock_open

from src.db import read_log_file


def test_functional_read_log_file_returns_file_contents():
    expected_content = "line1\nline2\n"
    m = mock_open(read_data=expected_content)

    with patch("src.db.Path") as mock_path:
        mock_file_path = mock_path.return_value.resolve.return_value.parent.__truediv__.return_value
        mock_file_path.open = m

        result = read_log_file("app.log")

    assert result == expected_content
    m.assert_called_once_with("r", encoding="utf-8")


def test_functional_read_log_file_uses_logs_directory():
    expected_content = "ok"
    m = mock_open(read_data=expected_content)

    with patch("src.db.Path") as mock_path:
        resolve_obj = mock_path.return_value.resolve.return_value
        parent_obj = resolve_obj.parent
        logs_dir_obj = parent_obj.__truediv__.return_value
        target_path_obj = logs_dir_obj.__truediv__.return_value
        target_path_obj.open = m

        result = read_log_file("server.log")

    assert result == expected_content
    mock_path.assert_called_once_with(__file__)
    resolve_obj.parent.__truediv__.assert_called_once_with("logs")
    logs_dir_obj.__truediv__.assert_called_once_with("server.log")


@pytest.mark.parametrize(
    "malicious_filename",
    [
        "../../etc/passwd",
        "app.log; rm -rf /",
        "app.log && cat /etc/shadow",
    ],
)
def test_security_read_log_file_rejects_malicious_payloads(malicious_filename):
    with pytest.raises(Exception):
        read_log_file(malicious_filename)