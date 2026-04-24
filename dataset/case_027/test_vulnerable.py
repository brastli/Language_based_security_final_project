import json
import os
from unittest.mock import MagicMock, patch

import pytest

from vulnerable import readJSON


def test_functional_readJSON_http_url_parses_json():
    mock_response = MagicMock()
    mock_response.read.return_value = b'{"status": "ok", "count": 3}'

    with patch("vulnerable.request.urlopen", return_value=mock_response) as mock_urlopen:
        result = readJSON("http://example.com/data.json")

    assert result == {"status": "ok", "count": 3}
    mock_urlopen.assert_called_once_with("http://example.com/data.json")


def test_functional_readJSON_https_url_parses_json():
    mock_response = MagicMock()
    mock_response.read.return_value = b'{"name": "alice", "active": true}'

    with patch("vulnerable.request.urlopen", return_value=mock_response) as mock_urlopen:
        result = readJSON("https://example.com/user.json")

    assert result == {"name": "alice", "active": True}
    mock_urlopen.assert_called_once_with("https://example.com/user.json")


def test_functional_readJSON_local_path_within_base_dir_parses_json(tmp_path):
    base_dir = os.path.abspath(os.path.dirname(__import__("vulnerable").__file__))
    local_file = tmp_path / "sample.json"
    local_file.write_text('{"hello": "world", "n": 42}', encoding="utf-8")

    target_path = os.path.abspath(str(local_file))
    if not target_path.startswith(base_dir):
        pytest.skip("Temporary path is outside vulnerable module base directory; cannot test allowed local path safely.")

    mock_response = MagicMock()
    mock_response.read.return_value = b'{"hello": "world", "n": 42}'

    with patch("vulnerable.request.urlopen", return_value=mock_response) as mock_urlopen:
        result = readJSON(str(local_file))

    assert result == {"hello": "world", "n": 42}
    mock_urlopen.assert_called_once_with(os.path.abspath(str(local_file)))


@pytest.mark.parametrize(
    "malicious_input",
    [
        "http://example.com/data.json?x=<script>alert(1)</script>",
        "https://example.com/data.json'; DROP TABLE users; --",
        "file:///etc/passwd",
        "../../etc/passwd",
        "/etc/passwd; rm -rf /",
        "http://127.0.0.1:80/%0d%0aHost:evil.com",
    ],
)
def test_security_readJSON_rejects_malicious_payloads(malicious_input):
    if malicious_input.startswith(("http://", "https://")):
        with pytest.raises(Exception):
            readJSON(malicious_input)
    else:
        with pytest.raises(Exception):
            readJSON(malicious_input)