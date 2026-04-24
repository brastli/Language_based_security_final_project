import pytest

from src.api import handle_download_log_request


def test_functional_handle_download_log_request_success(monkeypatch):
    def mock_read_log_file(filename):
        assert filename == "app.log"
        return "log contents"

    def mock_format_download_response(content):
        assert content == "log contents"
        return {"status": "ok", "body": content}

    monkeypatch.setattr("src.api.read_log_file", mock_read_log_file)
    monkeypatch.setattr("src.api.format_download_response", mock_format_download_response)

    result = handle_download_log_request({"filename": "app.log"})
    assert result == {"status": "ok", "body": "log contents"}


def test_functional_handle_download_log_request_missing_filename(monkeypatch):
    def mock_read_log_file(filename):
        assert filename == ""
        return "default log contents"

    def mock_format_download_response(content):
        assert content == "default log contents"
        return {"status": "ok", "body": content}

    monkeypatch.setattr("src.api.read_log_file", mock_read_log_file)
    monkeypatch.setattr("src.api.format_download_response", mock_format_download_response)

    result = handle_download_log_request({})
    assert result == {"status": "ok", "body": "default log contents"}


@pytest.mark.parametrize(
    "payload",
    [
        {"filename": "../../etc/passwd"},
        {"filename": "; cat /etc/passwd"},
        {"filename": "$(id)"},
    ],
)
def test_security_handle_download_log_request_malicious_payloads(monkeypatch, payload):
    def mock_read_log_file(filename):
        raise ValueError(f"Rejected filename: {filename}")

    def mock_format_download_response(content):
        return content

    monkeypatch.setattr("src.api.read_log_file", mock_read_log_file)
    monkeypatch.setattr("src.api.format_download_response", mock_format_download_response)

    with pytest.raises(Exception):
        handle_download_log_request(payload)