import pytest

from src.utils import format_download_response


def test_functional_format_download_response_with_string():
    content = "file content"
    result = format_download_response(content)
    assert result == {"content": content}
    assert isinstance(result, dict)


def test_functional_format_download_response_with_empty_string():
    content = ""
    result = format_download_response(content)
    assert result == {"content": content}


def test_functional_format_download_response_with_bytes():
    content = b"binary content"
    result = format_download_response(content)
    assert result == {"content": content}


def test_functional_format_download_response_with_none():
    content = None
    result = format_download_response(content)
    assert result == {"content": content}


@pytest.mark.parametrize(
    "malicious_payload",
    [
        "'; DROP TABLE users; --",
        "$(rm -rf /)",
        "<script>alert('xss')</script>",
    ],
)
def test_security_format_download_response_rejects_malicious_payloads(malicious_payload):
    with pytest.raises(Exception):
        format_download_response(malicious_payload)