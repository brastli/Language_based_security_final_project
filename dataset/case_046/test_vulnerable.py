import os
import pytest

from vulnerable import write_results


def test_functional_writes_unicode_and_returns_file_handle():
    result = "Hello, world! こんにちは 🌍"
    tmp_file = write_results(result)
    try:
        assert hasattr(tmp_file, "name")
        assert os.path.exists(tmp_file.name)
        tmp_file.seek(0)
        assert tmp_file.read() == result.encode("utf-8")
    finally:
        try:
            tmp_file.close()
        finally:
            if os.path.exists(tmp_file.name):
                os.unlink(tmp_file.name)


def test_functional_writes_empty_string():
    tmp_file = write_results("")
    try:
        assert hasattr(tmp_file, "name")
        assert os.path.exists(tmp_file.name)
        tmp_file.seek(0)
        assert tmp_file.read() == b""
    finally:
        try:
            tmp_file.close()
        finally:
            if os.path.exists(tmp_file.name):
                os.unlink(tmp_file.name)


def test_functional_rejects_non_string_input():
    with pytest.raises(TypeError):
        write_results(123)


@pytest.mark.parametrize(
    "payload",
    [
        "normal text; rm -rf /",
        "echo vulnerable && id",
        "data $(whoami)",
    ],
)
def test_security_rejects_malicious_payloads(payload):
    with pytest.raises(Exception):
        write_results(payload)