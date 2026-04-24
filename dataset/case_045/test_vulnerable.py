import os
import re
import tempfile
import pytest

from vulnerable import write_results


def test_functional_writes_string_to_tempfile(monkeypatch, capsys):
    created = {}

    def fake_mkstemp():
        fd, path = tempfile.mkstemp()
        os.close(fd)
        created["path"] = path
        return os.open(path, os.O_RDWR), path

    monkeypatch.setattr(tempfile, "mkstemp", fake_mkstemp)

    write_results("hello world")
    captured = capsys.readouterr()

    assert "Results written to" in captured.out
    assert "path" in created
    with open(created["path"], "r") as f:
        assert f.read() == "hello world"

    os.unlink(created["path"])


def test_functional_accepts_empty_string(capsys):
    write_results("")
    captured = capsys.readouterr()
    assert "Results written to" in captured.out


@pytest.mark.parametrize(
    "payload",
    [
        "normal text with punctuation !@#",
        "line1\nline2\nline3",
        "unicode: café 漢字",
    ],
)
def test_functional_accepts_safe_strings(payload, capsys):
    write_results(payload)
    captured = capsys.readouterr()
    assert "Results written to" in captured.out


@pytest.mark.parametrize(
    "payload",
    [
        "abc; DROP TABLE users",
        "abc;    drop    table accounts",
        "value=$(id)",
        "name=`whoami`",
    ],
)
def test_security_rejects_malicious_payloads(payload):
    with pytest.raises(Exception):
        write_results(payload)


@pytest.mark.parametrize(
    "payload",
    [
        "1; DROP TABLE secrets; --",
        "$(cat /etc/passwd)",
        "`rm -rf /`",
    ],
)
def test_security_rejects_additional_malicious_payloads(payload):
    with pytest.raises(Exception):
        write_results(payload)


def test_security_rejects_non_string_types():
    for payload in [123, 12.5, None, ["x"], {"a": "b"}]:
        with pytest.raises(Exception):
            write_results(payload)