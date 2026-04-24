import json
import os
import subprocess

import pytest

from vulnerable import run_npm_script


def test_functional_returns_minus_one_for_missing_script_name():
    assert run_npm_script("/tmp", "") == -1


def test_functional_returns_minus_one_for_missing_project_dir():
    assert run_npm_script("", "build") == -1


def test_functional_returns_minus_one_for_nonexistent_directory():
    assert run_npm_script("/path/does/not/exist", "build") == -1


def test_functional_returns_minus_two_when_script_not_in_package_json(tmp_path):
    pkg = {"scripts": {"test": "echo test"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg), encoding="utf-8")

    assert run_npm_script(str(tmp_path), "build") == -2


def test_functional_invokes_subprocess_with_expected_command_and_env(tmp_path, monkeypatch):
    pkg = {"scripts": {"build": "echo build"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg), encoding="utf-8")

    captured = {}

    def fake_call(cmd, shell, cwd, env):
        captured["cmd"] = cmd
        captured["shell"] = shell
        captured["cwd"] = cwd
        captured["env"] = env
        return 0

    monkeypatch.setattr(subprocess, "call", fake_call)
    monkeypatch.setenv("BASE_ENV_VAR", "base_value")

    ret = run_npm_script(str(tmp_path), "build", env={"CUSTOM_ENV_VAR": "custom_value"})

    assert ret == 0
    assert captured["cmd"] == "npm run build"
    assert captured["shell"] is True
    assert captured["cwd"] == os.path.abspath(str(tmp_path))
    assert captured["env"]["BASE_ENV_VAR"] == "base_value"
    assert captured["env"]["CUSTOM_ENV_VAR"] == "custom_value"


def test_functional_uses_absolute_project_directory(tmp_path, monkeypatch):
    pkg = {"scripts": {"build": "echo build"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg), encoding="utf-8")

    captured = {}

    def fake_call(cmd, shell, cwd, env):
        captured["cwd"] = cwd
        return 0

    monkeypatch.setattr(subprocess, "call", fake_call)

    relative_dir = os.path.relpath(str(tmp_path))
    ret = run_npm_script(relative_dir, "build")

    assert ret == 0
    assert captured["cwd"] == os.path.abspath(relative_dir)


def test_security_command_injection_payloads_raise_exception(tmp_path, monkeypatch):
    pkg = {"scripts": {"build": "echo build"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg), encoding="utf-8")

    malicious_payloads = [
        "build; rm -rf /",
        "build && echo hacked",
        "build | cat /etc/passwd",
    ]

    def fake_call(cmd, shell, cwd, env):
        raise ValueError("Blocked command execution")

    monkeypatch.setattr(subprocess, "call", fake_call)

    for payload in malicious_payloads:
        with pytest.raises(Exception):
            run_npm_script(str(tmp_path), payload)


def test_security_shell_metacharacters_raise_exception(tmp_path, monkeypatch):
    pkg = {"scripts": {"deploy": "echo deploy"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg), encoding="utf-8")

    malicious_payloads = [
        "$(id)",
        "`whoami`",
        "deploy\nuname -a",
    ]

    def fake_call(cmd, shell, cwd, env):
        raise RuntimeError("Rejected suspicious script name")

    monkeypatch.setattr(subprocess, "call", fake_call)

    for payload in malicious_payloads:
        with pytest.raises(Exception):
            run_npm_script(str(tmp_path), payload)


def test_security_sqli_like_payloads_raise_exception(tmp_path, monkeypatch):
    pkg = {"scripts": {"test": "echo test"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg), encoding="utf-8")

    malicious_payloads = [
        "test' OR '1'='1",
        'test"; DROP TABLE users; --',
        "test; SELECT * FROM users;",
    ]

    def fake_call(cmd, shell, cwd, env):
        raise Exception("Rejected malicious input")

    monkeypatch.setattr(subprocess, "call", fake_call)

    for payload in malicious_payloads:
        with pytest.raises(Exception):
            run_npm_script(str(tmp_path), payload)