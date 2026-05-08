import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

import pytest
pytest.importorskip("flask")
pytest.importorskip("jinja2")

"""Jinja 模板 — 渲染占位 + autoescape / Sandbox。"""

import inspect
from pathlib import Path
from unittest.mock import patch

import vulnerable as v


def test_renders_template_with_name(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Path("template.html").write_text("Hello {{ name }}", encoding="utf-8")
    v.app.testing = True
    with v.app.test_client() as client:
        resp = client.get("/render?name=Bob")
        assert resp.status_code == 200
        assert b"Bob" in resp.data


def test_environment_must_enable_autoescape_or_sandbox():
    src = inspect.getsource(v.render_response_from_env)
    assert "autoescape" in src or "SandboxedEnvironment" in src or "select_autoescape" in src
