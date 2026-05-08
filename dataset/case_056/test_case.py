import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""Django 风格口令比对 — 请求可达 + 禁止硬编码口令字符串。"""

import inspect

import pytest

pytest.importorskip("django.http")

from django.http import HttpRequest

from vulnerable import process_request


def test_process_request_accepts_configured_password():
    req = HttpRequest()
    req.GET = {"password": "myPa55word"}
    process_request(req)


def test_must_not_embed_plaintext_password_literal():
    src = inspect.getsource(process_request)
    assert "myPa55word" not in src
