import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

import pytest
pytest.importorskip("flask")

"""urllib 动态 import — GET 返回 200 + 禁止 exec 拼接 import。"""

import inspect

import vulnerable as v


def test_get_returns_ok():
    v.app.testing = True
    with v.app.test_client() as client:
        resp = client.get("/?module=")
        assert resp.status_code == 200


def test_must_not_use_exec_to_import():
    src = inspect.getsource(v.index)
    assert "exec(" not in src
