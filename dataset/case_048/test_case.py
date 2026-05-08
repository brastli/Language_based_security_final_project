import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

import pytest
pytest.importorskip("flask")

"""请求 YAML — 解析刻画 + yaml.safe_load。"""

import inspect

import vulnerable as v


def test_yaml_load_route_parses_mapping():
    v.app.testing = True
    with v.app.test_request_context("/yaml?data=a%3A+1"):
        out = v.yaml_load()
        assert out == {"a": 1}


def test_must_use_yaml_safe_api():
    src = inspect.getsource(v.yaml_load)
    assert "safe_load" in src or "SafeLoader" in src
