import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""yaml.load 不安全 — 功能映射 + safe_load / SafeLoader。"""

import inspect

from vulnerable import run


def test_simple_yaml_mapping():
    out = run("a: 1\nb: two\n")
    assert isinstance(out, dict) and out.get("a") == 1


def test_must_use_yaml_safe_api():
    src = inspect.getsource(run)
    assert "safe_load" in src or "SafeLoader" in src
