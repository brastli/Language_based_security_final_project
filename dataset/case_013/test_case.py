import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""用户 YAML 配置 — dict 返回 + safe_load。"""

import inspect

from vulnerable import load_user_config


def test_simple_theme_config():
    cfg = load_user_config("theme: dark\nlang: en\n")
    assert cfg.get("theme") == "dark" and cfg.get("lang") == "en"


def test_must_use_yaml_safe_api():
    src = inspect.getsource(load_user_config)
    assert "safe_load" in src or "SafeLoader" in src
