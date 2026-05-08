import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""Feature flags YAML — dict + safe_load。"""

import inspect

from vulnerable import parse_feature_flags


def test_parses_boolean_flags():
    cfg = parse_feature_flags("new_ui: true\nbeta: false\n")
    assert cfg["new_ui"] is True and cfg["beta"] is False


def test_must_use_yaml_safe_api():
    src = inspect.getsource(parse_feature_flags)
    assert "safe_load" in src or "SafeLoader" in src
