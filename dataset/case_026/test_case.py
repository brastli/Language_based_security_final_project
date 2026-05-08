import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""YAML 文件加载 — 映射内容 + 优先 yaml.safe_load。"""

import inspect

from vulnerable import yaml_load


def test_loads_mapping_from_file(tmp_path):
    p = tmp_path / "cfg.yaml"
    p.write_text("a: 1\nb: two\n", encoding="utf-8")
    data = yaml_load(str(p))
    assert isinstance(data, dict) and data.get("a") == 1


def test_must_use_safe_load_api():
    src = inspect.getsource(yaml_load)
    assert "safe_load" in src
