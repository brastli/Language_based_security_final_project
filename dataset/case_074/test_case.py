import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if "vulnerable" in sys.modules:
    del sys.modules["vulnerable"]
sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""
A — 功能回归：解密后的普通 YAML 映射仍能还原为 dict。

B — 修复验收：不得再走 yaml.load / UnsafeLoader；须使用 yaml.safe_load。
未修复基线在 B 失败；修复后 A/B 均应通过。

依赖：PyYAML（import yaml）。配合 Bandit B506 与 main.py 复扫。
"""

from unittest.mock import patch

from vulnerable import Vault


def test_benign_mapping_yaml_loads_to_plain_dict():
    """良性 YAML（纯映射）在修复前后都应解析为相同结构。"""
    v = Vault("secret")
    data = v.load(b"name: test\nvalue: 42\n")
    assert data == {"name": "test", "value": 42}


def test_load_must_use_safe_load_not_unsafe_yaml_load():
    """修复后仅调用 yaml.safe_load，不得调用 yaml.load(UnsafeLoader…)."""
    with patch("yaml.load") as mock_yaml_load:
        with patch("yaml.safe_load") as mock_safe_load:
            mock_safe_load.return_value = {"a": 1}
            v = Vault("secret")
            out = v.load(b"a: 1\n")
            mock_yaml_load.assert_not_called()
            mock_safe_load.assert_called_once()
            assert out == {"a": 1}
