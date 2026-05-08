import sys
from pathlib import Path
from unittest.mock import patch

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""tempfile.mktemp — 写入文件刻画 + 禁止 mktemp。"""

import inspect


def test_writes_results_to_temp_path(tmp_path):
    sys.modules.pop("vulnerable", None)
    sys.path.insert(0, _ROOT)
    import vulnerable as vm

    with patch.object(vm, "mktemp", return_value=str(tmp_path / "out.txt")):
        with patch("builtins.print"):
            vm.write_results("hello")
    assert (tmp_path / "out.txt").read_text(encoding="utf-8") == "hello"


def test_must_not_use_mktemp():
    sys.modules.pop("vulnerable", None)
    sys.path.insert(0, _ROOT)
    import vulnerable as vm

    src = inspect.getsource(vm.write_results)
    assert "mktemp" not in src
