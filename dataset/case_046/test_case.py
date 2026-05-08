import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""tempfile.mktemp — 写入字节刻画 + 禁止 mktemp。"""

import inspect
from unittest.mock import patch

from vulnerable import write_results


def test_writes_utf8_to_temp_file(tmp_path):
    out = tmp_path / "out.bin"
    with patch("tempfile.mktemp", return_value=str(out)):
        write_results("hi")
    assert out.read_bytes() == b"hi"


def test_must_not_use_mktemp():
    src = inspect.getsource(write_results)
    assert "mktemp" not in src
