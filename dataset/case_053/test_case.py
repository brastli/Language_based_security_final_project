import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""写二进制并执行 — 刻画写入 + 禁止 os.system 执行用户数据文件。"""

import inspect
from pathlib import Path
from unittest.mock import patch

from vulnerable import createExecutableFile


def test_writes_binary_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with patch("os.system"):
        with patch("os.chmod"):
            createExecutableFile(b"\x7fELF")
    assert Path("test.bin").exists()


def test_must_not_invoke_shell_on_binary():
    src = inspect.getsource(createExecutableFile)
    assert "os.system" not in src
