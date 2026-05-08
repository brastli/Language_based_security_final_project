import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""
功能验收：良性命令能调用到 subprocess.Popen（mock，不执行 shell）。
安全验收：修复后 shell=True 不得用于解析不可信整串命令。
"""

from unittest.mock import MagicMock, patch

from vulnerable import run


def test_benign_command_reaches_subprocess():
    with patch("subprocess.Popen") as m:
        m.return_value = MagicMock()
        run("echo benign")
        m.assert_called_once()


def test_must_not_use_shell_true():
    """未修补基线使用 shell=True；修复后须为 False 并使用 argv 列表等形式。"""
    with patch("subprocess.Popen") as m:
        m.return_value = MagicMock()
        run("echo hello")
        _, kwargs = m.call_args
        assert kwargs.get("shell") is not True
