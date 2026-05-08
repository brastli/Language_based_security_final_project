import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""
功能验收：良性命令在 mock 下被传入 os.system 一次。
安全验收：修复后应对含 shell 元字符的命令拒绝执行（基线未校验则失败）。
"""

from unittest.mock import patch

import pytest

from vulnerable import run


def test_benign_command_invokes_system_once():
    with patch("os.system", return_value=0) as m:
        run("echo benign")
        m.assert_called_once_with("echo benign")


def test_shell_metacharacters_in_command_must_be_rejected():
    """修复后须拒绝 ; | & 等拼接的多条命令；未修补时直接传入 os.system，本用例失败。"""
    with pytest.raises(ValueError):
        run("echo ok; rm -rf /tmp/se_test_marker")
