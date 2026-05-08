import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""git checkout shell 拼接 — 调用刻画 + 禁止 shell=True。"""

from unittest.mock import MagicMock, patch

from vulnerable import checkout_branch


def test_branch_checkout_invokes_subprocess():
    with patch("subprocess.Popen") as m:
        m.return_value = MagicMock(returncode=0)
        checkout_branch("/tmp/repo", "main")
        m.assert_called_once()


def test_must_not_use_shell_true():
    with patch("subprocess.Popen") as m:
        m.return_value = MagicMock(returncode=0)
        checkout_branch("/tmp/repo", "feature")
        _, kw = m.call_args
        assert kw.get("shell") is not True
