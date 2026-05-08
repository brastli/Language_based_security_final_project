import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""subprocess.run(..., shell=True) — 功能 + 禁止 shell。"""

from unittest.mock import MagicMock, patch

from vulnerable import run


def test_benign_run_invokes_subprocess():
    with patch("subprocess.run") as m:
        m.return_value = MagicMock(returncode=0)
        run("echo benign")
        m.assert_called_once()


def test_must_not_use_shell_true():
    with patch("subprocess.run") as m:
        m.return_value = MagicMock(returncode=0)
        run("echo hello")
        _, kwargs = m.call_args
        assert kwargs.get("shell") is not True
