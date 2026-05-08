import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""备份脚本路径拼接 — 良性路径 + 拒绝路径注入。"""

from unittest.mock import patch

import pytest

from vulnerable import run_backup


def test_safe_path_invokes_backup():
    with patch("os.system", return_value=0):
        assert run_backup("/var/data") is True


def test_path_must_reject_shell_metacharacters():
    with pytest.raises(ValueError):
        run_backup("/var/data; rm -rf /")
