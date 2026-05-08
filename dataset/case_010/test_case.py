import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""ping 拼接命令注入 — 可达性检查 + 拒绝 shell 元字符。"""

from unittest.mock import patch

import pytest

from vulnerable import check_host_reachable


def test_safe_loopback_host_returns_true_when_ping_ok():
    with patch("os.system", return_value=0):
        assert check_host_reachable("127.0.0.1") is True


def test_host_argument_must_reject_shell_injection():
    with pytest.raises(ValueError):
        check_host_reachable("127.0.0.1; user_payload")
