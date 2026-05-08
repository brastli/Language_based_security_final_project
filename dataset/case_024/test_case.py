import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""sendmail os.system — 合法邮件 + 拒绝换行等注入分隔符。"""

from unittest.mock import patch

import pytest

from vulnerable import send_notification


def test_valid_notification_invokes_sendmail():
    with patch("os.system", return_value=0):
        assert send_notification("user@local", "Alert", "Hello") is True


def test_body_must_reject_newlines():
    with pytest.raises(ValueError):
        send_notification("user@local", "subj", "line1\nline2;evil")
