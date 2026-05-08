import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""会话 ID — 整数范围 + 禁止 random.randint / 须使用 secrets。"""

import inspect

from vulnerable import getSessionID


def test_session_id_is_in_uint32_range():
    sid = getSessionID()
    assert 0 <= sid <= 0xFFFFFFFF


def test_must_use_secrets_not_randint():
    src = inspect.getsource(getSessionID)
    assert "random.randint" not in src
    assert "secrets." in src
