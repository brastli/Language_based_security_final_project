import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""Cookie pickle — 用户态会话解码 + 禁止裸 pickle.loads。"""

import base64
import inspect
import pickle

from vulnerable import load_session


def test_session_roundtrip_dict_fields():
    raw = pickle.dumps({"user_id": 42, "role": "admin"})
    cookie = base64.b64encode(raw).decode("ascii")
    assert load_session(cookie) == (42, "admin")


def test_decode_must_not_rely_only_on_unrestricted_pickle_loads():
    src = inspect.getsource(load_session)
    assert "pickle.loads" not in src or "hmac" in src or "json.loads" in src or "itsdangerous" in src
