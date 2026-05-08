import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

import inspect
import pickle
from pathlib import Path

from vulnerable import index_banner_stub, load_session_blob


def test_banner_stub():
    assert "Whoogle" in index_banner_stub()


def test_roundtrip_session_file(tmp_path: Path):
    p = tmp_path / "s.pkl"
    with open(p, "wb") as f:
        pickle.dump({"user": "u1"}, f)
    assert load_session_blob(str(p))["user"] == "u1"


def test_must_not_use_pickle_load_for_session_blob():
    """会话文件不应直接 pickle.load；应签名 JSON / itsdangerous 等。"""
    src = inspect.getsource(load_session_blob)
    assert "pickle.load" not in src or "json.load" in src

