import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""
A — 功能回归：legacy pickle 线路格式仍能签到成功（与上游「pickle 客户端」一致）。

B — 修复验收：UTF-8 JSON 负载应先 json.loads，不得在无必要时调用 pickle.loads
（未修复基线在此处失败）。

配合 Bandit B301 与 main.py 复扫。
"""

import base64
import bz2
import json
import pickle
from unittest.mock import patch

from vulnerable import checkin


def _encode_wire(obj, *, as_json: bool) -> str:
    body = json.dumps(obj).encode("utf-8") if as_json else pickle.dumps(obj)
    return base64.urlsafe_b64encode(bz2.compress(body)).decode("ascii")


def test_legacy_pickle_wire_checkin_success():
    """pickle 序列化的合法 dict 仍能走完流程并成功返回。"""
    wire = _encode_wire({"valid": True}, as_json=False)
    out = checkin(wire)
    assert "checked in successful" in out


def test_json_wire_checkin_success_without_pickle_loads():
    """
    修复后：纯 JSON 字节应先被 json.loads 接受，且不应调用 pickle.loads。
    未修复版本只对 pickle.loads(JSON 字节) → 抛错或无法签到成功。
    """
    wire = _encode_wire({"valid": True}, as_json=True)
    pickle_invocations = []
    real_loads = pickle.loads

    def traced(buf):
        pickle_invocations.append(buf)
        return real_loads(buf)

    with patch("pickle.loads", side_effect=traced):
        try:
            out = checkin(wire)
        except Exception as exc:
            assert False, (
                "JSON 线路在修复后应成功返回；当前仍失败，说明未走 json-first 或等价安全解码。"
                f" 异常: {exc!r}"
            )
        assert "checked in successful" in out
        assert not pickle_invocations, (
            "JSON 负载不应触发 pickle.loads；若调用列表非空则仍可能在反序列化不受信 pickle。"
        )
