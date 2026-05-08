import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""
功能验收：合法 pickle（dict）可反序列化。
安全验收：实现需包含显式安全解码路径（如 json / yaml.safe_load / 受限 unpickle），非裸 pickle.loads。
"""

import inspect
import pickle

from vulnerable import run


def test_benign_dict_roundtrip():
    blob = pickle.dumps({"k": 1})
    assert run(blob) == {"k": 1}


def test_implementation_must_include_safe_decode_alternative():
    """基线仅 pickle.loads；修复后应出现 json/yaml/safe 或 Restricted 等关键字之一。"""
    src = inspect.getsource(run)
    safe_markers = ("json.loads", "yaml.safe_load", "RestrictedUnpickler", "safe_load")
    assert any(m in src for m in safe_markers), (
        "须在源码中体现安全反序列化路径，而非仅 pickle.loads。"
    )
