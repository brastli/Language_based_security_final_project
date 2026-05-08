import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""SHA1 校验 — 正确十六进制匹配 + 升级为 SHA-256 等。"""

import hashlib
import inspect

from vulnerable import verify_package_checksum


def test_matching_checksum_succeeds():
    data = b"payload"
    h = hashlib.sha1(data).hexdigest()
    assert verify_package_checksum(data, h) is True


def test_must_not_use_sha1_for_integrity():
    src = inspect.getsource(verify_package_checksum)
    assert "sha1" not in src.lower()
