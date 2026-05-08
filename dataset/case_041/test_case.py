import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""证书指纹 MD5 — 匹配刻画 + 禁止 md5。"""

import inspect

from vulnerable import certificate_matches


def test_matching_certificate():
    data = b"cert-bytes"
    import hashlib

    h = hashlib.md5(data).hexdigest()
    assert certificate_matches(data, h) is True


def test_must_not_use_md5_for_certificate_fingerprint():
    src = inspect.getsource(certificate_matches).lower()
    assert "md5" not in src
