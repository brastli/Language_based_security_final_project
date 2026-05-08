import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""DES ECB — 加密输出长度 + 禁止 DES / ECB。"""

import inspect

import pytest

pytest.importorskip("Crypto")

from vulnerable import encrypt_secret


def test_encrypt_produces_non_empty_bytes():
    out = encrypt_secret("secret", "key12345")
    assert isinstance(out, bytes) and len(out) > 0


def test_must_not_use_des_ecb():
    src = inspect.getsource(encrypt_secret)
    assert "DES" not in src and "MODE_ECB" not in src
