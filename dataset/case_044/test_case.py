import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""crypto key — 返回整数密钥 + 禁止短 seed 喂 random。"""

import inspect

from vulnerable import generateCryptoKey


def test_key_is_integer():
    k = generateCryptoKey()
    assert isinstance(k, int)


def test_must_not_seed_stdlib_random():
    src = inspect.getsource(generateCryptoKey)
    assert "random.seed" not in src
