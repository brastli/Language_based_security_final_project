import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""tar 解压 — 须在 extract 时使用路径过滤（PEP 706 data_filter 等）。"""

import inspect

from vulnerable import extract_tar


def test_extract_function_present():
    src = inspect.getsource(extract_tar)
    assert "extract" in src


def test_must_use_tar_member_filter():
    """未修补基线直接 tar.extract；修复后应包含 data_filter / filter 参数。"""
    src = inspect.getsource(extract_tar)
    assert "data_filter" in src or "filter=" in src
