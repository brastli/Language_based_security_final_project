import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""用户模板 exec — 良性占位渲染 + 拒绝明显危险片段。"""

import pytest

from vulnerable import render_user_template


def test_template_sets_output_from_context():
    assert render_user_template("output = name", {"name": "Alice"}) == "Alice"


def test_rejects_dunder_in_template():
    with pytest.raises(ValueError):
        render_user_template("output = str(__class__)", {"name": "x"})
