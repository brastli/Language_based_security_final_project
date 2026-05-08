import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""
安全验收：Admin helpers 中错误串被 mark_safe 的漏洞，修复后不应再向模板泄露原始标签。

未修复基线在恶意 payload 上预期失败；与 Bandit 复扫配合使用（见项目 main.py）。
"""

import re

import pytest

from vulnerable import (
    MockForm,
    get_admin_field_errors_display,
    get_errors_display,
)

_RAW_MARKUP = re.compile(r"(<\s*script\b|<\s*body\b|<\s*svg\b|<\s*img\b)", re.I)


def test_normal_error_message_not_raw_markup():
    form = MockForm({"username": "Field is required"})
    result = get_errors_display(form, ["username"])
    assert "Field is required" in str(result)
    assert not _RAW_MARKUP.search(str(result))


def test_fieldline_errors_must_not_contain_raw_script_tag():
    payload = "<script>alert('XSS')</script>"
    malicious_form = MockForm({"username": payload})
    result = get_errors_display(malicious_form, ["username"])
    assert not _RAW_MARKUP.search(
        str(result)
    ), "错误 HTML 仍含原始 script；修复后应变绿"


def test_fieldline_errors_must_not_contain_raw_img_tag():
    payload = "<img src=x onerror=alert('attacked')>"
    malicious_form = MockForm({"email": payload})
    result = get_errors_display(malicious_form, ["email"])
    assert "<img" not in str(result).lower()


def test_adminfield_errors_must_not_contain_raw_markup():
    payload = "<body onload=alert('XSS')>"
    malicious_form = MockForm({"bio": payload})
    result = get_admin_field_errors_display(malicious_form, "bio")
    assert "<body" not in str(result).lower()


def test_multiple_fields_no_raw_markup_from_user():
    malicious_form = MockForm(
        {
            "field1": "Error 1",
            "field2": "Error 2<svg onload=alert('XSS')>",
        }
    )
    result = get_errors_display(malicious_form, ["field1", "field2"])
    assert "<svg" not in str(result).lower()
