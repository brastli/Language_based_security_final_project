import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

"""
安全验收测试（Security acceptance）：预期「修复后」满足这些断言。

未修复的 mark_safe 基线会在恶意用例上失败——这是刻意的：
单靠「漏洞行为复现」类测试无法证明补丁有效，必须配合本文件 +
流水线里的 Bandit 复扫（main.py / scanner.py）。

若希望单独跑「仅复现漏洞行为」类检查，请维护单独脚本或 xfail 用例。
"""

import re

import pytest

from vulnerable import BaseModelAdmin, AdminSiteStub, get_empty_value_display

# 粗粒度检测「用户可控字符串里是否仍以原始 HTML 形式出现危险片段」
_RAW_MARKUP = re.compile(
    r"(<\s*script\b|<\s*svg\b|<\s*img\b|=\s*alert\s*\(|=\s*prompt\s*\()",
    re.I | re.DOTALL,
)


def test_benign_placeholder_still_visible():
    """占位文案仍应对管理员可见（不要求一字不差保留实体写法）。"""
    result = get_empty_value_display("&mdash;")
    assert "mdash" in str(result)


def test_user_payload_must_not_emit_raw_markup_tags():
    """修复后：输出中不应再含可被模板当作标签解析的原始片段。"""
    payload = "<script>alert('XSS')</script>"
    result = get_empty_value_display(payload)
    assert not _RAW_MARKUP.search(
        str(result)
    ), "输出仍含原始 HTML/脚本片段；若未修复应失败，修复并转义后应变绿"


def test_event_handler_payload_must_not_appear_as_raw_markup():
    payload = "<img src=x onerror=alert('XSS')>"
    result = get_empty_value_display(payload)
    text = str(result)
    assert (
        "<img" not in text.lower()
    ), "仍输出原始 <img …>；正确修复应转义或剥离标记"


def test_fallback_path_must_not_emit_raw_markup():
    site_payload = "<svg onload=alert('XSS')>"
    admin = BaseModelAdmin(admin_site=AdminSiteStub(site_payload))
    with pytest.raises(AttributeError):
        _ = admin.empty_value_display

    result = admin.get_empty_value_display()
    assert (
        "<svg" not in str(result).lower()
    ), "except 分支仍输出原始 <svg …>；修复后应变绿"
