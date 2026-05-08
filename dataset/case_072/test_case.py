import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.modules.pop("vulnerable", None)

import inspect

from vulnerable import image_dimensions_placeholder, parse_xml_metadata


def test_dimensions_placeholder():
    assert image_dimensions_placeholder() == (0, 0)


def test_parse_simple_svg_tag():
    data = b"<svg xmlns='http://www.w3.org/2000/svg'></svg>"
    assert parse_xml_metadata(data).lower() == "svg"


def test_must_not_parse_untrusted_bytes_with_minidom_only():
    """应对不受信 XML 使用 defusedxml 或等价安全解析器。"""
    src = inspect.getsource(parse_xml_metadata)
    assert "defusedxml" in src.lower() or "minidom.parseString" not in src

