"""
case_072 ← exported case_013_CVE-2023-42458_Image (Zope OFS/Image.py)。

parseString 解析 SVG/XML；混入无关尺寸占位函数。
"""

from xml.dom import minidom


def image_dimensions_placeholder():
    """占位。"""
    return (0, 0)


def parse_xml_metadata(data: bytes) -> str:
    """VULNERABLE：对标 minidom.parseString(data)。"""
    xmldoc = minidom.parseString(data)
    el = xmldoc.documentElement
    return el.tagName if el else ""


def normalize_filename_stub(name: str) -> str:
    """占位。"""
    return name.strip().lower()