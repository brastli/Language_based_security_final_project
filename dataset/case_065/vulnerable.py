"""
case_065 ← exported case_006_CVE-2021-32568_import_utils (MrDoc import_utils).

read_zip 内 yaml.load；operat_md_media 等为无关逻辑占位（跨函数同一类内）。
"""

import re

import yaml


class ImportZipProject:
    """最小表面：保留 yaml 解析 + 一个 MD 占位处理。"""

    def read_project_meta_from_yaml_text(self, yaml_text: str):
        """VULNERABLE：对标 yaml.load(yaml_file.read())。"""
        yaml_str = yaml.load(yaml_text)
        name = yaml_str.get("project_name", "unnamed") if isinstance(yaml_str, dict) else "bad"
        return name

    def operat_md_media(self, md_content: str, _user):
        """占位：上游图片路径替换，不参与 YAML sink。"""
        if not re.search(r"!\[", md_content):
            return md_content
        return md_content + "\n"

    def temp_dir_name_stub(self, zip_path: str) -> str:
        """占位。"""
        return zip_path[:-4] + "_tmp"