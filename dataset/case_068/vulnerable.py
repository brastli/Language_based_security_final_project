"""
case_068 ← exported case_009_CVE-2021-4118_saving (PyTorch Lightning utilities/saving.py).

load_hparams_from_yaml 内 yaml.load(fp)；附带 CSV 占位名以对齐全文件噪声。
"""

import yaml


def load_tags_csv_stub(path: str) -> dict:
    """占位。"""
    return {}


def load_hparams_from_yaml_text(raw: str):
    """VULNERABLE：对标 fs.open + yaml.load(fp, Loader=UnsafeLoader)。"""
    return yaml.load(raw, Loader=yaml.UnsafeLoader)


def save_hparams_dummy(path: str, data: dict) -> None:
    """占位。"""
    _ = yaml.dump(data)