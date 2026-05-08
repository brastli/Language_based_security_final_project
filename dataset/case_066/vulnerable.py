"""
case_066 ← exported case_007_CVE-2021-41127_model (rasa/model.py unpack_model).

tar.extractall 无校验；附带 get_latest_model_dummy 等噪声函数。
"""

import glob
import os
import tarfile
import tempfile


def get_latest_model_dummy(model_path: str):
    """占位：对标 get_latest_model 体量。"""
    if not os.path.isdir(model_path):
        return None
    files = glob.glob(os.path.join(model_path, "*.tar.gz"))
    return max(files, key=os.path.getctime) if files else None


def unpack_model(model_file: str, working_directory=None):
    """VULNERABLE：tar.extractall 未过滤危险成员（Bandit B202）。"""
    if working_directory is None:
        working_directory = tempfile.mkdtemp()
    with tarfile.open(model_file, mode="r:gz") as tar:
        tar.extractall(working_directory)
    return working_directory


def fingerprint_stub(path: str) -> dict:
    """占位。"""
    return {} if not path else {"path": path}
