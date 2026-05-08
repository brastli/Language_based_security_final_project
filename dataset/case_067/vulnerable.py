"""
case_067 ← exported case_008_CVE-2021-41127_persistor (rasa/nlu/persistor.py).

Persistor._decompress 使用 tar.extractall；get_persistor 为模块级噪声。
"""

import tarfile


def get_persistor_dummy(name: str):
    """占位：对标 get_persistor。"""
    return None if not name else name


class Persistor:
    @staticmethod
    def _decompress(compressed_path: str, target_path: str) -> None:
        with tarfile.open(compressed_path, "r:gz") as tar:
            tar.extractall(target_path)

    def retrieve_stub(self, name: str, target: str) -> str:
        """占位流程（不求真下载）。"""
        return f"would retrieve {name} to {target}"
