"""
case_073 ← exported case_014_CVE-2024-22204_routes (Whoogle app/routes.py)。

会话 pickle.load；混入轻量路由占位函数。
"""

import pickle


def index_banner_stub():
    """占位。"""
    return "Whoogle"


def load_session_blob(path: str):
    """VULNERABLE：对标从磁盘会话 pickle.load。"""
    with open(path, "rb") as session_file:
        return pickle.load(session_file)


def save_session_dummy(path: str, obj: object) -> None:
    """占位。"""
    with open(path, "wb") as f:
        pickle.dump(obj, f)


def config_route_stub():
    return {"lang": "en"}
