from .db import get_user_by_name
from .utils import normalize_username


def handle_login_request(request_data: dict):
    """?? API ????"""
    username = normalize_username(request_data.get('username', ''))
    return get_user_by_name(username)
