from src.api import handle_ping_request


def test_normal_ping_like_flow():
    result = handle_ping_request({'host': '127.0.0.1'})
    assert result['host'] == '127.0.0.1'
    assert isinstance(result['status_code'], int)
