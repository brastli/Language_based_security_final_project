from src.api import handle_download_log_request


def test_path_traversal():
    payload = '../secret.txt'

    try:
        result = handle_download_log_request({'filename': payload})
    except Exception:
        return

    assert result['content'] is None
