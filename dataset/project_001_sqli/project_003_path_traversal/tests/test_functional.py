from src.api import handle_download_log_request


def test_normal_download():
    result = handle_download_log_request({'filename': 'app.log'})
    assert result['content'] == 'system started\n'
