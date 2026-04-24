from .db import read_log_file
from .utils import format_download_response


def handle_download_log_request(request_data: dict):
    filename = request_data.get('filename', '')
    return format_download_response(read_log_file(filename))
