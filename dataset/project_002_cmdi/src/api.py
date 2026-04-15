from .db import save_scan_record
from .utils import ping_host


def handle_ping_request(request_data: dict):
    host = request_data.get('host', '')
    status_code = ping_host(host)
    return save_scan_record(host, status_code)
