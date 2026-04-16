import subprocess
import re

def ping_host(host: str):
    """Ping a host to check its availability."""
    # Validate the host input to allow only valid IP addresses or hostnames
    if not re.match(r'^(?:[a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+$', host) and not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
        raise ValueError("Invalid host input")
    try:
        # Use subprocess.run with a list to avoid shell injection
        result = subprocess.run(['ping', '-n', '1', host], capture_output=True, text=True, check=True)
        return result.returncode
    except subprocess.CalledProcessError:
        return 1
