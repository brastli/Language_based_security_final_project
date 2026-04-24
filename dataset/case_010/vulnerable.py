import os

def check_host_reachable(host):
    """Check if a host is reachable by running ping."""
    if not host or not host.strip():
        return False
    cmd = "ping -c 1 " + host.strip()
    exit_code = os.system(cmd)
    return exit_code == 0

if __name__ == "__main__":
    print(check_host_reachable("127.0.0.1"))
