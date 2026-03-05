import subprocess

def ping_host(hostname):
    try:
        # Windows 环境下使用 -n 1
        result = subprocess.run(['ping', '-n', '1', hostname], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.returncode
    except subprocess.CalledProcessError as e:
        return e.returncode