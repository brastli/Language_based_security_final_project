import tempfile
import os
import stat


def write_temp_log(data):
    fd, filename = tempfile.mkstemp()
    try:
        os.write(fd, data.encode())
    finally:
        os.close(fd)
    os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)