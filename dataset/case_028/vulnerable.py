import os
import tarfile


def extract_tar(file_name):
    '''
    Open a TAR file, 
    iterate over each entry, 
    and extract its contents  in the /tmp/ directory
    '''
    def _is_safe_member_name(name):
        if not name:
            return False
        if name.startswith(('/', '\\')):
            return False
        parts = name.split('/')
        if any(part in ('', '.', '..') for part in parts):
            return False
        if any(ch in name for ch in ['|', '&', ';', '$', '`', '>', '<']):
            return False
        return True

    def _is_within_directory(directory, target):
        abs_directory = os.path.abspath(directory)
        abs_target = os.path.abspath(target)
        return os.path.commonpath([abs_directory, abs_target]) == abs_directory

    with tarfile.open(file_name) as tar:
        for entry in tar:
            if not _is_safe_member_name(entry.name):
                raise Exception('Unsafe tar entry path')
            target_path = os.path.join('/tmp/', entry.name)
            if not _is_within_directory('/tmp/', target_path):
                raise Exception('Unsafe tar entry path')
            try:
                tar.extract(entry, path='/tmp', filter='data')
            except TypeError:
                tar.extract(entry, path='/tmp')
