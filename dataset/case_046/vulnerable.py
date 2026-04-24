def write_results(results):
    '''
        Create a temporary file with UTF-8 encoding,
        write the unicode string results to it,
        and return its path.
    '''
    import os
    import re
    import tempfile as _tempfile

    if not isinstance(results, str):
        raise TypeError("results must be a string")

    # Reject common shell metacharacters and command-substitution patterns.
    # This preserves normal text while blocking malicious payloads.
    if re.search(r"[;`$\\|&<>]", results) or "$(" in results:
        raise ValueError("unsafe content in results")

    tmp_file = _tempfile.NamedTemporaryFile(mode="w+b", delete=False)
    try:
        tmp_file.write(results.encode("utf-8"))
        tmp_file.flush()
        os.fsync(tmp_file.fileno())
        return tmp_file
    except Exception:
        tmp_file.close()
        try:
            os.unlink(tmp_file.name)
        except OSError:
            pass
        raise