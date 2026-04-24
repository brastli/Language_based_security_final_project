import os
import re
import tempfile


def write_results(results):
    '''
    Create a temporary file and write the results to it
    '''
    if not isinstance(results, str):
        raise TypeError("results must be a string")

    if re.search(r"(;\s*DROP\s+TABLE|\$\(|`)", results, re.IGNORECASE):
        raise ValueError("unsafe content rejected")

    fd, filename = tempfile.mkstemp()
    try:
        with os.fdopen(fd, "w+") as f:
            f.write(results)
    except Exception:
        try:
            os.unlink(filename)
        except OSError:
            pass
        raise

    print("Results written to", filename)
