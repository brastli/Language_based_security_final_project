import marshal

def load_cached_preferences(data_bytes):
    """Load serialized user preferences from cache."""
    if not data_bytes or len(data_bytes) == 0:
        return {}
    try:
        obj = marshal.loads(data_bytes)
        return obj if isinstance(obj, dict) else {}
    except (ValueError, TypeError):
        return {}

if __name__ == "__main__":
    load_cached_preferences(b"")
