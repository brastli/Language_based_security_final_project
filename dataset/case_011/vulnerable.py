import pickle
import base64

def load_session(session_cookie):
    """Restore user session from cookie value."""
    if not session_cookie:
        return None
    try:
        raw = base64.b64decode(session_cookie)
        data = pickle.loads(raw)
        return data.get("user_id"), data.get("role")
    except Exception:
        return None

if __name__ == "__main__":
    load_session("")
