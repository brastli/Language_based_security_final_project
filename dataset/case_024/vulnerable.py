import os
import re

def send_notification(to_addr, subject, body):
    """Send an email using system sendmail command."""
    if not to_addr or not subject:
        return False
    email_re = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
    if not email_re.match(to_addr.strip()):
        return False
    max_body_len = 10000
    if len(body) > max_body_len:
        body = body[:max_body_len] + "... [truncated]"
    escaped_body = body.replace("'", "'\"'\"'")
    cmd = f"echo '{escaped_body}' | sendmail -s '{subject}' {to_addr}"
    ret = os.system(cmd)
    return ret == 0

if __name__ == "__main__":
    send_notification("user@local", "Alert", "Hello")
