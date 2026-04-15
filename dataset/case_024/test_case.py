from vulnerable import send_notification

def test_send_notification_valid_email():
    result = send_notification("user@example.com", "Test Subject", "This is a test body.")
    assert result == True

def test_send_notification_empty_subject():
    result = send_notification("user@example.com", "", "This is a test body.")
    assert result == False