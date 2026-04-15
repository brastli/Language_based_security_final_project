from vulnerable import run_backup

def test_run_backup_with_valid_directory():
    # Assuming the backup script and directory are set up correctly for testing
    assert run_backup("/valid/directory") == True

def test_run_backup_with_empty_directory():
    assert run_backup("") == False