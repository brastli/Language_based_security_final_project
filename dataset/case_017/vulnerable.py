import os

def run_backup(target_dir):
    """Run backup script for the given target directory."""
    if not target_dir or not target_dir.strip():
        return False
    script = "backup.sh"
    cmd = script + " " + target_dir.strip()
    ret = os.system(cmd)
    return ret == 0

if __name__ == "__main__":
    run_backup("/var/data")
