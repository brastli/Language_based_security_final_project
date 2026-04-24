import subprocess

def checkout_branch(repo_path, branch_name):
    """Switch git branch in the given repository."""
    if not branch_name or not repo_path:
        return False
    cmd = f"cd {repo_path} && git checkout {branch_name}"
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.wait()
    return proc.returncode == 0

if __name__ == "__main__":
    checkout_branch("/tmp/repo", "main")
