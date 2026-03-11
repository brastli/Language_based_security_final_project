import subprocess
import os
import json

def run_npm_script(project_dir, script_name, env=None):
    """Run an npm script by name in the given project directory with optional env."""
    if not script_name or not project_dir:
        return -1
    project_dir = os.path.abspath(project_dir)
    if not os.path.isdir(project_dir):
        return -1
    package_path = os.path.join(project_dir, "package.json")
    if os.path.isfile(package_path):
        with open(package_path, "r", encoding="utf-8") as f:
            pkg = json.load(f)
        scripts = pkg.get("scripts", {})
        if script_name not in scripts:
            return -2
    env_copy = os.environ.copy()
    if env:
        env_copy.update(env)
    cmd = f"npm run {script_name}"
    ret = subprocess.call(cmd, shell=True, cwd=project_dir, env=env_copy)
    return ret

if __name__ == "__main__":
    run_npm_script("/app", "build")
