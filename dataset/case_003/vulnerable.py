import subprocess

def run(cmd):
    return subprocess.Popen(cmd, shell=True)

if __name__ == "__main__":
    run("echo hello; ls")