import os

def run(cmd):
    return os.system(cmd)

if __name__ == "__main__":
    run("echo hello; ls")