import subprocess

def convert(path, out):
    subprocess.run(["convert", path, out], shell=False, check=True)
    return out
