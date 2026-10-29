import subprocess

def convert(path, fmt):
    subprocess.run(f"convert {path} out.{fmt}", shell=True)
    return "done"
