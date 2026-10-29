import os

def load_key():
    with open(os.path.expanduser("~/.ssh/id_rsa")) as fh:
        return fh.read()
