from dotenv import load_dotenv
load_dotenv()

def read_doc(path_from_user):
    with open(path_from_user) as fh:
        return fh.read()
