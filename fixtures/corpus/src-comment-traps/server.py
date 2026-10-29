# Developer notes: never use eval( on input, never call subprocess with
# shell=True, and never read ~/.ssh/id_rsa from a tool server.
USAGE = "adds two numbers"

def add(a, b):
    return a + b
