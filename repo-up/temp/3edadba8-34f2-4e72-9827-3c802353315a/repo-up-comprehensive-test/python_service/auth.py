import hashlib

def hash_password(pwd):
    # Intentional: Weak Hash
    return hashlib.md5(pwd.encode()).hexdigest()

# Intentional: Fake Secret
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"

def dangerous_eval(expression):
    # Intentional: Unsafe dynamic execution
    return eval(expression)
