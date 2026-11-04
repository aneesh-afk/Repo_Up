import yaml
import hashlib

def process_config(data: str):
    # This should trigger SEC-INSECURE-DESERIALIZATION which has autofix_available=True
    config = yaml.load(data)
    return config

def get_hash(text: str):
    # This should trigger SEC-CRYPTO-WEAK which has autofix_available=True
    h = hashlib.md5()
    h.update(text.encode())
    return h.hexdigest()

def execute_user_code(user_script: str):
    # This should trigger SEC-EVAL-EXEC which has autofix_available=False
    eval(user_script)

def test_sandbox():
    print("Sandbox test file loaded successfully")
