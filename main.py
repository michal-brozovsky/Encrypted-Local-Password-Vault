import json
import base64
import argparse
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

def generate_key(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key

def encrypt_data(data, key):
    f = Fernet(key)
    encrypted_data = f.encrypt(json.dumps(data).encode())
    return encrypted_data

def decrypt_data(encrypted_data, key):
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data)
    return json.loads(decrypted_data.decode())

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Local Encrypted Vault")
    parser.add_argument("-m", "--master", required=True, help="Master password")
    parser.add_argument("-a", "--add", nargs=2, metavar=('SERVICE', 'PASSWORD'), help="Add new credential")
    parser.add_argument("-r", "--read", action='store_true', help="Read all credentials")
    args = parser.parse_args()

    SALT_FILE = "vault_salt.bin"
    VAULT_FILE = "vault.enc"

    # Handle salt setup
    if not os.path.exists(SALT_FILE):
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
    else:
        with open(SALT_FILE, "rb") as f:
            salt = f.read()

    key = generate_key(args.master, salt)

    # Load existing vault or create empty
    vault_data = {}
    if os.path.exists(VAULT_FILE):
        try:
            with open(VAULT_FILE, "rb") as f:
                vault_data = decrypt_data(f.read(), key)
        except Exception:
            print("[!] Decryption failed. Incorrect master password.")
            exit()

    if args.add:
        service, password = args.add
        vault_data[service] = password
        with open(VAULT_FILE, "wb") as f:
            f.write(encrypt_data(vault_data, key))
        print(f"[+] Credentials for {service} saved securely.")

    if args.read:
        print("\n--- Decrypted Vault ---")
        for svc, pwd in vault_data.items():
            print(f"Service: {svc} | Password: {pwd}")