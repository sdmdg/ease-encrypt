from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import os, base64


def generate_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    return key

def encrypt(password, input_file, output_file):
    salt = os.urandom(16)
    key = generate_key_from_password(password, salt)

    cipher_suite = Fernet(key)
    with open(input_file, 'rb') as file:
        file_data = file.read()

    encrypted_data = cipher_suite.encrypt(file_data)

    with open(output_file, 'wb') as file:
        file.write(salt)
        file.write(encrypted_data)

def decrypt(password, input_file, output_file):

    with open(input_file, 'rb') as file:
        salt = file.read(16)
        key = generate_key_from_password(password, salt)

        cipher_suite = Fernet(key)

        encrypted_data = file.read()

    decrypted_data = cipher_suite.decrypt(encrypted_data)

    with open(output_file, 'wb') as file:
        file.write(decrypted_data)