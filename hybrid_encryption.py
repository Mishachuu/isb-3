import argparse
import os
import sys
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap


def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()

    print(type(private_key))
    print(private_key)
    print(type(public_key))
    print(public_key)

    return private_key, public_key


def generate_symmetric_key():
    key = os.urandom(128)
    print(type(key))
    print(key)
    return key


def encrypt_symmetric_key(symmetric_key, public_key):
    encrypted_key = public_key.encrypt(symmetric_key, padding.OAEP(mgf=padding.MGF1(
        algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return encrypted_key

def encrypt_file(input_file, output_file, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.SM4(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

 

def main():
    parser = argparse.ArgumentParser(description='Hybrid encryption')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-gen', '--generation',
                       help='Запускает режим генерации ключей')
    group.add_argument('-enc', '--encryption',
                       help='Запускает режим шифрования')
    group.add_argument('-dec', '--decryption',
                       help='Запускает режим дешифрования')

    args = parser.parse_args()
    if args.generation is not None:
        # генерируем ключи
    else if args.encryption is not None:
        # шифруем
    else:
        # дешифруем

        # генерируем ключ


if __name__ == "__main__":
    main()
