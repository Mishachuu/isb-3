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
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives import padding as sym_padding
import json
settings = {
    'initial_file': 'path/to/inital/file.txt',
    'encrypted_file': 'path/to/encrypted/file.txt',
    'decrypted_file': 'path/to/decrypted/file.txt',
    'symmetric_key': 'path/to/symmetric/key.txt',
    'public_key': 'path/to/public/key.pem',
    'secret_key': 'path/to/secret/key.pem',
}


def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    with open(settings['public_key'], 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    with open(settings['private_key'], 'wb') as f:
        f.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                          format=serialization.PrivateFormat.TraditionalOpenSSL,
                                          encryption_algorithm=serialization.NoEncryption()))

     # Генерация ключа симметричного алгоритма
    symmetric_key = os.urandom(128)

    # Шифрование ключа симметричного алгоритма
    ciphertext = public_key.encrypt(symmetric_key, padding.OAEP(mgf=padding.MGF1(
        algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

    # Сохранение зашифрованного ключа симметричного алгоритма
    with open(settings['symmetric_key'], "wb") as f:
        f.write(ciphertext)


def encrypt_data():
    # Чтение закрытого ключа
    with open(settings['private_key'], "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=None)

    # Расшифровка симметричного ключа
    with open(settings['symmetric_key'], "rb") as f:
        encrypted_symmetric_key = f.read()

    symmetric_key = private_key.decrypt(encrypted_symmetric_key, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

    # Шифрование текстового файла
    cipher = Cipher(algorithms.SM4(symmetric_key), modes.CBC(
        os.urandom(128)))
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(128).padder()

    with open(settings['initial_file'], "rb") as f_in, open(settings['encrypted_file'], "wb") as f_out:
        while chunk := f_in.read(128):
            padded_chunk = padder.update(chunk)
            f_out.write(encryptor.update(padded_chunk))

        f_out.write(encryptor.update(padder.finalize()))
        f_out.write(encryptor.finalize())


def decrypt_data(input_file, private_key_path, encrypted_symmetric_key_path, output_file):
    # Чтение закрытого ключа
    with open(settings['private_key'], "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    # Расшифровка симметричного ключа
    with open(settings['symmetric_key'], "rb") as f:
        encrypted_symmetric_key = f.read()

    symmetric_key = private_key.decrypt(encrypted_symmetric_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

    # Дешифрование текстового файла
    cipher = Cipher(algorithms.SM4(symmetric_key), modes.CBC(os.urandom(16)), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = sym_padding.PKCS7(128).unpadder()

    with open(settings['encrypted_file'], "rb") as f_in, open(settings['decrypted_file'], "wb") as f_out:
        while chunk := f_in.read(128):
            decrypted_chunk = decryptor.update(chunk)
            f_out.write(unpadder.update(decrypted_chunk))

        f_out.write(unpadder.update(decryptor.finalize()))
        f_out.write(unpadder.finalize())



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
        #создаем пару ключей

    else if args.encryption is not None:
        # шифруем
    else:
        # дешифруем

        # генерируем ключ

    with open('settings.json', 'w') as fp:
        json.dump(settings, fp)
# читаем из файла
    with open('settings.json') as json_file:
        json_data = json.load(json_file)

    print(json_data)


if __name__ == "__main__":
    main()
