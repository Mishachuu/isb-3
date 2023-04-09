import logging
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt_data(initial_file_path: str, private_key_path: str, encrypted_symmetric_key_path: str, encrypted_file_path: str) -> None:
    """Эта функция шифрует данные используя симметричный и ассиметричные ключи, а так же сохраняет результат по указыному пути

    Args:
        initial_file_path (str): путь до шифруемых данных
        private_key_path (str): путь до приватного ключа
        encrypted_symmetric_key_path (str): путь до зашифрованного симметричного ключа
        encrypted_file_path (str): путь куда шифруются данных
    """
    try:
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(), password=None)
    except FileExistsError:
        logging.error(f"{private_key_path} not found")
    try:
        with open(encrypted_symmetric_key_path, "rb") as f:
            encrypted_symmetric_key = f.read()
        symmetric_key = private_key.decrypt(encrypted_symmetric_key, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    except FileNotFoundError:
        logging.error(f"{encrypted_file_path} not found")
    iv = os.urandom(16)
    cipher = Cipher(algorithms.SM4(symmetric_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(128).padder()
    try:
        with open(initial_file_path, "rb") as f_in, open(encrypted_file_path, "wb") as f_out:
            f_out.write(iv)
            while chunk := f_in.read(128):
                padded_chunk = padder.update(chunk)
                f_out.write(encryptor.update(padded_chunk))
            f_out.write(encryptor.update(padder.finalize()))
            f_out.write(encryptor.finalize())
    except FileNotFoundError:
        logging.error(f"{initial_file_path} not found") if os.path.isfile(
            encrypted_file_path) else logging.error(f"{encrypted_file_path} not found")
