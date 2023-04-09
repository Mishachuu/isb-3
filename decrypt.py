import logging
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def decrypt_data(encrypted_file_path: str, private_key_path: str, encrypted_symmetric_key_path: str, decrypted_file_path: str) -> None:
    """эта функция дешифрует данные используя симметричный и ассиметричные ключи, а так же сохраняет результат по указоному пути

    Args:
        encrypted_file_path (str): путь до зашифрованных данных
        private_key_path (str): путь до секретного ключа
        encrypted_symmetric_key_path (str): путь до зашифрованного симметричного ключа
        decrypted_file_path (str): путь куда дешифруются данные
    """
    try:
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend())
    except FileNotFoundError:
        logging.error(f"{private_key_path} not found")
    try:
        with open(encrypted_symmetric_key_path, "rb") as f:
            encrypted_symmetric_key = f.read()
        symmetric_key = private_key.decrypt(encrypted_symmetric_key, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    except FileNotFoundError:
        logging.error(f"{encrypted_file_path} not found")
    try:
        with open(encrypted_file_path, "rb") as f_in, open(decrypted_file_path, "wb") as f_out:
            iv = f_in.read(16)
            cipher = Cipher(algorithms.SM4(symmetric_key),
                            modes.CBC(iv))
            decryptor = cipher.decryptor()
            unpadder = sym_padding.PKCS7(128).unpadder()
            try:
                with open(decrypted_file_path, "wb") as f_out:
                    while chunk := f_in.read(128):
                        decrypted_chunk = decryptor.update(chunk)
                        f_out.write(unpadder.update(decrypted_chunk))
                    f_out.write(unpadder.update(decryptor.finalize()))
                    f_out.write(unpadder.finalize())
            except FileNotFoundError:
                logging.error(f"{decrypted_file_path} not found")
    except FileNotFoundError:
        logging.error(f"{decrypted_file_path} not found") if os.path.isfile(
            encrypted_file_path) else logging.error(f"{encrypted_file_path} not found")
