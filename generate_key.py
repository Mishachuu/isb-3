import logging
import os

from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

SETTINGS = {'initial_file': 'file\initial_file.txt', 'encrypted_file': 'file\encrypted_file.txt', 'decrypted_file': 'file\decrypted_file.txt',
            'symmetric_key': 'key\symmetric_key.txt', 'public_key': 'key\public\key.pem', 'secret_key': 'key\secret\key.pem'}


def generate_key_pair(private_key_path: str,  public_key_path: str, symmetric_key_path: str) -> None:
    """Эта функция генерирует пару ключей(ассиметричный и симметричный) гибридной системы, а после сохраняет их в файлы.

    Args:
        private_key_path (str): путь до секретного ключа
        public_key_path (str): путь до общедоступного ключа
        symmetric_key_path (str): путь до симметричного ключа
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    try:
        with open(public_key_path, 'wb') as f_p, open(private_key_path, 'wb') as f_c:
            f_p.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo))
            f_c.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                encryption_algorithm=serialization.NoEncryption()))
    except FileNotFoundError:
        logging.error(f"{private_key_path} not found") if os.path.isfile(
            public_key_path) else logging.error(f"{public_key_path} not found")
    symmetric_key = os.urandom(16)
    ciphertext = public_key.encrypt(symmetric_key, padding.OAEP(mgf=padding.MGF1(
        algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    try:
        with open(symmetric_key_path, "wb") as f:
            f.write(ciphertext)
    except FileNotFoundError:
        logging.error(f"{symmetric_key_path} not found")
