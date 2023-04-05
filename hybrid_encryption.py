import json
import os
import argparse
import logging
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
settings = {
    'initial_file': 'file\initial_file.txt',
    'encrypted_file': 'file\encrypted_file.txt',
    'decrypted_file': 'file\decrypted_file.txt',
    'symmetric_key': 'key\symmetric_key.txt',
    'public_key': 'key\public\key.pem',
    'secret_key': 'key\secret\key.pem'
}


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
    with open(public_key_path, 'wb') as f_p, open(private_key_path, 'wb') as f_c:
        f_p.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo))
        f_c.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                                            encryption_algorithm=serialization.NoEncryption()))
    symmetric_key = os.urandom(16)
    ciphertext = public_key.encrypt(symmetric_key, padding.OAEP(mgf=padding.MGF1(
        algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    with open(symmetric_key_path, "wb") as f:
        f.write(ciphertext)


def encrypt_data(initial_file_path: str, private_key_path: str, encrypted_symmetric_key_path: str, encrypted_file_path: str) -> None:
    """Эта функция шифрует данные используя симметричный и ассиметричные ключи, а так же сохраняет результат по указыному пути

    Args:
        initial_file_path (str): путь до шифруемых данных
        private_key_path (str): путь до приватного ключа
        encrypted_symmetric_key_path (str): путь до зашифрованного симметричного ключа
        encrypted_file_path (str): путь куда шифруются данных
    """
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=None)
    with open(encrypted_symmetric_key_path, "rb") as f:
        encrypted_symmetric_key = f.read()
    symmetric_key = private_key.decrypt(encrypted_symmetric_key, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    iv = os.urandom(16)
    cipher = Cipher(algorithms.SM4(symmetric_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(128).padder()
    with open(initial_file_path, "rb") as f_in, open(encrypted_file_path, "wb") as f_out:
        f_out.write(iv)
        while chunk := f_in.read(128):
            padded_chunk = padder.update(chunk)
            f_out.write(encryptor.update(padded_chunk))
        f_out.write(encryptor.update(padder.finalize()))
        f_out.write(encryptor.finalize())


def decrypt_data(encrypted_file_path: str, private_key_path: str, encrypted_symmetric_key_path: str, decrypted_file_path: str) -> None:
    """эта функция дешифрует данные используя симметричный и ассиметричные ключи, а так же сохраняет результат по указоному пути

    Args:
        encrypted_file_path (str): путь до зашифрованных данных
        private_key_path (str): путь до секретного ключа
        encrypted_symmetric_key_path (str): путь до зашифрованного симметричного ключа
        decrypted_file_path (str): путь куда дешифруются данные
    """
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend())
    with open(encrypted_symmetric_key_path, "rb") as f:
        encrypted_symmetric_key = f.read()
    symmetric_key = private_key.decrypt(encrypted_symmetric_key, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    with open(encrypted_file_path, "rb") as f_in, open(decrypted_file_path, "wb") as f_out:
        iv = f_in.read(16)
        cipher = Cipher(algorithms.SM4(symmetric_key),
                        modes.CBC(iv))
        decryptor = cipher.decryptor()
        unpadder = sym_padding.PKCS7(128).unpadder()
        with open(decrypted_file_path, "wb") as f_out:
            while chunk := f_in.read(128):
                decrypted_chunk = decryptor.update(chunk)
                f_out.write(unpadder.update(decrypted_chunk))
            f_out.write(unpadder.update(decryptor.finalize()))
            f_out.write(unpadder.finalize())


def load_settings(settings_file_path: str) -> dict:
    """ эта функция читает из файла

    Args:
        settings_file_path (str): путь до файла

    Returns:
        dict: данные файла
    """
    with open(settings_file_path) as json_file:
        json_data = json.load(json_file)
    return json_data


def unload_settings(settings_file_path: str, settings: dict) -> None:
    """функция пишет данные в файл

    Args:
        settings_file_path (str): путь до файла
        settings (dict): данные
    """
    with open(settings_file_path, 'w') as fp:
        json.dump(settings, fp)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(
        description="Hybrid encryption using an asymmetric and symmetric key")
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument('-gen', '--generation', action='store_true',
                            help='Запускает режим генерации ключей')
    mode_group.add_argument('-enc', '--encryption', action='store_true',
                            help='Запускает режим шифрования')
    mode_group.add_argument('-dec', '--decryption', action='store_true',
                            help='Запускает режим дешифрования')
    parser.add_argument('-set', '--settings', help='Загружает файл json')
    args = parser.parse_args()
    if args.settings is not None:
        settings = load_settings(args.settings)
        logging.info('Data uploaded')
    mode = (args.generation, args.encryption, args.decryption)
    match mode:
        case (True, False, False):
            logging.info('Generation keys\n')
            generate_key_pair(
                settings['secret_key'], settings['public_key'], settings['symmetric_key'])
            logging.info('Keys created')
        case (False, True, False):
            logging.info('Encryption\n')
            encrypt_data(settings['initial_file'], settings['secret_key'],
                         settings['symmetric_key'], settings['encrypted_file'])
            logging.info('The data has been encrypted')
        case (False, False, True):
            logging.info('Decryption\n')
            decrypt_data(settings['encrypted_file'], settings['secret_key'],
                         settings['symmetric_key'], settings['decrypted_file'])
            logging.info('The data has been decrypted')
        case _:
            logging.error("No valid mode selected")
    unload_settings('settings.json', settings)
