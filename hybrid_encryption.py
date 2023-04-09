import argparse
import json
import logging
import os

from decrypt import decrypt_data
from encrypt import encrypt_data
from generate_key import generate_key_pair

SETTINGS_FILE = os.path.join('file', 'settings.json')
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
    args = parser.parse_args()
    try:
        with open(SETTINGS_FILE) as json_file:
            settings = json.load(json_file)
    except FileNotFoundError:
        logging.error(f"{SETTINGS_FILE} not found")
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
