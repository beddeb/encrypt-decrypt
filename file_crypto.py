import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import argparse


def generate_key(password: str, salt: bytes = None) -> tuple:
    if salt is None:
        salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt


def encrypt_file(input_file: str, output_file: str, password: str):
    salt = os.urandom(16)
    key, salt = generate_key(password, salt)
    fernet = Fernet(key)

    with open(input_file, 'rb') as f:
        data = f.read()

    encrypted = fernet.encrypt(data)

    with open(output_file, 'wb') as f:
        f.write(salt + encrypted)  # Сохраняем соль вместе с данными


def decrypt_file(input_file: str, output_file: str, password: str):
    with open(input_file, 'rb') as f:
        salt = f.read(16)  # Читаем соль
        encrypted_data = f.read()

    key, _ = generate_key(password, salt)
    fernet = Fernet(key)

    try:
        decrypted = fernet.decrypt(encrypted_data)
    except:
        print("Ошибка: неверный пароль или повреждённый файл")
        return False

    with open(output_file, 'wb') as f:
        f.write(decrypted)
    return True


def main():
    parser = argparse.ArgumentParser(description='Утилита для шифрования файлов')
    parser.add_argument('action', choices=['encrypt', 'decrypt'], help='Режим работы')
    parser.add_argument('input_file', help='Входной файл')
    parser.add_argument('output_file', help='Выходной файл')
    parser.add_argument('-p', '--password', help='Пароль (если не указан, будет запрошен)')

    args = parser.parse_args()

    password = args.password or input("Введите пароль: ")

    if args.action == 'encrypt':
        encrypt_file(args.input_file, args.output_file, password)
        print(f"Файл {args.input_file} успешно зашифрован в {args.output_file}")
    else:
        if decrypt_file(args.input_file, args.output_file, password):
            print(f"Файл {args.input_file} успешно расшифрован в {args.output_file}")


if __name__ == "__main__":
    main()
