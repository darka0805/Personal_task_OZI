"""
sign_image.py

Цей скрипт виконує цифрове підписування зображення за допомогою приватного ключа RSA
та приховує підпис у зображенні за допомогою стеганографії (метод LSB).
"""
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from stegano import lsb


def sign_image(image_path, private_key_path, output_path):
    """
    Підписує зображення цифровим підписом і приховує його в зображенні за допомогою стеганографії.

    Parameters:
        image_path (str): Шлях до зображення, яке потрібно підписати.
        private_key_path (str): Шлях до приватного ключа (PEM-файл), використовується для підпису.
        output_path (str): Шлях для збереження нового зображення з вбудованим підписом.

    Returns:
        None
    """
    # Завантажуємо приватний ключ
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    # Зчитуємо наше початкове зображення
    with open(image_path, "rb") as img_file:
        image_data = img_file.read()

    # РахуЄМО SHA256 хеш
    digest = hashes.Hash(hashes.SHA256())
    digest.update(image_data)
    image_hash = digest.finalize()

    # Підписуємо хеш
    signature = private_key.sign(
        image_hash,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

    # Вбудовуємо підпис у зображення за допомогою LSB стеганографії
    secret_image = lsb.hide(image_path, signature.hex())
    secret_image.save(output_path)
    print("Зображення підписано та збережено:", output_path)

if __name__ == "__main__":
    INPUT_IMAGE = "./input_images/download.bmp"
    PRIVATE_KEY = "./keys/private_key.pem"
    OUTPUT_IMAGE = "./output_images/signed_bmp.png"

    sign_image(INPUT_IMAGE, PRIVATE_KEY, OUTPUT_IMAGE)
