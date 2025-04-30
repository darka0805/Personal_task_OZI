"""
verify_signature.py

Цей скрипт перевіряє цифровий підпис, вбудований у зображення, використовуючи публічний ключ RSA.
Підпис витягується зі зображення за допомогою стеганографії (метод LSB) та звіряється з хешем
оригінального зображення.
"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from stegano import lsb


def verify_image_signature(image_path, public_key_path, original_image_path):
    """
    Перевіряє цифровий підпис, захований у зображенні, використовуючи публічний ключ.

    Parameters:
        image_path (str): Шлях до зображення з вбудованим підписом.
        public_key_path (str): Шлях до публічного ключа (PEM-файл).
        original_image_path (str): Шлях до оригінального зображення для перевірки.

    Returns:
        bool: True, якщо підпис дійсний, False інакше.
    """
    # Завантажуємо публічний ключ
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    # Отримуємо прихований підпис
    hidden_signature_hex = lsb.reveal(image_path)
    if hidden_signature_hex is None:
        print("Підпис не знайдено!")
        return False

    signature = bytes.fromhex(hidden_signature_hex)

    # Зчитуємо оригінальні дані зображення
    with open(original_image_path, "rb") as img_file:
        image_data = img_file.read()

    # Обчислюємо SHA256 хеш
    digest = hashes.Hash(hashes.SHA256())
    digest.update(image_data)
    image_hash = digest.finalize()

    # Перевіряємо підпис
    try:
        public_key.verify(
            signature,
            image_hash,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        print("Підпис дійсний.")
        return True
    except InvalidSignature:
        print("Підпис недійсний: недійсний підпис")
        return False
    except ValueError as err:
        print("Помилка перевірки: невірні дані або формат ключа:", err)
        return False


if __name__ == "__main__":
    SIGNED_IMAGE = "./output_images/signed_bmp.png"
    PUBLIC_KEY = "./keys/public_key.pem"
    ORIGINAL_IMAGE = "./input_images/download.bmp"

    verify_image_signature(SIGNED_IMAGE, PUBLIC_KEY, ORIGINAL_IMAGE)
