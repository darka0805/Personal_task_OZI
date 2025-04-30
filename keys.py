"""
keys.py

Цей модуль генерує приватний та публічний RSA ключі та зберігає їх у файли.

Приватний ключ зберігається у форматі PEM без шифрування, а публічний ключ
створюється на основі приватного ключа та зберігається також у форматі PEM.
Ключі зберігаються в каталозі './keys'.

Згенеровані ключі:
- private_key.pem
- public_key.pem
"""
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Генерація приватного ключа RSA
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
)

# Збереження приватного ключа в файл
with open("./keys/private_key.pem", "wb") as private_key_file:
    private_key_file.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

# Генерація публічного ключа з приватного
public_key = private_key.public_key()

# Збереження публічного ключа в файл
with open("./keys/public_key.pem", "wb") as public_key_file:
    public_key_file.write(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

print("Ключі були успішно згенеровані і збережені в файли.")
