from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac

def generate_key_with_salt_and_iv(password, salt_length=16):
    # ソルトを生成
    salt = os.urandom(salt_length)

    # PBKDF2を使ってパスワードとソルトから鍵を導出
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32バイトの鍵を使用
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)

    # 初期化ベクトル (IV) を生成
    iv = os.urandom(12)  # 12バイト (96ビット) のIVを使用

    return salt, iv, key

password = b"パスワード"
salt, iv, key = generate_key_with_salt_and_iv(password)

# AES-GCM暗号器を初期化
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
encryptor = cipher.encryptor()

# データを暗号化
data = b"秘密のメッセージ"
ciphertext = encryptor.update(data) + encryptor.finalize()

# タグを取得
tag = encryptor.tag

# 復号化のためにAES-GCM暗号器を初期化
decryptor = cipher.decryptor()

# 復号化とタグの検証
decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

print("元のデータ:", data)
print("暗号化されたデータ:", ciphertext)
print("復号化されたデータ:", decrypted_data)
