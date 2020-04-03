import os

from Crypto.Hash import SHA256
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES


def generate_keys():
    random_generator = Random.new().read
    key = RSA.generate(1024, random_generator)
    return key, key.publickey()


def encrypt_key(key, user_password):
    # user_password = input("Insert password which will be used to protect a private key:")
    # user_password = "haslo123"
    user_password_byte_array = user_password.encode("utf8")
    hashed_user_password = SHA256.new(user_password_byte_array)  # create a hash of password set by user
    initialisation_vector = Random.new().read(AES.block_size)  # create initialisation vector
    cipher = AES.new(hashed_user_password.digest(), AES.MODE_CBC, initialisation_vector)
    length = 16 - (len(key) % 16)
    key += bytes([length]) * length
    encrypted_key = cipher.encrypt(key)
    return encrypted_key, initialisation_vector


def decrypt_key(encrypted_key, initialisation_vector, user_password):
    # password = input("Insert password protecting key:")
    # password = "haslo123"
    password_byte_array = user_password.encode("utf8")
    hashed_password = SHA256.new(password_byte_array)
    cipher_to_decrypt = AES.new(hashed_password.digest(), AES.MODE_CBC, initialisation_vector)
    decrypted_key = cipher_to_decrypt.decrypt(encrypted_key)
    decrypted_key = decrypted_key[:-decrypted_key[-1]]
    return decrypted_key


def save_public_key(key: RSA.RsaKey):
    filename = os.getcwd() + "/keys/public_key/public_key.txt"
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, "wb") as f:
        f.write(key.exportKey())
        f.close()


def save_private_key(key: RSA.RsaKey, password):
    filename = os.getcwd() + "/keys/private_key/private_key.txt"
    key, vector = encrypt_key(key.exportKey(), password)
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, "wb") as f:
        f.write(key)
        f.write(vector)
        f.close()


def read_public_key():
    filename = "/keys/public_key/public_key.txt"
    with open(os.getcwd() + filename, "rb") as f:
        content = f.read()
        f.close()
        return RSA.import_key(content)


def read_private_key(password):
    filename = "/keys/private_key/private_key.txt"
    with open(os.getcwd() + filename, "rb") as f:
        content = f.read()
        key = content[:-16]
        vector = content[-16:]
        f.close()
    try:
        key = decrypt_key(key, vector, password)
        return RSA.import_key(key)
    except ValueError:
        random_generator = Random.new().read
        return RSA.generate(1024, random_generator)
