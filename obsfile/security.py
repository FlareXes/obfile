from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import scrypt
from Cryptodome.Random import get_random_bytes


def encrypt(data, key):
    random_bytes = get_random_bytes(32).__str__()
    private_key = scrypt(key, random_bytes, 32, 2 ** 14, 8, 1)

    cipher = AES.new(private_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    configs = {'salt': random_bytes, 'ciphertext': ciphertext, 'nonce': cipher.nonce, 'tag': tag}
    return configs


def decrypt(configs, key):
    random_bytes = get_random_bytes(32).__str__()
    random_bytes = configs['salt']
    ciphertext = configs['ciphertext']
    nonce = configs['nonce']
    tag = configs['tag']

    private_key = scrypt(key, random_bytes, 32, 2 ** 14, 8, 1)
    cipher = AES.new(private_key, AES.MODE_GCM, nonce)

    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data
