from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes


class BlockCipherEncryption:
    def __init__(self, cipher, key):
        self.cipher = cipher.new(key, cipher.MODE_EAX)

    def get_nonce(self):
        return self.cipher.nonce

    def encrypt(self, plaintext):
        ciphertext = self.cipher.encrypt(plaintext)
        return ciphertext
    

class BlockCipherDecyption:
    def __init__(self, cipher, key, nonce):
        self.cipher = cipher.new(key, cipher.MODE_EAX, nonce)

    def decrypt(self, ciphertext):
        plaintext = self.cipher.decrypt(ciphertext)
        return plaintext


if __name__ == '__main__':
    CIPHER = DES
    KEY_SIZE = 8

    key = get_random_bytes(KEY_SIZE)
    encryption = BlockCipherEncryption(CIPHER, key)
    with open('inputs/Skeleton.py', 'rb') as f:
        plaintext = f.read()
    
    ciphertext = encryption.encrypt(plaintext)
    with open('outputs/ciphertext.txt', 'wb') as f:
        f.write(ciphertext)

    decryption = BlockCipherDecyption(CIPHER, key, encryption.get_nonce())
    plaintext = decryption.decrypt(ciphertext)
    with open('outputs/plaintext.py', 'wb') as f:
        f.write(plaintext)