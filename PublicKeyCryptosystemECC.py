from typing import Any
from tinyec import registry
from Crypto.Cipher import AES
import hashlib, secrets, binascii
from ecdsa import SigningKey, keys
from BlockCipher import BlockCipherEncryption, BlockCipherType, BlockCipherDecyption

class EncryptionECC():
    def __init__(self) -> None:
        self.curve = registry.get_curve('brainpoolP256r1')
    
    def encrypt_AES(self, message, secretKey):
        aesCipher = BlockCipherEncryption(BlockCipherType.AES,secretKey)
        ciphertext = aesCipher.encrypt(message)
        return ciphertext, aesCipher.get_nonce()

    def decrypt_AES(self, ciphertext, nonce, secret_key):
        aesCipher = BlockCipherDecyption(BlockCipherType.AES,secret_key, nonce)
        plaintext = aesCipher.decrypt(ciphertext)
        return plaintext

    def encrypt(self, msg, pubKey):
        ciphertextPrivKey = secrets.randbelow(self.curve.field.n)
        sharedECCKey = ciphertextPrivKey * pubKey
        secretKey = self.ecc_point_to_256_bit_key(sharedECCKey)
        ciphertext, nonce = self.encrypt_AES(msg, secretKey)
        ciphertextPubKey = ciphertextPrivKey * self.curve.g
        return (ciphertext, nonce, ciphertextPubKey)
    
    def decrypt(self, encryptedMsg, privKey):
        (ciphertext, nonce, ciphertextPubKey) = encryptedMsg
        sharedECCKey = privKey * ciphertextPubKey
        secretKey = self.ecc_point_to_256_bit_key(sharedECCKey)
        plaintext = self.decrypt_AES(ciphertext, nonce, secretKey)
        return plaintext

    def ecc_point_to_256_bit_key(self, point):
        sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
        sha.update(int.to_bytes(point.y, 32, 'big'))
        return sha.digest()
    
    def generate_keys(self):
        privKey = secrets.randbelow(self.curve.field.n)
        pubKey = privKey * self.curve.g
        return privKey, pubKey
    

class SigningECC:
    @staticmethod
    def generate_keys():
        private_key = SigningKey.generate() # uses NIST192p
        public_key = private_key.verifying_key
        return private_key, public_key
    
    @staticmethod
    def sign(hash, private_key: SigningKey):
        return private_key.sign(hash)
    
    @staticmethod
    def verify(hash, signed_hash, public_key):
        try:
            public_key.verify(signed_hash,hash)
            return True
        except keys.BadSignatureError:
            return False
    

if __name__ == '__main__':
    msg = b'Text to be encrypted by ECC public key and ' \
        b'decrypted by its corresponding ECC private key'
    print("original msg:", msg)

    ecc = EncryptionECC()

    privKey, pubKey = ecc.generate_keys()

    encryptedMsg = ecc.encrypt(msg, pubKey)
    encryptedMsgObj = {
        'ciphertext': binascii.hexlify(encryptedMsg[0]),
        'nonce': binascii.hexlify(encryptedMsg[1]),
        'ciphertextPubKey': hex(encryptedMsg[2].x) + hex(encryptedMsg[2].y % 2)[2:]
    }
    print("encrypted msg:", encryptedMsgObj)

    decryptedMsg = ecc.decrypt(encryptedMsg, privKey)
    print("decrypted msg:", decryptedMsg)

    signing_priv_key, signing_pub_key = SigningECC.generate_keys()
    msg = b"This is a message to sign"
    signed = SigningECC.sign(msg,signing_priv_key)
    
    if SigningECC.verify(b"This is a message to sign",signed,signing_pub_key):
        print("Message verified")
    else:
        print("The message is not verified")
