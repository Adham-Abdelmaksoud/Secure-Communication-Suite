from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
import secrets
from tinyec import registry
import os
from OpenSSL import crypto


class KeyManager:
    def __init__(self, key_store_dir, cert_store_dir):
        self.key_store_dir = key_store_dir
        self.cert_store_dir = cert_store_dir

    def generate_DES_session_key(self, key_size=8):
        return get_random_bytes(key_size)
    
    def generate_AES_session_key(self, key_size=32):
        return get_random_bytes(key_size)
    
    def generate_RSA_keys(self, key_size=2048):
        private_key = RSA.generate(key_size)
        public_key = private_key.public_key()
        return private_key, public_key
    
    def generate_ECC_keys(self, curve_name='brainpoolP256r1'):
        curve = registry.get_curve(curve_name)
        private_key = secrets.randbelow(curve.field.n)
        public_key = private_key * curve.g
        return private_key, public_key


    def store_DES_AES_key(self, key, key_name):
        with open(os.path.join(self.key_store_dir, key_name), 'wb') as f:
            f.write(key)
    
    def store_RSA_key(self, key, key_name):
        with open(os.path.join(self.key_store_dir, key_name), 'wb') as f:
            f.write(key.export_key())

    def store_ECC_priv_key(self, priv_key, key_name):
        with open(os.path.join(self.key_store_dir, key_name), 'wb') as f:
            f.write(priv_key.to_bytes(32, 'big'))

    def store_certificate(self, cert, cert_name):
        with open(os.path.join(self.cert_store_dir, cert_name), 'wt') as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode())


    def read_DES_AES_key(self, key_name):
        with open(os.path.join(self.key_store_dir, key_name), 'rb') as f:
            return f.read()
    
    def read_RSA_key(self, key_name):
        with open(os.path.join(self.key_store_dir, key_name), 'rb') as f:
            return RSA.import_key(f.read())

    def read_ECC_priv_key(self, key_name):
        with open(os.path.join(self.key_store_dir, key_name), 'rb') as f:
            return int.from_bytes(f.read(), 'big')
        
    def read_certificate(self, cert_name):
        with open(os.path.join(self.cert_store_dir, cert_name), 'r') as f:
            return crypto.load_certificate(crypto.FILETYPE_PEM, f.read())



if __name__ == '__main__':
    manager = KeyManager('./keys')
    priv_key, pub_key = manager.generate_ECC_keys()