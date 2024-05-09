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
    

    def RSAKey_2_bytes(self, key):
        return key.export_key()
    
    def cert_2_bytes(self, cert):
        return crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    
    def certKey_2_bytes(self, pub_key):
        return crypto.dump_publickey(crypto.FILETYPE_PEM, pub_key)
    
    def bytes_2_RSAKey(self, key_bytes):
        return RSA.import_key(key_bytes)
    
    def bytes_2_cert(self, cert_bytes):
        return crypto.load_certificate(crypto.FILETYPE_PEM, cert_bytes)


    def store_DES_AES_key(self, key, key_name):
        with open(os.path.join(self.key_store_dir, key_name), 'wb') as f:
            f.write(key)
    
    def store_RSA_key(self, key, key_name):
        with open(os.path.join(self.key_store_dir, key_name), 'wb') as f:
            f.write(self.RSAKey_2_bytes(key))

    def store_ECC_priv_key(self, priv_key, key_name):
        with open(os.path.join(self.key_store_dir, key_name), 'wb') as f:
            f.write(priv_key.to_bytes(32, 'big'))

    def store_certificate(self, cert, cert_name):
        with open(os.path.join(self.cert_store_dir, cert_name), 'wt') as f:
            f.write(self.cert_2_bytes(cert).decode())


    def read_DES_AES_key(self, key_name):
        with open(os.path.join(self.key_store_dir, key_name), 'rb') as f:
            return f.read()
    
    def read_RSA_key(self, key_name):
        with open(os.path.join(self.key_store_dir, key_name), 'rb') as f:
            return self.bytes_2_RSAKey(f.read())

    def read_ECC_priv_key(self, key_name):
        with open(os.path.join(self.key_store_dir, key_name), 'rb') as f:
            return int.from_bytes(f.read(), 'big')
        
    def read_certificate(self, cert_name):
        with open(os.path.join(self.cert_store_dir, cert_name), 'r') as f:
            return self.bytes_2_cert(f.read())



if __name__ == '__main__':
    manager = KeyManager(None, None)
    priv_key, pub_key = manager.generate_ECC_keys()
    print(pub_key)