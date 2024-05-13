from socket import *
import os
import pickle

from KeyManagement import KeyManager
from PublicKeyCryptosystemRSA import PublicKeyCryptosystemSigning
from Hashing import Hashing, HashingType
from BlockCipher import BlockCipherType
from DiffieHelman import DiffieHelman

SERVER_IP = ''
SERVER_PORT = 10000
    
def read_private_key(priv_key_dir='./Server', priv_key_name = 'private.key'):
    manager = KeyManager(priv_key_dir, priv_key_dir)
    return manager.read_RSA_key(priv_key_name)

def read_cert_bytes(cert_dir='./Server', cert_name = 'certificate.crt'):
    with open(os.path.join(cert_dir, cert_name), 'rb') as f:
        return f.read()
    

def init_server():
    server_sock = socket(AF_INET, SOCK_STREAM)
    server_sock.bind((SERVER_IP, SERVER_PORT))
    print('listening to connections...')
    server_sock.listen()
    return server_sock
    
def start_connection(server_sock):
    client_sock, client_addr = server_sock.accept()
    return client_sock

def close_connection(client_sock):
    client_sock.close()

def recv_security_params(client_sock):
    pickle_obj = client_sock.recv(4096)
    blockcipher_t, hashing_t = pickle.loads(pickle_obj)
    return blockcipher_t, hashing_t

def send_cert_dhKey_sign(client_sock, blockcipher_t, hashing_t):
    cert_bytes = read_cert_bytes()
    my_priv_key = read_private_key()
    signer = PublicKeyCryptosystemSigning(my_priv_key)
    cert_sign = signer.sign(Hashing.hash(cert_bytes, hashing_t))

    manager = KeyManager(None, None)
    dh_params = manager.generate_DH_params()
    dh_server_priv_key, dh_server_pub_key = manager.generate_DH_keys(dh_params)
    dh_params_bytes = manager.dhParams_2_bytes(dh_params)
    dh_server_pub_key_bytes = manager.dhPubKey_2_bytes(dh_server_pub_key)

    client_sock.send(pickle.dumps([cert_bytes, cert_sign, dh_params_bytes, dh_server_pub_key_bytes]))

    return dh_server_priv_key


def recv_dh_client_pub_key(client_sock, dh_server_priv_key):
    dh_client_pub_key_bytes = client_sock.recv(4096)

    manager = KeyManager(None, None)
    dh_client_pub_key = manager.bytes_2_dhPubKey(dh_client_pub_key_bytes)

    dh = DiffieHelman(dh_server_priv_key, dh_client_pub_key)
    derived_key = dh.calculate_shared_key()
    print(derived_key)



if __name__ == '__main__':
    server_sock = init_server()

    while True:
        client_sock = start_connection(server_sock)

        dh_server_priv_key = send_cert_dhKey_sign(client_sock, BlockCipherType.AES, HashingType.SHA256)
        recv_dh_client_pub_key(client_sock, dh_server_priv_key)

        close_connection(client_sock)