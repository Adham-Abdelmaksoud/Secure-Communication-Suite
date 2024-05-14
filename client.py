from socket import *
import pickle

from BlockCipher import BlockCipherEncryption, BlockCipherType, BlockCipherKeySize
from PublicKeyCryptosystemRSA import PublicKeyCryptosystemVerification
from Hashing import Hashing, HashingType
from KeyManagement import KeyManager
from DiffieHelman import DiffieHelman


SERVER_IP = '127.0.0.1'
SERVER_PORT = 10000

def start_connection():
    client_sock = socket(AF_INET, SOCK_STREAM)
    client_sock.connect((SERVER_IP, SERVER_PORT))
    return client_sock

def close_connection(client_sock):
    client_sock.close()


def send_security_params(client_sock, blockcipher_t=BlockCipherType.AES, hashing_t=HashingType.SHA256):
    client_sock.send(pickle.dumps([blockcipher_t, hashing_t]))

def recv_cert_dhPubKey_sign(client_sock, blockcipher_t, hashing_t):
    # receive message
    pickle_obj = client_sock.recv(4096)
    cert_bytes, dh_params_bytes, dh_server_pub_key_bytes, msg_sign = pickle.loads(pickle_obj)

    # convert message bytes to objects
    manager = KeyManager()
    cert = manager.bytes_2_cert(cert_bytes)
    cert_server_pub_key = cert.get_pubkey()
    RSA_server_pub_key = manager.bytes_2_RSAKey(manager.certKey_2_bytes(cert_server_pub_key))
    dh_params = manager.bytes_2_dhParams(dh_params_bytes)
    dh_server_pub_key = manager.bytes_2_dhPubKey(dh_server_pub_key_bytes)

    # calculate Diffie-Helman shared key
    dh_client_priv_key, dh_client_pub_key = manager.generate_DH_keys(dh_params)
    dh = DiffieHelman(dh_client_priv_key, dh_server_pub_key)
    derived_key = dh.calculate_shared_key(blockcipher_t)
    print(derived_key)
    
    # verify server signature
    verifier = PublicKeyCryptosystemVerification(RSA_server_pub_key)
    all_bytes = cert_bytes + dh_params_bytes + dh_server_pub_key_bytes
    print(verifier.verify(Hashing.hash(all_bytes, hashing_t), msg_sign))

    return dh_client_pub_key, derived_key


def send_dhPubKey(client_sock, dh_client_pub_key):
    # convert objects to bytes
    manager = KeyManager()
    dh_client_pub_key_bytes = manager.dhPubKey_2_bytes(dh_client_pub_key)

    # send message
    client_sock.send(pickle.dumps(dh_client_pub_key_bytes))




        
        




if __name__ == '__main__':
    client_sock = start_connection()

    blockcipher_t = BlockCipherType.AES
    hashing_t = HashingType.SHA256

    send_security_params(client_sock, blockcipher_t, hashing_t)
    dh_client_pub_key, derived_key = recv_cert_dhPubKey_sign(client_sock, blockcipher_t, hashing_t)
    send_dhPubKey(client_sock, dh_client_pub_key)

    close_connection(client_sock)