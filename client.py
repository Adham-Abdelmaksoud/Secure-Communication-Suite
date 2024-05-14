from socket import *
import pickle
import threading
import sys

from BlockCipher import BlockCipherType
from PublicKeyCryptosystemRSA import PublicKeyCryptosystemVerification
from Hashing import Hashing, HashingType
from KeyManagement import KeyManager
from DiffieHelman import DiffieHelman
from CertificateVerification import CertificateVerifier
from MessageThreads import *


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
    server_cert = manager.bytes_2_cert(cert_bytes)
    cert_server_pub_key = server_cert.get_pubkey()
    RSA_server_pub_key = manager.bytes_2_RSAKey(manager.certKey_2_bytes(cert_server_pub_key))
    dh_params = manager.bytes_2_dhParams(dh_params_bytes)
    dh_server_pub_key = manager.bytes_2_dhPubKey(dh_server_pub_key_bytes)

    # calculate Diffie-Helman shared key
    dh_client_priv_key, dh_client_pub_key = manager.generate_DH_keys(dh_params)
    dh = DiffieHelman(dh_client_priv_key, dh_server_pub_key)
    derived_key = dh.calculate_shared_key(blockcipher_t)

    # verify server certificate
    cert_verifier = CertificateVerifier()
    print('Certificate Verified:', cert_verifier.verify_certificate(server_cert))
    
    # verify server signature
    sign_verifier = PublicKeyCryptosystemVerification(RSA_server_pub_key)
    all_bytes = cert_bytes + dh_params_bytes + dh_server_pub_key_bytes
    print('Signature Verified:', sign_verifier.verify(Hashing.hash(all_bytes, hashing_t), msg_sign))

    return dh_client_pub_key, derived_key


def send_username_password(client_sock, blockcipher_t, hashing_t):
    print('(1) Login')
    print('(2) Signup')
    login_signup = int(input('Enter the number corresponding to the desired action: '))
    username = input('Enter your username: ')
    password = input('Enter your password: ')

    all_data = pickle.dumps([username, password, login_signup])
    cipher_msg, msg_signature, nonce = encrypt_message(all_data, derived_key, blockcipher_t, hashing_t)

    client_sock.send(pickle.dumps([cipher_msg, msg_signature, nonce]))


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
    send_username_password(client_sock, blockcipher_t, hashing_t)

    status = client_sock.recv(4096)
    status = eval(status.decode())
    if status:
        print('Successful Operation')
    else:
        print('Unsuccessful Operation')
        close_connection(client_sock)
        sys.exit(0)
    
    send_thread = threading.Thread(target=send_message_thread, args=(client_sock, derived_key, blockcipher_t, hashing_t,))
    recv_thread = threading.Thread(target=recv_message_thread, args=(client_sock, derived_key, blockcipher_t, hashing_t,))
    send_thread.start()
    recv_thread.start()

    send_thread.join()
    recv_thread.join()

    close_connection(client_sock)