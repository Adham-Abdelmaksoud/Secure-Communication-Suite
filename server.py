from socket import *
import os
import pickle
import threading

from KeyManagement import KeyManager
from PublicKeyCryptosystemRSA import PublicKeyCryptosystemSigning
from Hashing import Hashing
from DiffieHelman import DiffieHelman
from PasswordAuth import PasswordAuth
from MessageThreads import *


SERVER_IP = ''
SERVER_PORT = 10000
    
def read_private_key(priv_key_dir='./Server', priv_key_name = 'private.key'):
    manager = KeyManager()
    return manager.read_RSA_key(priv_key_name, priv_key_dir)

def read_cert_bytes(cert_dir='./Server', cert_name = 'certificate.crt'):
    with open(os.path.join(cert_dir, cert_name), 'rb') as f:
        return f.read()
    

def init_server():
    server_sock = socket(AF_INET, SOCK_STREAM)
    server_sock.bind((SERVER_IP, SERVER_PORT))
    server_sock.listen()
    return server_sock
    
def start_connection(server_sock):
    print('listening to connections...')
    client_sock, client_addr = server_sock.accept()
    return client_sock

def close_connection(client_sock):
    client_sock.close()


def recv_security_params(client_sock):
    pickle_obj = client_sock.recv(4096)
    blockcipher_t, hashing_t = pickle.loads(pickle_obj)
    return blockcipher_t, hashing_t

def send_cert_dhPubKey_sign(client_sock, hashing_t):
    cert_bytes = read_cert_bytes()
    my_priv_key = read_private_key()

    # generate Diffie-Helman params & keys 
    manager = KeyManager()
    dh_params = manager.generate_DH_params()
    dh_server_priv_key, dh_server_pub_key = manager.generate_DH_keys(dh_params)
    # convert params & keys to bytes
    dh_params_bytes = manager.dhParams_2_bytes(dh_params)
    dh_server_pub_key_bytes = manager.dhPubKey_2_bytes(dh_server_pub_key)

    # form message signature
    signer = PublicKeyCryptosystemSigning(my_priv_key)
    all_bytes = cert_bytes + dh_params_bytes + dh_server_pub_key_bytes
    msg_sign = signer.sign(Hashing.hash(all_bytes, hashing_t))

    # send message
    client_sock.send(pickle.dumps([cert_bytes, dh_params_bytes, dh_server_pub_key_bytes, msg_sign]))

    return dh_server_priv_key


def recv_dhPubKey(client_sock, dh_server_priv_key, blockcipher_t):
    # receive message
    dh_client_pub_key_bytes = client_sock.recv(4096)

    # convert message bytes to public key
    manager = KeyManager()
    dh_client_pub_key = manager.bytes_2_dhPubKey(dh_client_pub_key_bytes)

    # calculate Diffie-Helman shared key
    dh = DiffieHelman(dh_server_priv_key, dh_client_pub_key)
    derived_key = dh.calculate_shared_key(blockcipher_t)

    return derived_key


def recv_username_password(client_sock, blockcipher_t, hashing_t):
    pickle_obj = client_sock.recv(4096)
    cipher_msg, msg_signature, nonce = pickle.loads(pickle_obj)

    all_data, my_hashed_msg, hashed_msg = decrypt_message(cipher_msg, msg_signature, nonce, derived_key, blockcipher_t, hashing_t)

    if(my_hashed_msg == hashed_msg):
        print('VALID MESSAGE!')
    else:
        print('TAMPERED MESSAGE!!!')

    username, password, login_signup = pickle.loads(all_data)

    auth = PasswordAuth()
    if login_signup == 1:
        status = auth.authenticate(username, password)
    elif login_signup == 2:
        status = auth.register(username, password)
    return status
    
    
        



if __name__ == '__main__':
    server_sock = init_server()

    while True:
        client_sock = start_connection(server_sock)

        blockcipher_t, hashing_t = recv_security_params(client_sock)
        dh_server_priv_key = send_cert_dhPubKey_sign(client_sock, hashing_t)
        derived_key = recv_dhPubKey(client_sock, dh_server_priv_key, blockcipher_t)
        status = recv_username_password(client_sock, blockcipher_t, hashing_t)
        
        client_sock.send(f'{status}'.encode())
        if not status:
            close_connection(client_sock)
            continue

        send_thread = threading.Thread(target=send_message_thread, args=(client_sock, derived_key, blockcipher_t, hashing_t,))
        recv_thread = threading.Thread(target=recv_message_thread, args=(client_sock, derived_key, blockcipher_t, hashing_t,))
        
        send_thread.start()
        recv_thread.start()

        recv_thread.join()
        send_thread.join()

        close_connection(client_sock)