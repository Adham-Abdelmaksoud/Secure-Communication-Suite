from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

key = RSA.generate(1024)
private_key = key
public_key = key.public_key()


msg = b"Hello, this is a message to be encrypted"
cipher_rsa = PKCS1_OAEP.new(public_key)

encrypted_msg = cipher_rsa.encrypt(msg)

print('Encrypted: ', encrypted_msg)

cipher_rsa = PKCS1_OAEP.new(private_key)
decrypted_msg = cipher_rsa.decrypt(encrypted_msg)

print("Decrypted: ", decrypted_msg.decode())
