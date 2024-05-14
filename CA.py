import random
import os
from OpenSSL import crypto
from CertificateVerification import CertificateVerifier


def create_CA(root_ca_path, public_key_path, private_key_path):
    with open(private_key_path, 'rb') as f:
        ca_private_key = crypto.load_privatekey(crypto.FILETYPE_PEM,f.read())
    with open(public_key_path, 'rb') as f:
        ca_public_key = crypto.load_publickey(crypto.FILETYPE_PEM,f.read())

    ca_cert = crypto.X509()
    ca_cert.set_version(2)
    ca_cert.set_serial_number(random.randint(50000000, 100000000))

    ca_subj = ca_cert.get_subject()
    ca_subj.countryName = input("Country Name (2 letter code) [XX]: ")
    ca_subj.stateOrProvinceName = input("State or Province Name (full name) []: ")
    ca_subj.localityName = input("Locality Name (eg, city) [Default City]: ")
    ca_subj.organizationName = input("Organization Name (eg, company) [Default Company Ltd]: ")
    ca_subj.organizationalUnitName = input("Organizational Unit Name (eg, section) []: ")
    ca_subj.commonName = input("Common Name (eg, your name or your server's hostname) []: ")
    ca_subj.emailAddress = input("Email Address []: ")
    
    ca_cert.set_issuer(ca_subj)
    ca_cert.set_pubkey(ca_public_key)

    ca_cert.add_extensions([
        crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca_cert),
    ])

    ca_cert.add_extensions([
        crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always,issuer", issuer=ca_cert),
    ])

    ca_cert.add_extensions([
        crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE"),
    ])

    ca_cert.gmtime_adj_notBefore(0)
    ca_cert.gmtime_adj_notAfter(10*365*24*60*60)

    ca_cert.sign(ca_private_key, 'sha256')

    with open(root_ca_path, "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert).decode("utf-8"))
        
        
def load_CA(root_ca_path, private_key_path):
    with open(root_ca_path, "r") as f:
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
    with open(private_key_path, "r") as f:
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())
    return ca_cert, ca_key
    
            
def create_cert(ca_cert, ca_subj, ca_key, client_cn, client_email, client_public_key):
    client_cert = crypto.X509()
    client_cert.set_version(2)
    client_cert.set_serial_number(random.randint(50000000, 100000000))

    client_subj = client_cert.get_subject()
    client_subj.commonName = client_cn
    client_subj.emailAddress = client_email
    
    client_cert.set_issuer(ca_subj)
    client_cert.set_pubkey(client_public_key)

    client_cert.add_extensions([
        crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
    ])

    client_cert.add_extensions([
        crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid", issuer=ca_cert),
        crypto.X509Extension(b"keyUsage", True, b"digitalSignature, keyEncipherment"),
    ])

    client_cert.add_extensions([
        crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=client_cert),
    ])
    
    client_cert.gmtime_adj_notBefore(0)
    client_cert.gmtime_adj_notAfter(365*24*60*60)

    client_cert.sign(ca_key, 'sha256')

    return client_cert
    

        
# def main():

#     # with open('CA/ca_private.key', 'rb') as f:
#     #     private_key = crypto.load_privatekey(crypto.FILETYPE_PEM,f.read())
#     # with open('CA/ca_public.key', 'rb') as f:
#     #     public_key = crypto.load_publickey(crypto.FILETYPE_PEM,f.read())

#     private_key_path = "CA/ca_private.key"
#     public_key_path = "CA/ca_public.key"
#     root_ca_path = "CA/ca_certificate.crt"
    
#     if not os.path.exists('CA'):
#         print ("Creating CA driectory")
#         os.makedirs('CA')
        
#     if not os.path.exists(root_ca_path):
#         print ("Creating CA Certificate, Please provide the values")
#         create_CA(root_ca_path, public_key_path, private_key_path)
#         print ("Created CA Certificate")
#         ca_cert, ca_key = load_CA(root_ca_path, private_key_path)
#         CA_verification(ca_cert)
#     else:
#         print ("CA certificate has been found as {}".format(root_ca_path))
#         ca_cert, ca_key = load_CA(root_ca_path, private_key_path)
#         CA_verification(ca_cert)
    
#     client_cn = "Mohamed Ayman"
#     client_email = "mohameddallash21@gmail.com"
    
#     with open("public.txt",'rb') as f:
#         client_public_key = crypto.load_publickey(crypto.FILETYPE_PEM,f.read())
            
#     # subject = ca_cert.get_subject()
#     # client_cert = create_cert(ca_cert, subject, ca_key, client_cn, client_email, client_public_key)
#     # with open(client_cn + ".crt", "wt") as f:
#     #     f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, client_cert).decode("utf-8"))

#     with open(client_cn + ".crt", "r") as f:
#         cer = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
#         store = crypto.X509Store()
#         store.add_cert(ca_cert)
#         sub = cer.get_subject()
#         sub.emailAddress = "someotheremail@gmail.com"
#         cer.set_subject(sub)
#         store_ctx = crypto.X509StoreContext(store,cer)
#         store_ctx.verify_certificate()
#         # crypto.verify(cer,cer.)
#         # req = crypto.load_certificate_request(crypto.FILETYPE_PEM, f.read().decode("utf-8"))
#         # print(req.verify(cer.get_pubkey()))
    
# if __name__ == "__main__":
#     main()