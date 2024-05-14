from datetime import datetime
from OpenSSL import crypto

def client_verification(cert, ca_cert):
    cert_expiry = datetime.strptime(str(cert.get_notAfter(), 'utf-8'),"%Y%m%d%H%M%SZ")
    now = datetime.now()
    validity = (cert_expiry - now).days
    if validity <= 0:
        return False

    store = crypto.X509Store()
    store.add_cert(ca_cert)
    store_ctx = crypto.X509StoreContext(store, cert)
    try:
        store_ctx.verify_certificate()
        return True
    except:
        return False
    


if __name__ == '__main__':
    from KeyManagement import KeyManager

    manager = KeyManager()
    client_cert = manager.read_certificate('certificate.crt', './Client')
    ca_cert = manager.read_certificate('ca_certificate.crt', './CA')

    print(client_verification(client_cert, ca_cert))