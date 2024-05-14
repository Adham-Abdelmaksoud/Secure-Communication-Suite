from datetime import datetime
from OpenSSL import crypto

from KeyManagement import KeyManager

class CertificateVerifier:
    def __init__(self) -> None:
        manager = KeyManager()
        self.ca_cert = manager.read_certificate('ca_certificate.crt', './CA')
        self.store = crypto.X509Store()
        self.store.add_cert(self.ca_cert)
    
    def verify_certificate(self, cert):
        cert_expiry = datetime.strptime(str(cert.get_notAfter(), 'utf-8'),"%Y%m%d%H%M%SZ")
        now = datetime.now()
        validity = (cert_expiry - now).days
        if validity <= 0:
            return False

        store_ctx = crypto.X509StoreContext(self.store, cert)
        try:
            store_ctx.verify_certificate()
            return True
        except:
            return False
    


if __name__ == '__main__':
    from KeyManagement import KeyManager

    manager = KeyManager()
    client_cert = manager.read_certificate('certificate.crt', './Client')

    verifier = CertificateVerifier()
    print(verifier.verify_certificate(client_cert))