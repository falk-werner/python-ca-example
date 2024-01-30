#!/usr/bin/env python3

import argparse
import datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

def sign_csr(certfile, csrfile, issuer_certfile, issuer_keyfile, days_valid):
    with open(csrfile, "rb") as f:
        csr = x509.load_pem_x509_csr(f.read())
    with open(issuer_certfile, "rb") as f:
        issuer_cert = x509.load_pem_x509_certificate(f.read())
    with open(issuer_keyfile, "rb") as f:
        issuer_key = serialization.load_pem_private_key(f.read(), password=None)
    
    now = datetime.datetime.now(datetime.timezone.utc)

    builder = x509.CertificateBuilder()
    builder = builder.issuer_name(issuer_cert.subject)
    builder = builder.subject_name(csr.subject)
    builder = builder.public_key(csr.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + datetime.timedelta(days=days_valid))
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )
    cert  = builder.sign(issuer_key, hashes.SHA256())

    with open(certfile, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

if __name__ == "__main__":
    parser = argparse.ArgumentParser("sign-csr",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("filename", type=str, help="Path of generated certificate")
    parser.add_argument("--issuer", "-i", type=str, required=False, default="issuer.cert", help="Path of issuer's certficate")
    parser.add_argument("--key","-k", type=str, required=False, default="key.pem", help="Path of private key")    
    parser.add_argument("--csr", "-c", type=str, required=False, default="csr.pem", help="Path of CSR file")
    parser.add_argument("--days-valid","-d", type=int, required=False, default=10, help="Number of days the certificate is valid")
    args = parser.parse_args()

    sign_csr(args.filename, args.csr, args.issuer, args.key, args.days_valid)
