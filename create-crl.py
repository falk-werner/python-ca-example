#!/usr/bin/env python3

import argparse
import datetime
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

def create_crl(crlfile, issuer_certfile, issuer_keyfile, certfile):
    with open(issuer_certfile, "rb") as f:
        issuer_cert = x509.load_pem_x509_certificate(f.read())
    with open(issuer_keyfile, "rb") as f:
        issuer_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(certfile, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    
    now = datetime.datetime.now(datetime.timezone.utc)

    builder = x509.RevokedCertificateBuilder()
    builder = builder.serial_number(cert.serial_number)
    builder = builder.revocation_date(now)
    revoked_cert = builder.build()

    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(issuer_cert.subject)
    builder = builder.last_update(now)
    builder = builder.next_update(now + datetime.timedelta(days=10))
    builder = builder.add_revoked_certificate(revoked_cert)
    crl = builder.sign(issuer_key, hashes.SHA256())

    with open(crlfile, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))

if __name__ == "__main__":
    parser = argparse.ArgumentParser("create-crl",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("filename", type=str, help="Path of generated CRL")
    parser.add_argument("--issuer", "-i", type=str, required=False, default="issuer.cert", help="Path of issuer's certficate")
    parser.add_argument("--key","-k", type=str, required=False, default="key.pem", help="Path of private key")    
    parser.add_argument("--cert", "-c", type=str, required=False, default="cert.pem", help="Path of certificate to revoke")
    args = parser.parse_args()

    create_crl(args.filename, args.issuer, args.key, args.cert)

