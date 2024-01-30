#!/usr/bin/env python3

import argparse

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID

class Name:
    def __init__(self, country, state, locality, organization, common_name):
        self.country = country
        self.state = state
        self.locality = locality
        self.organization = organization
        self.common_name = common_name

def create_csr(keyfile, csrfile, name):
    key = ec.generate_private_key(ec.SECP256R1())
    with open(keyfile, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, name.country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, name.state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, name.locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, name.organization),
        x509.NameAttribute(NameOID.COMMON_NAME, name.common_name)
    ])

    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(subject)
    builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )
    csr = builder.sign(key, hashes.SHA256())

    with open(csrfile, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))



if __name__ == "__main__":
    parser = argparse.ArgumentParser("create-csr",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-k", "--key", type=str, required=False,
        default="key.pem", help="Path where to store private key")
    parser.add_argument("-c", "--csr", type=str, required=False,
        default="cert.csr", help="Path where to store certificate signing request")
    parser.add_argument("--country", type=str, required=False,
        default="DE", help="Code of the issuers country")
    parser.add_argument("--state", type=str, required=False,
        default="NRW", help="Name of the issuers state or provice")
    parser.add_argument("--locality", type=str, required=False,
        default="Minden", help="Name of the issuers locality")
    parser.add_argument("--organization", type=str, required=False,
        default="Sample CA", help="Name of the issuers organization")
    parser.add_argument("--common-name", type=str, required=False,
        default="Sample CA", help="Common name of the issuer")
    args = parser.parse_args()

    name = Name(args.country, args.state, args.locality,
        args.organization, args.common_name)

    create_csr(args.key, args.csr, name)