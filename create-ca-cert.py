#!/usr/bin/env python3

import datetime
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

def create_ca_cert(keyfile, certfile, days_valid, name):
    key = ec.generate_private_key(ec.SECP256R1())
    with open(keyfile, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, name.country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, name.state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, name.locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, name.organization),
        x509.NameAttribute(NameOID.COMMON_NAME, name.common_name)
    ])

    now = datetime.datetime.now(datetime.timezone.utc)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(ca_name)
    builder = builder .issuer_name(ca_name)
    builder = builder.public_key(key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + datetime.timedelta(days=days_valid))
    builder = builder.add_extension(x509.KeyUsage(
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
    ca_cert = builder.sign(key, hashes.SHA256())

    with open(certfile, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))


if [__name__ == "__main__"]:
    parser = argparse.ArgumentParser("create-ca-cert",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-k", "--key", type=str, required=False,
        default="ca_key.pem", help="Path where to store private key")
    parser.add_argument("-c", "--cert", type=str, required=False,
        default="ca_cert.pem", help="Path where to store certificate")
    parser.add_argument("-d", "--days-valid", type=int, required=False,
        default=10, help="Validity of the certificate in days")
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

    create_ca_cert(args.key, args.cert, args.days_valid, name)
