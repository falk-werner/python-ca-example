#!/usr/bin/env python3

import datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

def save_key(key, filename):
    with open(filename, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

def sign_csr(csr, ca, ca_private_key):
    now = datetime.datetime.now(datetime.timezone.utc)

    cert = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        ca.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now
    ).not_valid_after(
        now + datetime.timedelta(days=10)
    ).add_extension(
        x509.BasicConstraints(ca=True,path_length=None),
        critical=True
    ).add_extension(
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
    ).sign(ca_private_key, hashes.SHA256())

    return cert


##########################
# 1) Generate Root CA
##########################

#------------------------
# 1.1) Create Private Key
#------------------------

root_ca_key = ec.generate_private_key(ec.SECP256R1())
save_key(root_ca_key, "root-ca_private-key.pem")

#------------------------
# 1.2) Create Self-Signed Cert
#------------------------

root_ca_name = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "NRW"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Minden"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Root CA"),
    x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")
])

now = datetime.datetime.now(datetime.timezone.utc)

root_ca_cert = x509.CertificateBuilder().subject_name(
        root_ca_name
    ).issuer_name(
        root_ca_name
    ).public_key(
        root_ca_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now
    ).not_valid_after(
        now + datetime.timedelta(days=10)
    ).add_extension(
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
    ).sign(root_ca_key, hashes.SHA256())

with open("root-ca_cert.pem", "wb") as f:
    f.write(root_ca_cert.public_bytes(serialization.Encoding.PEM))

# openssl x509 -text -in root-ca_cert.pem

##########################
# 2) Generate Signing CA
##########################

#------------------------
# 2.1) Create Private Key
#------------------------

signing_ca_key = ec.generate_private_key(ec.SECP256R1())
save_key(signing_ca_key, "signing-ca_private-key.pem")

#------------------------
# 2.2) Create CSR
#------------------------

signing_ca_csr = x509.CertificateSigningRequestBuilder().subject_name(
    x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "NRW"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Minden"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Signing CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Signing CA")
    ])).add_extension(
        x509.BasicConstraints(ca=True,path_length=None),
        critical=True
    ).add_extension(
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
    ).sign(signing_ca_key, hashes.SHA256())

with open("signing-ca.csr", "wb") as f:
    f.write(signing_ca_csr.public_bytes(serialization.Encoding.PEM))

# openssl req -text -in signing-ca.csr


#------------------------
# 2.3) Sign CSR
#------------------------

signing_ca_cert = x509.CertificateBuilder().subject_name(
        signing_ca_csr.subject
    ).issuer_name(
        root_ca_cert.subject
    ).public_key(
        signing_ca_csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now
    ).not_valid_after(
        now + datetime.timedelta(days=10)
    ).add_extension(
        x509.BasicConstraints(ca=True,path_length=None),
        critical=True
    ).add_extension(
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
    ).sign(root_ca_key, hashes.SHA256())

with open("signing-ca.pem", "wb") as f:
    f.write(signing_ca_cert.public_bytes(serialization.Encoding.PEM))

# openssl x509 -text -in signing-ca.pem
# openssl verify -verbose -CAfile root-ca_cert.pem signing-ca.pem 

##########################
# 3) Sign Certificate
##########################

#------------------------
# 3.1) Create Private Key
#------------------------

key = ec.generate_private_key(ec.SECP256R1())
save_key(key, "cert-key.pem")

#------------------------
# 3.2) Create CSR
#------------------------

csr = x509.CertificateSigningRequestBuilder().subject_name(
    x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "NRW"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Minden"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Some Cert"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Some Cert")
    ])).add_extension(
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
    ).sign(key, hashes.SHA256())

with open("cert.csr", "wb") as f:
    f.write(csr.public_bytes(serialization.Encoding.PEM))

# openssl req -text -in signing-ca.csr

#------------------------
# 3.3) Sign CSR
#------------------------

cert = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        signing_ca_cert.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now
    ).not_valid_after(
        now + datetime.timedelta(days=10)
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=True,
            key_encipherment=True,
            data_encipherment=True,
            key_agreement=True,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    ).add_extension(
        x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH,
            ExtendedKeyUsageOID.CLIENT_AUTH           
        ]),
        critical=True
    ).add_extension(
        x509.CRLDistributionPoints([x509.DistributionPoint(
            full_name=[x509.DNSName("wago.com")],
            relative_name=None,
            crl_issuer=None,
            reasons=None
        )]),
        critical=False        
    ).sign(signing_ca_key, hashes.SHA256())

with open("cert.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

# openssl x509 -text -in cert.pem
# openssl verify -verbose -CAfile root-ca_cert.pem <(cat signing-ca.pem cert.pem)
