#!/usr/bin/env python3

from cryptography import x509
from cryptography.x509.oid import NameOID

with open('ca.csr', "rb") as f:
    data = f.read()

csr = x509.load_pem_x509_csr(data)

commonName = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0]
print(commonName.value)
