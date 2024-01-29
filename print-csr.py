#!/usr/bin/env python3

import argparse
from cryptography import x509
from cryptography.x509.oid import NameOID

if __name__ == "__main__":
    parser = argparse.ArgumentParser("print-csr")
    parser.add_argument("filename", type=str)
    args = parser.parse_args()

    with open(args.filename, "rb") as f:
        data = f.read()

    csr = x509.load_pem_x509_csr(data)

    commonName = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0]
    print(commonName.value)
