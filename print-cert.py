#!/usr/bin/env python3

import argparse
from cryptography import x509


def print_cert(filename: str):
    with open(filename, "rb") as f:
        data = f.read()
    cert = x509.load_pem_x509_certificate(data)
    print(f"serial          : 0x{cert.serial_number:x}")
    print(f"not valid before: {cert.not_valid_before_utc}")
    print(f"not valid after : {cert.not_valid_after_utc}")
    print("issuer:")
    print_name(cert.issuer)
    print("subject:")
    print_name(cert.subject)
    print("Extensions:")
    for extension in cert.extensions:
            print(extension)

def print_name(name):
    for item in name:
        print(f"\t{item.rfc4514_attribute_name}: {item.value}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="print-cert",
        description="print certificate")
    parser.add_argument("filename", type=str)
    args = parser.parse_args()
    print_cert(args.filename)
