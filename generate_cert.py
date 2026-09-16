"""
Self-Signed TLS/HTTPS Certificate Generator for CNS Project
Uses Python's cryptography library (x509) so OpenSSL CLI is not required.
"""
import datetime
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import ipaddress

def generate_self_signed_cert(cert_path="cert.pem", key_path="key.pem"):
    cert_file = Path(cert_path)
    key_file = Path(key_path)

    if cert_file.exists() and key_file.exists():
        print(f"[*] Certificate and key already exist: {cert_path}, {key_path}")
        return

    print("[*] Generating 2048-bit RSA Private Key for TLS...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Campus"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CNS Educational Security Lab"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    print("[*] Building X.509 v3 Certificate...")
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    print(f"[*] Saving Private Key to {key_path}...")
    with open(key_file, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    print(f"[*] Saving Certificate to {cert_path}...")
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("[+] TLS Certificate and Key generated successfully!")

if __name__ == "__main__":
    generate_self_signed_cert()
