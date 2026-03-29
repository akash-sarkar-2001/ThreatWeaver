import os
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import SubjectAlternativeName, DNSName, IPAddress
import ipaddress
import dotenv

dotenv.load_dotenv()

# Read from .env, default to current directory and localhost if missing
CERT_DIR = os.getenv("CERT_DIR")
SERVER_IP = os.getenv("SERVER_IP", "127.0.0.1")
os.makedirs(CERT_DIR, exist_ok=True)

print(f"[*] Generating 2048-bit RSA SSL Certificate for IP: {SERVER_IP}...")

# Generate private key
key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096
)

subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Kerala"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ThreatWeaver SOC"),
    x509.NameAttribute(NameOID.COMMON_NAME, str(SERVER_IP)),
])

cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.now(timezone.utc))
    .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
    .add_extension(
        SubjectAlternativeName([
            IPAddress(ipaddress.IPv4Address(SERVER_IP)),
            IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            DNSName("localhost")
        ]),
        critical=False,
    )
    .sign(key, hashes.SHA256())
)

cert_path = os.path.join(CERT_DIR, "cert.pem")
key_path = os.path.join(CERT_DIR, "key.pem")

with open(cert_path, "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

with open(key_path, "wb") as f:
    f.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))

print(f"[+] SUCCESS! Saved to {cert_path} and {key_path}")
