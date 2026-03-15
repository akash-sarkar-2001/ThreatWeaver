from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta, timezone
from cryptography.x509 import SubjectAlternativeName, DNSName, IPAddress
import ipaddress
import os
import zoneinfo

CERT_DIR = r"C:\https_cert"
os.makedirs(CERT_DIR, exist_ok=True)

# Generate private key
key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Kerala"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"AD-Lab"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"192.168.40.10"),
])

cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.now(timezone.utc))
    .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))

    # IMPORTANT: Add SAN
    .add_extension(
        SubjectAlternativeName([
            IPAddress(ipaddress.IPv4Address("192.168.40.10")),
            DNSName("localhost")
        ]),
        critical=False
    )

    .sign(key, hashes.SHA256())
)

# Save key
with open(os.path.join(CERT_DIR, "key.pem"), "wb") as f:
    f.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Save cert
with open(os.path.join(CERT_DIR, "cert.pem"), "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

print("Certificate regenerated with SAN support")
