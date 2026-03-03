from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
import os

CERT_DIR = r"C:\https_cert"
os.makedirs(CERT_DIR, exist_ok=True)

# Generate private key
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Create certificate
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Kerala"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"AD-Lab"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"DC-Server"),
])

cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.utcnow())
    .not_valid_after(datetime.utcnow() + timedelta(days=365))
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

print("Self-signed certificate created in C:\\https_cert")
