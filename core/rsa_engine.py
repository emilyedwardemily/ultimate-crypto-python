import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
import os

class RSAEngine:
    """RSA-2048 OAEP-SHA256 (inaendana na crypto/RSAUtil.java ya frontend)."""

    @staticmethod
    def generate_keypair(bits: int = 2048):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode('utf-8')
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode('utf-8')
        return private_pem, public_pem

    @staticmethod
    def encrypt(data: str, public_key_pem: str):
        public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
        ciphertext = public_key.encrypt(
            data.encode('utf-8'),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None),
        )
        return base64.b64encode(ciphertext).decode('utf-8')

    @staticmethod
    def decrypt(data_b64: str, private_key_pem: str):
        private_key = serialization.load_pem_private_key(private_key_pem.encode('utf-8'), password=None)
        plaintext = private_key.decrypt(
            base64.b64decode(data_b64),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None),
        )
        return plaintext.decode('utf-8')


class PGPEngine:
    """PGP-lite armored encryption kwa kutumia AES-256-GCM (aad kama header)."""

    HEADER = "-----BEGIN PGP MESSAGE-----"
    FOOTER = "-----END PGP MESSAGE-----"

    @staticmethod
    def encrypt(data: str, password: str = "default_secure_key"):
        from core.key_manager import KeyManager
        key = KeyManager.derive_key(password)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data.encode('utf-8'), b"UC_PGP_V1")
        body = base64.b64encode(nonce + ciphertext).decode('utf-8')
        return f"{PGPEngine.HEADER}\n{body}\n{PGPEngine.FOOTER}"

    @staticmethod
    def decrypt(armored: str, password: str = "default_secure_key"):
        from core.key_manager import KeyManager
        body = armored.replace(PGPEngine.HEADER, "").replace(PGPEngine.FOOTER, "").strip()
        raw = base64.b64decode(body.replace("\n", ""))
        key = KeyManager.derive_key(password)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(raw[:12], raw[12:], b"UC_PGP_V1")
        return plaintext.decode('utf-8')


class IdentityEngine:
    """Self-signed X.509 certificate (S/MIME) generation."""

    @staticmethod
    def generate_cert(subject_cn: str = "UC-Suite Secure Identity"):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Ultimate Crypto Suite"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode('utf-8')
        return cert_pem, key_pem
