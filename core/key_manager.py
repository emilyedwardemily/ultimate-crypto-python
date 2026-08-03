import hashlib

class KeyManager:
    SYSTEM_SALT = b'UC_PRO_MILITARY_STRETCH_2026_KIU'

    @staticmethod
    def derive_key(password: str):
        if not password:
            password = "default_secure_key"

        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            KeyManager.SYSTEM_SALT,
            iterations=600000,
            dklen=32,
        )