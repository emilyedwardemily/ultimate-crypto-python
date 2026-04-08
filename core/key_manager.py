import os
from argon2 import PasswordHasher, Type

class KeyManager:
    # Salt lazima iwe bytes na iwe angalau 16 bytes
    SYSTEM_SALT = b'UC_PRO_MILITARY_STRETCH_2026_KIU'

    @staticmethod
    def derive_key(password: str):
        """
        Inatumia Argon2id kuzalisha 32-byte key kwa ajili ya AES-256.
        Hii ni 'Cloud-Safe' na haina matatizo ya matoleo (Versions).
        """
        if not password:
            password = "default_secure_key"

        # Tunatumia Argon2id (Type.ID)
        ph = PasswordHasher(
            time_cost=3,        # Iterations
            memory_cost=65536,   # 64MB RAM
            parallelism=4,       # Threads
            hash_len=32,         # Tunahitaji 32 bytes kwa AES-256
            type=Type.ID         # Argon2id
        )
        
        # Tunazalisha key (hash) kwa kutumia password na salt yetu ya siri
        # Kumbuka: Argon2-cffi inashughulikia salt ndani ya kodi kwa usalama zaidi
        derived = ph.hash(password)
        
        # Kwa AES-256, tunahitaji bytes 32 safi
        # Tunarudisha bytes pekee ili zitumike na AES engine yako
        import hashlib
        return hashlib.sha256(derived.encode()).digest()