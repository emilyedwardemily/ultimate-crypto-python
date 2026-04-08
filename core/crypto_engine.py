from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64

class CryptoEngine:
    @staticmethod
    def encrypt(data: str, key: bytes):
        try:
            # Tunahakikisha key ina urefu wa bytes 32 (AES-256)
            if len(key) != 32:
                raise ValueError("Key must be 32 bytes for AES-256")
                
            aesgcm = AESGCM(key)
            nonce = os.urandom(12) # 12 bytes ndiyo standard ya GCM
            ciphertext = aesgcm.encrypt(nonce, data.encode('utf-8'), None)
            
            # Tunarudisha Nonce + Ciphertext ikiwa Base64
            return base64.b64encode(nonce + ciphertext).decode('utf-8')
        except Exception as e:
            return f"ENCRYPTION_ERROR: {str(e)}"

    @staticmethod
    def decrypt(encoded_data: str, key: bytes):
        try:
            aesgcm = AESGCM(key)
            raw = base64.b64decode(encoded_data)
            
            # Tenganisha Nonce (12 bytes za mwanzo) na Ciphertext (zilizobaki)
            nonce = raw[:12]
            ciphertext = raw[12:]
            
            decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
            return decrypted_bytes.decode('utf-8')
        except Exception as e:
            # Hapa itatokea kama Key ni mbaya au data imebadilishwa (Tampered)
            return f"DECRYPTION_ERROR: Authentication failed or malformed data."