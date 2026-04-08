import base64
import os
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

class SignatureEngine:
    @staticmethod
    def sign(data: str):
        """
        Inatengeneza Digital Signature (RSA Seal) kwa ajili ya data husika.
        Inatumia SHA-256 hashing na RSA-2048 signing.
        """
        try:
            # 1. Hakikisha kuna Private Key ya kusaini
            # Kwenye mazingira ya Kali Linux, tunahifadhi key kwenye folder la sasa
            key_path = "private_key.pem"
            
            if not os.path.exists(key_path):
                # Kama key haipo, tengeneza mpya (RSA 2048-bit)
                key = RSA.generate(2048)
                with open(key_path, "wb") as f:
                    f.write(key.export_key())
            else:
                # Kama ipo, isome tayari kwa matumizi
                with open(key_path, "rb") as f:
                    key = RSA.import_key(f.read())

            # 2. Tengeneza Hash ya data (SHA-256)
            # Hii inahakikisha hata nukta ikibadilika, signature itakataa
            h = SHA256.new(data.encode('utf-8'))

            # 3. Saini Hash hiyo kwa kutumia Private Key
            signature = pkcs1_15.new(key).sign(h)
            
            # 4. Badilisha kwenda Base64 ili Java iweze kuonyesha kwenye UI kirahisi
            encoded_sig = base64.b64encode(signature).decode('utf-8')
            
            return encoded_sig

        except Exception as e:
            # Kama kuna tatizo lolote (mfano library inakosekana), irudishe error message
            return f"SIGNING_ERROR: {str(e)}"

    @staticmethod
    def verify(data: str, signature_b64: str, public_key_path: str):
        """
        Inahakiki kama signature ni sahihi na data haijabadilishwa.
        """
        try:
            with open(public_key_path, "rb") as f:
                pub_key = RSA.import_key(f.read())
            
            h = SHA256.new(data.encode('utf-8'))
            signature = base64.b64decode(signature_b64)
            
            pkcs1_15.new(pub_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False