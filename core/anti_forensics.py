import os
import secrets

class AntiForensics:
    @staticmethod
    def secure_wipe(file_path):
        """
        Inafuta file kwa kuandika random noise mara 3 (DoD Standard).
        Inahakikisha data haipo tena hata kwa Forensic Recovery Tools.
        """
        try:
            if not os.path.exists(file_path):
                return False
            
            size = os.path.getsize(file_path)
            
            # Tunafungua file katika 'binary write' mode
            with open(file_path, "br+", buffering=0) as f:
                for pass_num in range(3):
                    f.seek(0)
                    # Tunatumia secrets.token_bytes kwa sababu ni Cryptographically Secure
                    f.write(secrets.token_bytes(size))
                    
                    # MUHIMU: Inalazimisha Hard Drive kuandika data sasa hivi (No caching)
                    f.flush()
                    os.fsync(f.fileno())
            
            # Baada ya kuandika kelele mara 3, sasa tunafuta file kabisa
            os.remove(file_path)
            return True
            
        except Exception as e:
            print(f"Forensic Wipe Error: {e}")
            return False