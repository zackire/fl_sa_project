import os
import ascon
from typing import Dict
from present_cipher import present as Present
from crypto.interface import CryptoInterface
from cryptography.hazmat.primitives.asymmetric import x25519

class Stack3Crypto(CryptoInterface):
    def __init__(self):
        self._cSK = None
        self._sSK = None

    def generate_keypairs(self) -> Dict[str, bytes]:
        try:
            self._cSK = x25519.X25519PrivateKey.generate()
            self._sSK = x25519.X25519PrivateKey.generate()
            
            return {
                "cPK": self._cSK.public_key().public_bytes_raw(),
                "sPK": self._sSK.public_key().public_bytes_raw()
            }
        except Exception as e:
            raise RuntimeError(f"Key generation failure: {e}")

    def compute_shared_secrets(self, external_public_keys: Dict[str, Dict[str, bytes]]) -> Dict[str, bytes]:
        shared_secrets = {}
        for target_id, keys in external_public_keys.items():
            target_cPK = x25519.X25519PublicKey.from_public_bytes(keys["cPK"])
            shared_secrets[target_id] = self._cSK.exchange(target_cPK)
        return shared_secrets

    def generate_prg_mask(self, shared_secret: bytes, mask_length: int) -> bytes:
        present_key = shared_secret[:16]
        cipher = Present(present_key)
        
        mask_bytes = bytearray()
        num_blocks = (mask_length + 7) // 8  
        
        for counter in range(num_blocks):
            counter_block = counter.to_bytes(8, byteorder='big')
            prg_block = cipher.encrypt(counter_block)
            mask_bytes.extend(prg_block)
        
        return bytes(mask_bytes[:mask_length])

    def encrypt_payload(self, target_client_id: str, payload: bytes, shared_secret: bytes) -> bytes:
        ascon_key = shared_secret[:16] 
        nonce = os.urandom(16)
        ciphertext = ascon.encrypt(self.key, self.nonce, self.ad, plaintext, variant="Ascon-128")
        return nonce + ciphertext

    def decrypt_payload(self, source_client_id: str, ciphertext: bytes, shared_secret: bytes) -> bytes:
        ascon_key = shared_secret[:16]
        nonce = ciphertext[:16]
        actual_ciphertext = ciphertext[16:]
        plaintext = ascon.decrypt(self.key, self.nonce, self.ad, ciphertext, variant="Ascon-128")
        
        if plaintext is None:
            raise ValueError("Authentication tag verification failed.")
        return plaintext

    def get_private_masking_key(self) -> bytes:
        return self._sSK.private_bytes_raw()

    def get_private_client_key(self) -> bytes:
        return self._cSK.private_bytes_raw()