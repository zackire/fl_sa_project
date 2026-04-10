import os
import ascon
from typing import Dict
from crypto.interface import CryptoInterface
from cryptography.hazmat.primitives.asymmetric import x25519 # type: ignore
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

class Stack1Crypto(CryptoInterface):
    def __init__(self):
        self._cSK = None
        self._sSK = None

# X25519 - KEY EXCHANGE
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

# CHACHA20 - PRG MASK GENERATION
    def generate_prg_mask(self, shared_secret: bytes, mask_length: int) -> bytes:
        chacha_key = shared_secret 
        nonce = b'\x00' * 16  
        
        cipher = Cipher(algorithms.ChaCha20(chacha_key, nonce), mode=None) 
        encryptor = cipher.encryptor()
        
        return encryptor.update(b'\x00' * mask_length) 

# ASCON - PAYLOAD ENCRYPTION
    def encrypt_payload(self, target_client_id: str, payload: bytes, shared_secret: bytes) -> bytes:
        ascon_key = shared_secret[:16] 
        nonce = os.urandom(16)
        
        ciphertext = ascon.ascon_encrypt(ascon_key, nonce, b"", payload, variant="Ascon-128")
        return nonce + ciphertext

    def decrypt_payload(self, source_client_id: str, ciphertext: bytes, shared_secret: bytes) -> bytes:
        ascon_key = shared_secret[:16]
        nonce = ciphertext[:16]
        actual_ciphertext = ciphertext[16:]
        
        plaintext = ascon.ascon_decrypt(ascon_key, nonce, b"", actual_ciphertext, variant="Ascon-128")
        if plaintext is None:
            raise ValueError("Authentication tag verification failed.")
        return plaintext

    def get_private_masking_key(self) -> bytes:
        return self._sSK.private_bytes_raw()

    def get_private_client_key(self) -> bytes:
        return self._cSK.private_bytes_raw()