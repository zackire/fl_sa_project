import os
import ascon
from typing import Dict
from crypto.interface import CryptoInterface
from cryptography.hazmat.primitives.asymmetric import x25519
from simonspeckciphers.simon.simon import SimonCipher

class Stack2Crypto(CryptoInterface):
    def __init__(self):
        self._cSK = None
        self._sSK = None

#X25519 - KEY EXCHANGE
    def generate_keypairs(self) -> Dict[str, bytes]:
    #This function generates two X25519 key pairs: one for encryption and one for masking. 
    # It returns the public keys in a dictionary format. If any error occurs during key generation, it raises a RuntimeError with an appropriate message.
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
    #This function computes shared secrets for each target client based on their public keys.
        shared_secrets = {}
        for target_id, keys in external_public_keys.items():
            target_cPK = x25519.X25519PublicKey.from_public_bytes(keys["cPK"])
            shared_secrets[target_id] = self._cSK.exchange(target_cPK)
        return shared_secrets
    
#SIMON - PRG MASK GENERATION
    def generate_prg_mask(self, shared_secret: bytes, mask_length: int) -> bytes:
    #This function generates a PRG mask using the shared secret and the specified mask length.
            simon_key_int = int.from_bytes(shared_secret[:16], byteorder='big') #Takes the first half of the X25519 secret and treats it as the 128-bit key for SIMON.
            nonce_int = int.from_bytes(shared_secret[16:32], byteorder='big') #Takes the second half as the unique starting point (IV).
            
            cipher = SimonCipher(simon_key_int, key_size=128, block_size=128, mode='CTR', init=nonce_int)
            
            mask_bytes = bytearray()
            num_blocks = (mask_length + 15) // 16  
            
            for _ in range(num_blocks):
                #In CTR mode, the cipher encrypts an incrementing counter. By XORing this with 0, the code extracts the raw "keystream."
                prg_block_int = cipher.encrypt(0)
                mask_bytes.extend(prg_block_int.to_bytes(16, byteorder='big'))
            
            return bytes(mask_bytes[:mask_length])

#ASCON - AEAD ENCRYPTION   
    def encrypt_payload(self, target_client_id: str, payload: bytes, shared_secret: bytes) -> bytes:
    #This function encrypts the given payload using the shared secret.
            ascon_key = shared_secret[:16] #Derives a 128-bit session key.
            nonce = os.urandom(16) #Generates a random 128-bit nonce for encryption.
            
            ciphertext = ascon.ascon_encrypt(ascon_key, nonce, b"", payload, variant="Ascon-128a") #Sponge-based permutation. It absorbs the payload and outputs a ciphertext + Authentication tag.
            return nonce + ciphertext

    def decrypt_payload(self, source_client_id: str, ciphertext: bytes, shared_secret: bytes) -> bytes:
        ascon_key = shared_secret[:16]
        nonce = ciphertext[:16]
        actual_ciphertext = ciphertext[16:]
        
        plaintext = ascon.ascon_decrypt(ascon_key, nonce, b"", actual_ciphertext, variant="Ascon-128a")
        
        if plaintext is None:
            raise ValueError("Authentication tag verification failed.")
        return plaintext

    def get_private_masking_key(self) -> bytes:
        return self._sSK.private_bytes_raw()

    def get_private_client_key(self) -> bytes:
        return self._cSK.private_bytes_raw()