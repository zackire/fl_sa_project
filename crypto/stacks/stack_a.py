import os
import pickle
import struct
import ascon
from typing import Dict, List, Tuple

from crypto.interface import CryptoInterface
from cryptography.hazmat.primitives.asymmetric import x25519 # type: ignore
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

# Importing the SSS logic provided by the Flower adapter
from flower_secagg_utils import create_shares

class Stack1Crypto(CryptoInterface):
    def __init__(self, my_client_id: str):
        self._my_id = my_client_id
        
        # Internal Secret Storage
        self._cSK = None
        self._sSK = None
        self._b_u = None
        
        # Storage for incoming Shamir shares 
        self._held_b_u_shares: Dict[str, bytes] = {}
        self._held_s_sk_shares: Dict[str, bytes] = {}

    # ==========================================
    # ROUND 0: KEY EXCHANGE (X25519)
    # ==========================================

    def generate_dh_encryption_keypair(self) -> Dict[str, bytes]:
        self._cSK = x25519.X25519PrivateKey.generate()
        return {"cPK": self._cSK.public_key().public_bytes_raw()}

    def generate_dh_masking_keypair(self) -> Dict[str, bytes]:
        self._sSK = x25519.X25519PrivateKey.generate()
        return {"sPK": self._sSK.public_key().public_bytes_raw()}

    # ==========================================
    # ROUND 1: SHARED SECRETS, MASKS & SHARES
    # ==========================================

    def compute_shared_secrets(self, external_public_keys: Dict[str, Dict[str, bytes]]) -> Dict[str, Dict[str, bytes]]:
        shared_secrets = {}
        for target_id, keys in external_public_keys.items():
            target_cPK = x25519.X25519PublicKey.from_public_bytes(keys["cPK"])
            target_sPK = x25519.X25519PublicKey.from_public_bytes(keys["sPK"])
            
            # Returning both keys so the orchestrator can route them to encryption and masking
            shared_secrets[target_id] = {
                "c_uv": self._cSK.exchange(target_cPK),
                "s_uv": self._sSK.exchange(target_sPK)
            }
        return shared_secrets

    def generate_pairwise_masks(self, shared_mask_seeds: Dict[str, bytes], mask_length: int) -> Dict[str, List[float]]:
        masks = {}
        for target_id, seed in shared_mask_seeds.items():
            # INLINE: ChaCha20 PRG expansion
            chacha_key = seed[:32] 
            nonce = b'\x00' * 16  
            cipher = Cipher(algorithms.ChaCha20(chacha_key, nonce), mode=None) 
            encryptor = cipher.encryptor()
            
            # Generate bytes and immediately convert to floats inline
            prg_bytes = encryptor.update(b'\x00' * (mask_length * 4))
            masks[target_id] = list(struct.unpack(f'{mask_length}f', prg_bytes))
            
        return masks

    def generate_self_mask_seed(self) -> bytes:
        # Utilizing OS-PRNG for true entropy
        self._b_u = os.urandom(32)
        return self._b_u

    def generate_shamir_shares(self, threshold: int, total_shares: int) -> Dict[str, List[Tuple[int, bytes]]]:
        # INLINE: Utilizing Flower's SSS
        b_u_shares_raw = create_shares(self._b_u, threshold, total_shares)
        s_sk_shares_raw = create_shares(self._sSK.private_bytes_raw(), threshold, total_shares)
        
        # Mapping Flower's byte format to the required Tuple format
        b_u_list = [(int.from_bytes(s[:4], "little", signed=False), s) for s in b_u_shares_raw]
        s_sk_list = [(int.from_bytes(s[:4], "little", signed=False), s) for s in s_sk_shares_raw]
        
        return {
            "b_u": b_u_list,
            "s_sk": s_sk_list
        }

    def encrypt_shares_for_routing(self, target_client_id: str, b_u_share: bytes, s_sk_share: bytes, c_uv: bytes) -> bytes:
        payload = pickle.dumps({"b_u_share": b_u_share, "s_sk_share": s_sk_share})
        ascon_key = c_uv[:16] 
        nonce = os.urandom(16)
        
        ciphertext = ascon.ascon_encrypt(ascon_key, nonce, b"", payload, variant="Ascon-128")
        return nonce + ciphertext

    def decrypt_incoming_shares(self, source_client_id: str, ciphertext: bytes, c_uv: bytes) -> bytes:
        ascon_key = c_uv[:16]
        nonce = ciphertext[:16]
        actual_ciphertext = ciphertext[16:]
        
        plaintext = ascon.ascon_decrypt(ascon_key, nonce, b"", actual_ciphertext, variant="Ascon-128")
        if plaintext is None:
            raise ValueError("Authentication tag verification failed.")
            
        shares = pickle.loads(plaintext)
        self._held_b_u_shares[source_client_id] = shares["b_u_share"]
        self._held_s_sk_shares[source_client_id] = shares["s_sk_share"]
        
        return plaintext

    # ==========================================
    # ROUND 2: MASKED INPUT GENERATION
    # ==========================================

    def generate_self_mask(self, self_mask_seed: bytes, mask_length: int) -> List[float]:
        # INLINE: ChaCha20 PRG expansion
        chacha_key = self_mask_seed[:32] 
        nonce = b'\x00' * 16  
        cipher = Cipher(algorithms.ChaCha20(chacha_key, nonce), mode=None) 
        encryptor = cipher.encryptor()
        
        prg_bytes = encryptor.update(b'\x00' * (mask_length * 4))
        return list(struct.unpack(f'{mask_length}f', prg_bytes))

    def compute_masked_input(self, raw_data_vector: List[float], b_u_vector: List[float], pairwise_masks: Dict[str, List[float]], active_users: List[str]) -> List[float]:
        # Vector Arithmetic: Summing raw data with the self-mask
        y_u = [r + b for r, b in zip(raw_data_vector, b_u_vector)]
        
        # Applying Bonawitz dropout cancellation logic with vector arithmetic
        for target_id, mask in pairwise_masks.items():
            if target_id not in active_users:
                continue
            
            # Lexicographical check to ensure opposite signs
            sign = 1 if self._my_id > target_id else -1
            y_u = [y + (sign * m) for y, m in zip(y_u, mask)]
            
        return y_u

    # ==========================================
    # ROUND 3: UNMASKING
    # ==========================================

    def provide_survivor_b_u_shares(self, surviving_users: List[str], dropped_users_check: List[str]) -> Dict[str, bytes]:
        shares_to_return = {}
        for user_id in surviving_users:
            if user_id in dropped_users_check:
                raise ValueError(f"Protocol abort: Server illicitly requested b_u share for dropped user {user_id}")
            if user_id in self._held_b_u_shares:
                shares_to_return[user_id] = self._held_b_u_shares[user_id]
        return shares_to_return

    def provide_dropped_s_sk_shares(self, dropped_users: List[str], surviving_users_check: List[str]) -> Dict[str, bytes]:
        shares_to_return = {}
        for user_id in dropped_users:
            if user_id in surviving_users_check:
                raise ValueError(f"Protocol abort: Server illicitly requested s_SK share for surviving user {user_id}")
            if user_id in self._held_s_sk_shares:
                shares_to_return[user_id] = self._held_s_sk_shares[user_id]
        return shares_to_return