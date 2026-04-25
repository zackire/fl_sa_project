import os
import pickle
import struct
from typing import Dict, List, Tuple

from crypto.interface import CryptoInterface
from cryptography.hazmat.primitives.asymmetric import x25519
from crypto.stacks.algorithms.present_algo import Present
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from secure_aggregation.flower_secagg_utils import create_shares


class Stack3Crypto(CryptoInterface):
    STACK_ID = "C"

    def __init__(self, my_client_id: str):
        self._my_id = my_client_id
        self._cSK = None
        self._sSK = None
        self._b_u = None
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
        if self._cSK is None or self._sSK is None:
            raise ValueError("Keypairs not generated.")
        if external_public_keys is None:
            raise ValueError("external_public_keys cannot be None.")
        shared_secrets = {}
        for target_id, keys in external_public_keys.items():
            target_cPK = x25519.X25519PublicKey.from_public_bytes(keys["cPK"])
            target_sPK = x25519.X25519PublicKey.from_public_bytes(keys["sPK"])
            shared_secrets[target_id] = {
                "c_uv": self._cSK.exchange(target_cPK),
                "s_uv": self._sSK.exchange(target_sPK),
            }
        return shared_secrets

    def generate_pairwise_masks(self, shared_mask_seeds: Dict[str, bytes], mask_length: int) -> Dict[str, List[int]]:
        if shared_mask_seeds is None:
            raise ValueError("shared_mask_seeds cannot be None.")
        masks = {}
        byte_length = mask_length * 4
        num_blocks  = (byte_length + 7) // 8  # PRESENT uses 8-byte (64-bit) blocks

        for target_id, seed in shared_mask_seeds.items():
            if seed is None:
                raise ValueError(f"Seed for {target_id} is None.")

            present_key_int = int.from_bytes(seed[:10], byteorder="big")
            cipher          = Present(present_key_int)
            mask_bytes      = bytearray()

            for counter in range(num_blocks):
                prg_block_int = cipher.encrypt(counter)
                mask_bytes.extend(prg_block_int.to_bytes(8, byteorder="big"))

            prg_bytes = bytes(mask_bytes[:byte_length])
            # FIX: unpack as unsigned 32-bit integers, NOT floats
            masks[target_id] = list(struct.unpack(f"{mask_length}I", prg_bytes))

        return masks

    def generate_self_mask_seed(self) -> bytes:
        self._b_u = os.urandom(32)
        return self._b_u

    def generate_shamir_shares(self, threshold: int, total_shares: int) -> Dict[str, List[Tuple[int, bytes]]]:
        if self._b_u is None or self._sSK is None:
            raise ValueError("Secrets not generated.")
        b_u_shares_raw  = create_shares(self._b_u, threshold, total_shares)
        s_sk_shares_raw = create_shares(self._sSK.private_bytes_raw(), threshold, total_shares)

        b_u_list  = [(int.from_bytes(s[:4], "little", signed=False), s) for s in b_u_shares_raw]
        s_sk_list = [(int.from_bytes(s[:4], "little", signed=False), s) for s in s_sk_shares_raw]

        return {"b_u": b_u_list, "s_sk": s_sk_list}

    def encrypt_shares_for_routing(self, target_client_id: str, b_u_share: bytes, s_sk_share: bytes, c_uv: bytes) -> bytes:
        if b_u_share is None or s_sk_share is None or c_uv is None:
            raise ValueError("None values passed to byte-strict encryption.")
        payload = pickle.dumps({"b_u_share": b_u_share, "s_sk_share": s_sk_share})
        cipher  = ChaCha20Poly1305(c_uv)   # c_uv from X25519 is exactly 32 bytes
        nonce   = os.urandom(12)
        ciphertext = cipher.encrypt(nonce, payload, None)
        return nonce + ciphertext

    def decrypt_incoming_shares(self, source_client_id: str, ciphertext: bytes, c_uv: bytes) -> bytes:
        if ciphertext is None or c_uv is None:
            raise ValueError("None values passed to byte-strict decryption.")
        cipher            = ChaCha20Poly1305(c_uv)
        nonce             = ciphertext[:12]
        actual_ciphertext = ciphertext[12:]
        try:
            plaintext = cipher.decrypt(nonce, actual_ciphertext, None)
        except Exception:
            raise ValueError(f"Decryption or integrity check failed for {source_client_id}")
        shares = pickle.loads(plaintext)
        self._held_b_u_shares[source_client_id]  = shares["b_u_share"]
        self._held_s_sk_shares[source_client_id] = shares["s_sk_share"]
        return plaintext

    # ==========================================
    # ROUND 2: MASKED INPUT GENERATION
    # ==========================================

    def generate_self_mask(self, self_mask_seed: bytes, mask_length: int) -> List[int]:
        if self_mask_seed is None:
            raise ValueError("self_mask_seed cannot be None.")

        byte_length = mask_length * 4
        num_blocks  = (byte_length + 7) // 8

        present_key_int = int.from_bytes(self_mask_seed[:10], byteorder="big")
        cipher          = Present(present_key_int)
        mask_bytes      = bytearray()

        for counter in range(num_blocks):
            prg_block_int = cipher.encrypt(counter)
            mask_bytes.extend(prg_block_int.to_bytes(8, byteorder="big"))

        prg_bytes = bytes(mask_bytes[:byte_length])
        # FIX: unpack as unsigned 32-bit integers, NOT floats
        return list(struct.unpack(f"{mask_length}I", prg_bytes))

    def compute_masked_input(self, raw_data_vector: List[int], b_u_vector: List[int], pairwise_masks: Dict[str, List[int]], active_users: List[str]) -> List[int]:
        if raw_data_vector is None or b_u_vector is None or pairwise_masks is None or active_users is None:
            raise ValueError("Masking inputs cannot be None.")

        # FIX: enforce 32-bit modulo boundary — identical to Stack A
        FIELD_MODULUS = 2**32
        y_u = [(int(r) + b) % FIELD_MODULUS for r, b in zip(raw_data_vector, b_u_vector)]

        for target_id, mask in pairwise_masks.items():
            if target_id not in active_users:
                continue
            sign = 1 if self._my_id > target_id else -1
            y_u  = [(y + sign * m) % FIELD_MODULUS for y, m in zip(y_u, mask)]

        return y_u

    # ==========================================
    # ROUND 3: UNMASKING
    # ==========================================

    def provide_survivor_b_u_shares(self, surviving_users: List[str], dropped_users_check: List[str]) -> Dict[str, bytes]:
        shares_to_return = {}
        for user_id in surviving_users:
            if user_id in dropped_users_check:
                raise ValueError(f"Protocol abort: b_u share requested for dropped user {user_id}")
            if user_id in self._held_b_u_shares:
                shares_to_return[user_id] = self._held_b_u_shares[user_id]
        return shares_to_return

    def provide_dropped_s_sk_shares(self, dropped_users: List[str], surviving_users_check: List[str]) -> Dict[str, bytes]:
        shares_to_return = {}
        for user_id in dropped_users:
            if user_id in surviving_users_check:
                raise ValueError(f"Protocol abort: s_SK share requested for surviving user {user_id}")
            if user_id in self._held_s_sk_shares:
                shares_to_return[user_id] = self._held_s_sk_shares[user_id]
        return shares_to_return