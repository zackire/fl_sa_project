from abc import ABC, abstractmethod
from typing import Dict, List, Tuple

class CryptoInterface(ABC):

    # ROUND 0: KEY EXCHANGE (X25519)

    @abstractmethod
    def generate_dh_encryption_keypair(self) -> Dict[str, bytes]:
        """Generates the temporary Diffie-Hellman session keypair for AEAD encryption (cSK, cPK)."""
        pass

    @abstractmethod
    def generate_dh_masking_keypair(self) -> Dict[str, bytes]:
        """Generates the temporary Diffie-Hellman session keypair for pairwise masks (sSK, sPK)."""
        pass


    # ROUND 1: SHARED SECRETS, MASKS & SHARES

    @abstractmethod
    def compute_shared_secrets(self, external_public_keys: Dict[str, Dict[str, bytes]]) -> Dict[str, bytes]:
        """
        Computes the shared pairwise mask seeds (s_{u,v}) and shared encryption keys (c_{u,v}) 
        using X25519 ECDH.
        """
        pass

    @abstractmethod
    def generate_pairwise_masks(self, shared_mask_seeds: Dict[str, bytes], mask_length: int) -> Dict[str, List[float]]:
        """
        Expands all shared seeds (s_{u,v}) into the actual pairwise mask vectors 
        using the PRG (SIMON/CHACHA20/PRESENT).
        """
        pass

    @abstractmethod
    def generate_self_mask_seed(self) -> bytes:
        """Generates the client's private server-side mask seed (b_u)."""
        pass

    @abstractmethod
    def generate_shamir_shares(self, threshold: int, total_shares: int) -> Dict[str, List[Tuple[int, bytes]]]:
        """
        Splits BOTH the private server seed (b_u) AND the private masking key (s_u^{SK})
        into shares using Shamir's Secret Sharing.
        """
        pass

    @abstractmethod
    def encrypt_shares_for_routing(self, target_client_id: str, b_u_share: bytes, s_sk_share: bytes, c_uv: bytes) -> bytes:
        """
        Encrypts the Shamir shares meant for a specific user using the AEAD stack (ASCON/GIFT-COFB).
        """
        pass
    
    @abstractmethod
    def decrypt_incoming_shares(self, source_client_id: str, ciphertext: bytes, c_uv: bytes) -> bytes:
        """
        Decrypts incoming Shamir shares received from the MQTT broker using the AEAD stack 
        (ASCON/GIFT-COFB) and the shared encryption key (c_{u,v}).
        """
        pass

    # ROUND 2: MASKED INPUT GENERATION

    @abstractmethod
    def generate_self_mask(self, self_mask_seed: bytes, mask_length: int) -> List[float]:
        """
        Expands the private seed (b_u) into the self-mask vector (B_u) 
        using the PRG (SIMON/CHACHA20/PRESENT).
        """
        pass

    @abstractmethod
    def compute_masked_input(self, raw_data_vector: List[float], b_u_vector: List[float], pairwise_masks: Dict[str, List[float]], active_users: List[str]) -> List[float]:
        """
        The final summation step. 
        Computes: Y_u = raw_data + B_u + SUM(pairwise_masks * sign)
        Returns the masked input (Y_u) to be sent to the server.
        """
        pass

    # ROUND 3: UNMASKING 

    @abstractmethod
    def provide_survivor_b_u_shares(self, surviving_users: List[str], dropped_users_check: List[str]) -> Dict[str, bytes]:
        """
        Returns decrypted shares of b_v for users who STAYED online.
        SECURITY CHECK: Must verify that no requested user is in the dropped_users_check list.
        """
        pass

    @abstractmethod
    def provide_dropped_s_sk_shares(self, dropped_users: List[str], surviving_users_check: List[str]) -> Dict[str, bytes]:
        """
        Returns decrypted shares of s_v^{SK} for users who DROPPED offline.
        SECURITY CHECK: Must verify that no requested user is in the surviving_users_check list.
        """
        pass