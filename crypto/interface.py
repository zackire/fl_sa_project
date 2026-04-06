from abc import ABC, abstractmethod
from typing import Dict

class CryptoInterface(ABC):
    @abstractmethod
    def generate_keypairs(self) -> Dict[str, bytes]:
        pass

    @abstractmethod
    def compute_shared_secrets(self, external_public_keys: Dict[str, Dict[str, bytes]]) -> Dict[str, bytes]:
        pass

    @abstractmethod
    def generate_prg_mask(self, shared_secret: bytes, mask_length: int) -> bytes:
        pass

    @abstractmethod
    def encrypt_payload(self, target_client_id: str, payload: bytes, shared_secret: bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt_payload(self, source_client_id: str, ciphertext: bytes, shared_secret: bytes) -> bytes:
        pass

    @abstractmethod
    def get_private_masking_key(self) -> bytes:
        """Returns the raw bytes of the Server Secret Key (sSK) for Shamir splitting."""
        pass

    @abstractmethod
    def get_private_client_key(self) -> bytes:
        """Returns the raw bytes of the Client Secret Key (cSK) for server communication."""
        pass