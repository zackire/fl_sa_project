import base64
import json
from typing import Dict, Any, List

class PayloadBuilder:
    """
    Centralized utility for formatting MQTT topics and lightweight 
    JSON payloads for the CI Secure Aggregation testbed.
    """
    
    BASE_TOPIC = "ci_fl"

    @staticmethod
    def build_topic(epoch: int, round_num: int, sender_id: str, is_broadcast: bool = False) -> str:
        """
        Creates a highly descriptive MQTT topic for easy network monitoring
        without bloating the JSON payload.
        Example: ci_fl/epoch_1/round_1/client_1/tx
        """
        target = "broadcast" if is_broadcast else "tx"
        return f"{PayloadBuilder.BASE_TOPIC}/epoch_{epoch}/round_{round_num}/{sender_id}/{target}"

    @staticmethod
    def encode_bytes_to_b64_string(raw_bytes: bytes) -> str:
        """Converts raw cryptographic bytes into a network-efficient Base64 string."""
        return base64.b64encode(raw_bytes).decode('utf-8')

    @staticmethod
    def decode_b64_string_to_bytes(b64_string: str) -> bytes:
        """Converts an incoming Base64 string back into raw bytes."""
        return base64.b64decode(b64_string.encode('utf-8'))

    @staticmethod
    def build_round_0_payload(public_keys: Dict[str, bytes]) -> str:
        """Serializes the X25519 public keys using Base64."""
        b64_keys = {
            k: PayloadBuilder.encode_bytes_to_b64_string(v) 
            for k, v in public_keys.items()
        }
        return json.dumps({"public_keys": b64_keys})

    @staticmethod
    def build_round_1_payload(encrypted_shares: Dict[str, bytes]) -> str:
        """Serializes the Ascon-128a encrypted Shamir shares."""
        b64_shares = {
            target_id: PayloadBuilder.encode_bytes_to_b64_string(ciphertext)
            for target_id, ciphertext in encrypted_shares.items()
        }
        return json.dumps({"encrypted_shares": b64_shares})

    @staticmethod
    def build_round_2_payload(masked_weights: List[float], mask_length: int) -> str:
        """
        Packages the masked ML weights. Since these are floats/integers, 
        they serialize cleanly without Base64.
        """
        return json.dumps({
            "masked_weights": masked_weights,
            "mask_length": mask_length
        })

    @staticmethod
    def build_round_3_payload(encrypted_recovery_data: bytes) -> str:
        """Serializes the Ascon-128a encrypted recovery payload."""
        b64_recovery = PayloadBuilder.encode_bytes_to_b64_string(encrypted_recovery_data)
        return json.dumps({"recovery_payload": b64_recovery})