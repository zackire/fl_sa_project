import base64
import json
from typing import Dict, Any, List

class PayloadBuilder:
    """
    Centralized utility for formatting MQTT topics and lightweight 
    JSON payloads for the CI Secure Aggregation testbed.
    """
    
    @staticmethod
    def get_server_broadcast_topic() -> str:
        return "fl/server/broadcast"

    @staticmethod
    def get_client_inbox_topic(client_id: str) -> str:
        return f"fl/client/{client_id}/inbox"

    @staticmethod
    def get_server_dropbox_topic(client_id: str) -> str:
        return f"fl/client/{client_id}/to_server"

    @staticmethod
    def _wrap_payload(epoch: int, round_num: int, msg_type: str, client_id: str, data: Dict[str, Any]) -> str:
        return json.dumps({
            "meta": {
                "epoch": epoch,
                "round": round_num,
                "msg_type": msg_type,
                "client_id": client_id
            },
            "data": data
        })

    @staticmethod
    def encode_bytes_to_b64_string(raw_bytes: bytes) -> str:
        """Converts raw cryptographic bytes into a network-efficient Base64 string."""
        return base64.b64encode(raw_bytes).decode('utf-8')

    @staticmethod
    def decode_b64_string_to_bytes(b64_string: str) -> bytes:
        """Converts an incoming Base64 string back into raw bytes."""
        return base64.b64decode(b64_string.encode('utf-8'))

    @staticmethod
    def build_round_0_payload(client_id: str, public_keys: Dict[str, bytes]) -> str:
        b64_keys = {k: PayloadBuilder.encode_bytes_to_b64_string(v) for k, v in public_keys.items()}
        return PayloadBuilder._wrap_payload(1, 0, "public_keys", client_id, {"public_keys": b64_keys})

    @staticmethod
    def build_round_1_payload(client_id: str, encrypted_shares: Dict[str, bytes]) -> str:
        b64_shares = {target_id: PayloadBuilder.encode_bytes_to_b64_string(ciphertext) for target_id, ciphertext in encrypted_shares.items()}
        return PayloadBuilder._wrap_payload(1, 1, "secret_shares", client_id, {"encrypted_shares": b64_shares})

    @staticmethod
    def build_round_2_payload(client_id: str, masked_weights: List[float], mask_length: int) -> str:
        return PayloadBuilder._wrap_payload(1, 2, "masked_weights", client_id, {
            "masked_weights": masked_weights,
            "mask_length": mask_length
        })

    @staticmethod
    def build_round_3_payload(client_id: str, encrypted_recovery_data: bytes) -> str:
        b64_recovery = PayloadBuilder.encode_bytes_to_b64_string(encrypted_recovery_data)
        return PayloadBuilder._wrap_payload(1, 3, "recovery_shares", client_id, {"recovery_payload": b64_recovery})