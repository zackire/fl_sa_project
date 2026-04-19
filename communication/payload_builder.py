import json
from typing import Dict, List

class PayloadBuilder:
    """
    Centralized utility for formatting MQTT topics and lightweight 
    JSON payloads for the CI Secure Aggregation testbed.
    """
    
    BASE_TOPIC = "ci_fl"

    @staticmethod
    def build_topic(epoch: int, round_num: int, sender_id: str, is_broadcast: bool = False) -> str:
        """
        Creates a highly descriptive MQTT topic for easy network monitoring.
        Example: ci_fl/epoch_1/round_1/client_1/tx
        """
        target = "broadcast" if is_broadcast else "tx"
        return f"{PayloadBuilder.BASE_TOPIC}/epoch_{epoch}/round_{round_num}/{sender_id}/{target}"

    @staticmethod
    def build_round_0_payload(public_keys: Dict[str, str]) -> str:
        """
        Expects a dictionary of base64-encoded keys from the Orchestrator.
        """
        return json.dumps({"public_keys": public_keys})

    @staticmethod
    def build_round_1_payload(encrypted_shares: Dict[str, str]) -> str:
        """
        Expects a dictionary of base64-encoded ASCON/GIFT ciphertexts.
        """
        return json.dumps({"encrypted_shares": encrypted_shares})

    @staticmethod
    def build_round_2_payload(masked_weights: List[float], mask_length: int = 0) -> str:
        """
        Packages the flat list of masked model weights.
        """
        return json.dumps({
            "masked_weights": masked_weights,
            "mask_length": mask_length
        })

    @staticmethod
    def build_round_3_payload(recovery_payload: Dict[str, Dict[str, str]]) -> str:
        """
        Expects the fully formatted, nested recovery dictionary from the Orchestrator,
        separating survivor b_u shares from dropped s_sk shares.
        """
        return json.dumps({"recovery_payload": recovery_payload})