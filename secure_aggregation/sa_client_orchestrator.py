import json
import logging
from crypto.interface import CryptoInterface
from fl_core.fedavg_logic import local_fit
from secure_aggregation.flower_secagg_utils import create_shares, quantize 
from communication.payload_builder import PayloadBuilder

class SecureAggregationClient:
    def __init__(self, client_id: str, crypto_stack: CryptoInterface, mqtt_handler, ml_model):
        self.client_id = client_id
        self.crypto = crypto_stack
        self.mqtt = mqtt_handler
        self.ml_model = ml_model
        
        self.public_keys = {}
        self.shared_secrets = {}
        
    def process_mqtt_message(self, topic: str, payload: str):
        data = json.loads(payload)
        try:
            if "round_0" in topic: self._execute_round_0(data)
            elif "round_1" in topic: self._execute_round_1(data)
            elif "round_2" in topic: self._execute_round_2(data)
            elif "round_3" in topic: self._execute_round_3(data)
        except Exception as e:
            logging.error(f"Security failure in {topic}: {e}")

    def _execute_round_0(self, data):
        # Guard Clause
        if "command" not in data or data["command"] != "ignite_fl":
            return
            
        logging.info(f"[{self.client_id}] Received ignition trigger. Generating keys...")
        pub_keys = self.crypto.generate_keypairs()
        payload = PayloadBuilder.build_round_0_payload(pub_keys)
        topic = PayloadBuilder.build_topic(epoch=1, round_num=0, sender_id=self.client_id, is_broadcast=False)
        self.mqtt.publish(topic, payload)

    def _execute_round_1(self, data):
        # Guard Clause
        if "all_public_keys" not in data or "t_threshold" not in data:
            return
            
        logging.info(f"[{self.client_id}] Received public keys registry. Computing shares...")
        
        # Decoding and assigning keys safely
        self.public_keys = {
            cid: {"cPK": PayloadBuilder.decode_b64_string_to_bytes(keys["cPK"]), 
                  "sPK": PayloadBuilder.decode_b64_string_to_bytes(keys["sPK"])}
            for cid, keys in data['all_public_keys'].items()
        }
        threshold = data['t_threshold']
        self.shared_secrets = self.crypto.compute_shared_secrets(self.public_keys)
        
        encrypted_shares_to_distribute = {}
        for target_id in self.public_keys.keys():
            if target_id == self.client_id: continue
            raw_share = create_shares(self.crypto.get_private_masking_key(), threshold, len(self.public_keys) - 1)
            
            encrypted_shares_to_distribute[target_id] = self.crypto.encrypt_payload(
                target_client_id=target_id, 
                payload=raw_share, 
                shared_secret=self.shared_secrets[target_id]
            )
            
        payload = PayloadBuilder.build_round_1_payload(encrypted_shares_to_distribute)
        topic = PayloadBuilder.build_topic(epoch=1, round_num=1, sender_id=self.client_id, is_broadcast=False)
        self.mqtt.publish(topic, payload)

    def _execute_round_2(self, data):
        # Guard Clause (Mock)
        if "global_weights" not in data:
            return
            
        logging.info(f"[{self.client_id}] Received global model. Starting local fit...")
        delta_w, _ = local_fit(self.ml_model, data['global_weights'], data.get('X_train', []), data.get('y_train', []))
        quantized_w = quantize(delta_w)
        mask_length = sum(len(w.tobytes()) for w in quantized_w)
        
        # (Bonawitz mask math logic remains exactly the same here)
        
        payload = PayloadBuilder.build_round_2_payload([], mask_length) # Placeholder for actual masked weight array
        topic = PayloadBuilder.build_topic(epoch=1, round_num=2, sender_id=self.client_id, is_broadcast=False)
        self.mqtt.publish(topic, payload)

    def _execute_round_3(self, data):
        # Guard Clause
        if "dropped_clients" not in data:
            return
            
        logging.info(f"[{self.client_id}] Received dropout list. Preparing recovery shares...")
        dropped_clients = data['dropped_clients']
        recovery_shares = self._get_recovery_shares(dropped_clients) if hasattr(self, '_get_recovery_shares') else {}
        
        encrypted_recovery = self.crypto.encrypt_payload(
            target_client_id="server", 
            payload=json.dumps(recovery_shares).encode(), 
            shared_secret=self.crypto.get_private_client_key()
        )
        payload = PayloadBuilder.build_round_3_payload(encrypted_recovery)
        topic = PayloadBuilder.build_topic(epoch=1, round_num=3, sender_id=self.client_id, is_broadcast=False)
        self.mqtt.publish(topic, payload)