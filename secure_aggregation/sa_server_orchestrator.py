import json
import logging
from crypto.interface import CryptoInterface
from fl_core.fedavg_logic import aggregate
from secure_aggregation.flower_secagg_utils import combine_shares, dequantize
from communication.payload_builder import PayloadBuilder

class SecureAggregationServer:
    def __init__(self, mqtt_handler, t_threshold: int, expected_k: int, crypto_stack: CryptoInterface):
        self.mqtt = mqtt_handler
        self.t_threshold = t_threshold
        self.expected_k = expected_k
        self.crypto = crypto_stack 
        
        self.active_clients = set()
        self.public_keys_registry = {}
        self.encrypted_shares_routing_table = {}
        self.masked_weights_pool = []
        self.surviving_clients = set()
        
        self._known_mask_length = None 

    def process_mqtt_message(self, topic: str, payload: str):
        data = json.loads(payload)
        
        # Topic structure is ci_fl/epoch/round/client_id/target (tx/broadcast)
        # Therefore, client_id is at index -2, not -1
        try:
            client_id = topic.split('/')[-2]
            
            if "round_0" in topic: self._execute_round_0(client_id, data)
            elif "round_1" in topic: self._execute_round_1(client_id, data)
            elif "round_2" in topic: self._execute_round_2(client_id, data)
            elif "round_3" in topic: self._execute_round_3(client_id, data)
        except Exception as e:
            logging.error(f"Server-side execution failure for topic {topic}: {e}")

    def _execute_round_0(self, client_id, data):
        # Guard Clause: Ensuring public keys exist in the payload
        if "public_keys" not in data:
            return
            
        # Store only the keys dictionary, bypassing the 'public_keys' wrapper
        self.public_keys_registry[client_id] = data["public_keys"]
        self.active_clients.add(client_id)
        
        logging.info(f"[Server] Received public keys from {client_id}. Expected: {len(self.public_keys_registry)}/{self.expected_k}")
        if len(self.public_keys_registry) == self.expected_k:
            logging.info(f"[Server] Broadcasting public keys registry for Round 1...")
            payload = json.dumps({"all_public_keys": self.public_keys_registry, "t_threshold": self.t_threshold})
            # Broadcast topic for Round 1
            topic = PayloadBuilder.build_topic(epoch=1, round_num=1, sender_id="server", is_broadcast=True)
            self.mqtt.publish(topic, payload)

    def _execute_round_1(self, client_id, data):
        # Guard Clause
        if "encrypted_shares" not in data:
            return
            
        self.encrypted_shares_routing_table[client_id] = data["encrypted_shares"]
        
        if len(self.encrypted_shares_routing_table) == self.expected_k:
            logging.info(f"[Server] Generating round 2 routing tables...")
            for target_client in self.active_clients:
                # Placeholder for active routing table generation logic
                payload = {"global_weights": [], "X_train": [], "y_train": []}
                # Uniquely identifiable transmit topic
                topic = PayloadBuilder.build_topic(epoch=1, round_num=2, sender_id=target_client, is_broadcast=False)
                self.mqtt.publish(topic, json.dumps(payload))

    def _execute_round_2(self, client_id, data):
        # Guard Clause
        if "masked_weights" not in data or "mask_length" not in data:
            return
            
        self.masked_weights_pool.append(data['masked_weights'])
        self.surviving_clients.add(client_id)
        
        if self._known_mask_length is None:
            self._known_mask_length = data['mask_length']
        
        if len(self.surviving_clients) >= self.t_threshold:
            dropped_clients = self.active_clients - self.surviving_clients
            payload = {"dropped_clients": list(dropped_clients)}
            topic = PayloadBuilder.build_topic(epoch=1, round_num=3, sender_id="server", is_broadcast=True)
            self.mqtt.publish(topic, json.dumps(payload))

    def _execute_round_3(self, client_id, data):
        # Guard Clause
        if "recovery_payload" not in data:
            return
            
        if hasattr(self, '_store_recovery_shares'):
            self._store_recovery_shares(data['recovery_payload'])
            
        if hasattr(self, '_have_enough_shares') and self._have_enough_shares(self.t_threshold):
            recovered_keys = self._reconstruct_keys() if hasattr(self, '_reconstruct_keys') else []
            
            reconstructed_masks = []
            for r_key in recovered_keys:
                mask = self.crypto.generate_prg_mask(shared_secret=r_key, mask_length=self._known_mask_length)
                reconstructed_masks.append(mask)
            
            self.mqtt.publish("ci_fl/baseline/global_model/tx", "new_model_payload")