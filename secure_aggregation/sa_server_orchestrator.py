import json
import logging
import base64
from typing import List, Dict

# Machine Learning Logic
from fl_core.fedavg_logic import aggregate

# Cryptography & Utilities
from crypto.interface import CryptoInterface
from cryptography.hazmat.primitives.asymmetric import x25519 # Required to re-derive dropped secrets
from secure_aggregation.flower_secagg_utils import combine_shares, dequantize, reshape_list_to_ndarrays
from communication.payload_builder import PayloadBuilder

class SecureAggregationServer:
    def __init__(self, mqtt_handler, t_threshold: int, expected_k: int, crypto_stack: CryptoInterface, model_dimensions):
        self.mqtt = mqtt_handler
        self.t_threshold = t_threshold
        self.expected_k = expected_k
        self.crypto = crypto_stack 
        self.model_dimensions = model_dimensions # Required to reshape the final sum
        
        # Network & Protocol State
        self.active_clients = set()
        self.surviving_clients = set()
        self.public_keys_registry = {}
        
        # Round 2 & 3 Data Pools
        self._known_mask_length = None 
        self.y_u_payloads: Dict[str, List[float]] = {}
        self.b_u_shares_pool: Dict[str, List[bytes]] = {}
        self.s_sk_shares_pool: Dict[str, List[bytes]] = {}

    def process_mqtt_message(self, topic: str, payload: str):
        data = json.loads(payload)
        
        try:
            client_id = topic.split('/')[-2]
            
            if "round_0" in topic: self._execute_round_0(client_id, data)
            elif "round_1" in topic: self._execute_round_1(client_id, data)
            elif "round_2" in topic: self._execute_round_2(client_id, data)
            elif "round_3" in topic: self._execute_round_3(client_id, data)
        except Exception as e:
            logging.error(f"[Server] Execution failure for topic {topic}: {e}")

    # ==========================================
    # ROUND 0: REGISTRY COLLECTION
    # ==========================================
    def _execute_round_0(self, client_id: str, data: dict):
        if "public_keys" not in data:
            return
            
        self.public_keys_registry[client_id] = data["public_keys"]
        self.active_clients.add(client_id)
        
        logging.info(f"[Server] Received keys from {client_id}. ({len(self.active_clients)}/{self.expected_k})")
        
        if len(self.active_clients) == self.expected_k:
            logging.info(f"[Server] Quorum reached. Broadcasting public keys registry for Round 1...")
            payload = json.dumps({
                "all_public_keys": self.public_keys_registry, 
                "t_threshold": self.t_threshold
            })
            topic = PayloadBuilder.build_topic(epoch=1, round_num=1, sender_id="server", is_broadcast=True)
            self.mqtt.publish(topic, payload)

    # ==========================================
    # ROUND 1: THE POSTMASTER (ROUTING SHARES)
    # ==========================================
    def _execute_round_1(self, source_client_id: str, data: dict):
        if "encrypted_shares" not in data:
            return
            
        encrypted_shares = data["encrypted_shares"]
        
        for target_client_id, ciphertext_b64 in encrypted_shares.items():
            routed_payload = json.dumps({
                "source_id": source_client_id,
                "ciphertext": ciphertext_b64
            })
            topic = f"ci_fl/epoch_1/round_1/shares/{target_client_id}"
            self.mqtt.publish(topic, routed_payload)
            
        # Simplified trigger logic for Round 2
        if len(self.active_clients) == self.expected_k: 
            self._trigger_round_2()

    def _trigger_round_2(self):
        logging.info(f"[Server] Share routing complete. Initiating Round 2 (Training)...")
        payload = json.dumps({"global_weights": [], "X_train": [], "y_train": []})
        topic = PayloadBuilder.build_topic(epoch=1, round_num=2, sender_id="server", is_broadcast=True)
        self.mqtt.publish(topic, payload)

    # ==========================================
    # ROUND 2: MASKED INPUT COLLECTION
    # ==========================================
    def _execute_round_2(self, client_id: str, data: dict):
        if "masked_weights" not in data:
            return
            
        self.y_u_payloads[client_id] = data['masked_weights']
        self.surviving_clients.add(client_id)
        
        if self._known_mask_length is None:
            self._known_mask_length = data.get('mask_length', len(data['masked_weights']))
        
        if len(self.surviving_clients) >= self.t_threshold:
            self._trigger_round_3()

    def _trigger_round_3(self):
        logging.info(f"[Server] Round 2 complete. {len(self.surviving_clients)} survivors. Requesting recovery shares...")
        payload = json.dumps({"surviving_clients": list(self.surviving_clients)})
        topic = PayloadBuilder.build_topic(epoch=1, round_num=3, sender_id="server", is_broadcast=True)
        self.mqtt.publish(topic, payload)

    # ==========================================
    # ROUND 3: UNMASKING & DROPOUT RECOVERY
    # ==========================================
    def _execute_round_3(self, client_id: str, data: dict):
        if "recovery_payload" not in data:
            return
            
        recovery_payload = data["recovery_payload"]
        
        for target_id, b64_share in recovery_payload.get("b_u_shares", {}).items():
            self.b_u_shares_pool.setdefault(target_id, []).append(base64.b64decode(b64_share))
            
        for target_id, b64_share in recovery_payload.get("s_sk_shares", {}).items():
            self.s_sk_shares_pool.setdefault(target_id, []).append(base64.b64decode(b64_share))
            
        if len(self.b_u_shares_pool) >= len(self.surviving_clients): 
            self._finalize_aggregation()

    def _finalize_aggregation(self):
        logging.info("[Server] Threshold reached. Executing final unmasking cryptography...")
        
        # 1. Sum all received Y_u vectors
        final_sum = [sum(x) for x in zip(*self.y_u_payloads.values())]
        
        # 2. Cancel Survivor Self-Masks (b_u)
        
        for survivor_id in self.surviving_clients:
            shares = self.b_u_shares_pool[survivor_id][:self.t_threshold]
            b_u_seed = combine_shares(shares)
            b_u_vector = self.crypto.generate_self_mask(b_u_seed, self._known_mask_length)
            final_sum = [y - b for y, b in zip(final_sum, b_u_vector)]

        # 3. Cancel Dropped Client Pairwise Masks
        dropped_clients = self.active_clients - self.surviving_clients
        for dropped_id in dropped_clients:
            shares = self.s_sk_shares_pool[dropped_id][:self.t_threshold]
            s_sk_bytes = combine_shares(shares)
            dropped_sSK = x25519.X25519PrivateKey.from_private_bytes(s_sk_bytes)
            
            dropped_shared_seeds = {}
            for survivor_id in self.surviving_clients:
                survivor_sPK_bytes = base64.b64decode(self.public_keys_registry[survivor_id]["sPK"])
                survivor_sPK = x25519.X25519PublicKey.from_public_bytes(survivor_sPK_bytes)
                dropped_shared_seeds[survivor_id] = dropped_sSK.exchange(survivor_sPK)
            
            pairwise_masks = self.crypto.generate_pairwise_masks(dropped_shared_seeds, self._known_mask_length)
            
            for survivor_id, mask_vector in pairwise_masks.items():
                sign = 1 if dropped_id > survivor_id else -1
                final_sum = [y - (sign * m) for y, m in zip(final_sum, mask_vector)]
                
        logging.info("[Server] Cryptographic Unmasking Complete. Passing to FL Logic...")
        
        # 4. Translation & Machine Learning Hand-off
        dequantized_flat_sum = dequantize([final_sum], clipping_range=10.0, target_range=2**24)[0]
        final_model_ndarrays = reshape_list_to_ndarrays(dequantized_flat_sum, self.model_dimensions)
        
        # Average and apply via FedAvg (UPDATED LINE)
        new_global_weights = aggregate(final_model_ndarrays, len(self.surviving_clients))
        
        logging.info("[Server] Global model successfully updated.")