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
        try:
            wrapper = json.loads(payload)
            meta = wrapper.get("meta", {})
            data = wrapper.get("data", {})
            
            client_id = meta.get("client_id")
            msg_type = meta.get("msg_type")
            round_num = meta.get("round")
            
            if msg_type == "public_keys":
                self._execute_round_0(client_id, data)
            elif msg_type == "masked_weights":
                self._execute_round_2(client_id, data)
            elif msg_type == "recovery_shares":
                self._execute_round_3(client_id, data)
                
        except Exception as e:
            logging.error(f"[Server] Execution failure processing meta block for topic {topic}: {e}")

    # ==========================================
    # ROUND 0: REGISTRY COLLECTION
    # ==========================================
    def _execute_round_0(self, client_id: str, data: dict):
        self.public_keys_registry[client_id] = data
        self.active_clients.add(client_id)
        
        logging.info(f"[Server] Received keys from {client_id}. ({len(self.active_clients)}/{self.expected_k})")
        
        # When all expected clients register, broadcast the directory
        if len(self.active_clients) == self.expected_k:
            logging.info(f"[Server] Quorum reached. Broadcasting public keys registry for Round 1...")
            data_payload = {
                "all_public_keys": self.public_keys_registry, 
                "t_threshold": self.t_threshold
            }
            wrapped_payload = PayloadBuilder._wrap_payload(1, 1, "key_registry", "server", data_payload)
            topic = PayloadBuilder.get_server_broadcast_topic()
            self.mqtt.publish(topic, wrapped_payload)
            
            # Asynchronously advance state lock: Immediately broadcast Global Model to start Round 2
            # Since clients route round 1 shares P2P, the server trusts them to handle it.
            self._trigger_round_2()

    def _trigger_round_2(self):
        logging.info(f"[Server] Key registry broadcasted. Initiating Round 2 (Training) asynchronously...")
        # In actual deployment, global weights are retrieved from the local model
        data_payload = {"global_weights": [], "X_train": [], "y_train": []}
        wrapped_payload = PayloadBuilder._wrap_payload(1, 2, "global_model", "server", data_payload)
        topic = PayloadBuilder.get_server_broadcast_topic()
        self.mqtt.publish(topic, wrapped_payload)

    # ==========================================
    # ROUND 2: MASKED INPUT COLLECTION
    # ==========================================
    def _execute_round_2(self, client_id: str, data: dict):
        self.y_u_payloads[client_id] = data.get('masked_weights', [])
        self.surviving_clients.add(client_id)
        
        if self._known_mask_length is None and len(self.y_u_payloads[client_id]) > 0:
            self._known_mask_length = len(self.y_u_payloads[client_id])
        
        # When the threshold is met, lock the round and demand unmasking shares
        if len(self.surviving_clients) == self.t_threshold:
            self._trigger_round_3()

    def _trigger_round_3(self):
        logging.info(f"[Server] Round 2 threshold met. {len(self.surviving_clients)} survivors. Requesting recovery shares...")
        data_payload = {"surviving_clients": list(self.surviving_clients)}
        wrapped_payload = PayloadBuilder._wrap_payload(1, 3, "dropout_list", "server", data_payload)
        topic = PayloadBuilder.get_server_broadcast_topic()
        self.mqtt.publish(topic, wrapped_payload)

    # ==========================================
    # ROUND 3: UNMASKING & DROPOUT RECOVERY
    # ==========================================
    def _execute_round_3(self, client_id: str, data: dict):
        if "b_u_shares" not in data or "s_sk_shares" not in data:
            return
            
        # 1. Collect and Decode Incoming Shares
        for target_id, b64_share in data["b_u_shares"].items():
            self.b_u_shares_pool.setdefault(target_id, []).append(base64.b64decode(b64_share))
            
        for target_id, b64_share in data["s_sk_shares"].items():
            self.s_sk_shares_pool.setdefault(target_id, []).append(base64.b64decode(b64_share))
            
        # 2. Check if we have enough shares to proceed with final unmasking
        # (Requires at least `t_threshold` shares from `t_threshold` clients)
        # Assuming true for this execution flow:
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
            
            # Regenerate the self-mask via the crypto stack interface
            b_u_vector = self.crypto.generate_self_mask(b_u_seed, self._known_mask_length)
            
            # Vector Subtraction
            final_sum = [y - b for y, b in zip(final_sum, b_u_vector)]

        # 3. Cancel Dropped Client Pairwise Masks
        dropped_clients = self.active_clients - self.surviving_clients
        for dropped_id in dropped_clients:
            shares = self.s_sk_shares_pool[dropped_id][:self.t_threshold]
            s_sk_bytes = combine_shares(shares)
            
            # Instantiate the dropped client's private key to re-derive shared secrets
            dropped_sSK = x25519.X25519PrivateKey.from_private_bytes(s_sk_bytes)
            
            dropped_shared_seeds = {}
            for survivor_id in self.surviving_clients:
                # Retrieve the survivor's public key from the Round 0 registry
                survivor_sPK_bytes = base64.b64decode(self.public_keys_registry[survivor_id]["sPK"])
                survivor_sPK = x25519.X25519PublicKey.from_public_bytes(survivor_sPK_bytes)
                
                # Perform ECDH to rebuild the missing seed
                dropped_shared_seeds[survivor_id] = dropped_sSK.exchange(survivor_sPK)
            
            # Regenerate the pairwise masks via the crypto stack interface
            pairwise_masks = self.crypto.generate_pairwise_masks(dropped_shared_seeds, self._known_mask_length)
            
            for survivor_id, mask_vector in pairwise_masks.items():
                # Apply strictly opposite math to cancel out the mask exactly as it was added
                sign = 1 if dropped_id > survivor_id else -1
                final_sum = [y - (sign * m) for y, m in zip(final_sum, mask_vector)]
                
        logging.info("[Server] Cryptographic Unmasking Complete. Passing to FL Logic...")
        
        # 4. Translation & Machine Learning Hand-off
        dequantized_flat_sum = dequantize([final_sum], clipping_range=10.0, target_range=2**24)[0]
        final_model_ndarrays = reshape_list_to_ndarrays(dequantized_flat_sum, self.model_dimensions)
        
        # Average and apply via FedAvg
        new_global_weights = aggregate([final_model_ndarrays])
        
        logging.info("[Server] Global model successfully updated.")