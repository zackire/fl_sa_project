import json
import logging
import base64
from crypto.interface import CryptoInterface
from fl_core.fedavg_logic import local_fit

# Importing only the ML prep and dimensionality adapters from our utils
from secure_aggregation.flower_secagg_utils import quantize, flatten_ndarrays_to_list, get_model_dimensions
from communication.payload_builder import PayloadBuilder

class SecureAggregationClient:
    def __init__(self, client_id: str, crypto_stack: CryptoInterface, mqtt_handler, ml_model):
        self.client_id = client_id
        self.crypto = crypto_stack
        self.mqtt = mqtt_handler
        self.ml_model = ml_model
        
        # Network & Cryptographic State Memory
        self.public_keys = {}
        self.active_users = []
        self.shared_secrets = {} # Stores ECDH keys so we don't recompute them
        self.my_b_u_seed = None  # Stores the self-mask seed for Round 2
        
    def process_mqtt_message(self, topic: str, payload: str):
        data = json.loads(payload)
        try:
            if "round_0" in topic: self._execute_round_0(data)
            elif "round_1/broadcast" in topic: self._execute_round_1_distribute(data)
            elif "round_1/shares" in topic: self._execute_round_1_receive(data)
            elif "round_2" in topic: self._execute_round_2(data)
            elif "round_3" in topic: self._execute_round_3(data)
        except Exception as e:
            logging.error(f"[{self.client_id}] Security/Execution failure in {topic}: {e}")

    # ==========================================
    # ROUND 0: KEY GENERATION
    # ==========================================
    def _execute_round_0(self, data):
        """
        Triggered by server. Calls the stack to generate X25519 pairs.
        """
        if data.get("command") != "ignite_fl":
            return
            
        logging.info(f"[{self.client_id}] Received ignition trigger. Generating keys...")
        
        # 1. Crypto Stack Execution
        c_keys = self.crypto.generate_dh_encryption_keypair()
        s_keys = self.crypto.generate_dh_masking_keypair()
        
        # 2. Package and Publish (Base64 for JSON compatibility)
        pub_keys = {
            "cPK": base64.b64encode(c_keys["cPK"]).decode('utf-8'),
            "sPK": base64.b64encode(s_keys["sPK"]).decode('utf-8')
        }
        
        payload = PayloadBuilder.build_round_0_payload(pub_keys)
        topic = PayloadBuilder.build_topic(epoch=1, round_num=0, sender_id=self.client_id, is_broadcast=False)
        self.mqtt.publish(topic, payload)

    # ==========================================
    # ROUND 1: SHARED SECRETS & SHAMIR SHARES
    # ==========================================
    def _execute_round_1_distribute(self, data):
        """
        Triggered when server broadcasts all public keys. 
        Computes shared secrets and distributes encrypted shares.
        """
        if "all_public_keys" not in data or "t_threshold" not in data:
            return
            
        logging.info(f"[{self.client_id}] Registry received. Computing shared secrets and SSS...")
        
        # 1. Decode public keys into bytes
        self.public_keys = {
            cid: {
                "cPK": base64.b64decode(keys["cPK"]), 
                "sPK": base64.b64decode(keys["sPK"])
            }
            for cid, keys in data['all_public_keys'].items()
        }
        self.active_users = list(self.public_keys.keys())
        threshold = data['t_threshold']
        total_shares = len(self.active_users)
        
        # 2. Crypto Stack Executions (Saving outputs to Orchestrator memory)
        self.shared_secrets = self.crypto.compute_shared_secrets(self.public_keys)
        self.my_b_u_seed = self.crypto.generate_self_mask_seed()
        shamir_shares = self.crypto.generate_shamir_shares(threshold, total_shares)
        
        # 3. Encrypt Shares for Routing (ASCON/GIFT-COFB)
        encrypted_shares_to_distribute = {}
        for idx, target_id in enumerate(self.active_users):
            if target_id == self.client_id: continue
            
            # Extract the specific share tuple for this target
            b_u_share = shamir_shares["b_u"][idx][1]
            s_sk_share = shamir_shares["s_sk"][idx][1]
            c_uv_key = self.shared_secrets[target_id]["c_uv"]
            
            ciphertext = self.crypto.encrypt_shares_for_routing(target_id, b_u_share, s_sk_share, c_uv_key)
            encrypted_shares_to_distribute[target_id] = base64.b64encode(ciphertext).decode('utf-8')
            
        payload = PayloadBuilder.build_round_1_payload(encrypted_shares_to_distribute)
        topic = PayloadBuilder.build_topic(epoch=1, round_num=1, sender_id=self.client_id, is_broadcast=False)
        self.mqtt.publish(topic, payload)

    def _execute_round_1_receive(self, data):
        """
        Triggered when receiving encrypted shares from peers via MQTT.
        """
        source_id = data.get("source_id")
        ciphertext = base64.b64decode(data.get("ciphertext"))
        
        # Fetch the pre-computed ASCON key from memory
        c_uv_key = self.shared_secrets[source_id]["c_uv"] 
        
        # 1. Crypto Stack Execution: Decrypt and hold inside the stack's internal memory
        self.crypto.decrypt_incoming_shares(source_id, ciphertext, c_uv_key)
        logging.info(f"[{self.client_id}] Successfully decrypted incoming shares from {source_id}.")

    # ==========================================
    # ROUND 2: MASKED INPUT GENERATION
    # ==========================================
    def _execute_round_2(self, data):
        """
        Trains model, flattens weights, computes masks, and returns Y_u.
        """
        if "global_weights" not in data:
            return
            
        logging.info(f"[{self.client_id}] Received global model. Starting local fit and masking...")
        
        # 1. ML Logic
        delta_w, _ = local_fit(self.ml_model, data['global_weights'], data.get('X_train', []), data.get('y_train', []))
        
        # 2. Preparation (Flower Utils)
        quantized_w = quantize(delta_w, clipping_range=10.0, target_range=2**24)
        flat_weights = flatten_ndarrays_to_list(quantized_w)
        mask_length = len(flat_weights)
        
        # 3. Crypto Stack Executions (PRG Expansions)
        s_uv_seeds = {cid: secrets["s_uv"] for cid, secrets in self.shared_secrets.items() if cid != self.client_id}
        
        # Pass the memory-stored seed back into the interface
        b_u_vector = self.crypto.generate_self_mask(self.my_b_u_seed, mask_length)
        pairwise_masks = self.crypto.generate_pairwise_masks(s_uv_seeds, mask_length)
        
        # 4. Final Aggregation Math
        y_u = self.crypto.compute_masked_input(flat_weights, b_u_vector, pairwise_masks, self.active_users)
        
        payload = PayloadBuilder.build_round_2_payload(y_u) 
        topic = PayloadBuilder.build_topic(epoch=1, round_num=2, sender_id=self.client_id, is_broadcast=False)
        self.mqtt.publish(topic, payload)

    # ==========================================
    # ROUND 3: UNMASKING / DROPOUT RECOVERY
    # ==========================================
    def _execute_round_3(self, data):
        """
        Server requests unmasking shares. Strict access control applied.
        """
        if "surviving_clients" not in data:
            return
            
        logging.info(f"[{self.client_id}] Received unmasking request. Evaluating protocol rules...")
        surviving_users = data['surviving_clients']
        dropped_users = [user for user in self.active_users if user not in surviving_users]
        
        # 1. Crypto Stack Execution: Strict Security Gates
        b_u_shares = self.crypto.provide_survivor_b_u_shares(surviving_users, dropped_users_check=dropped_users)
        s_sk_shares = self.crypto.provide_dropped_s_sk_shares(dropped_users, surviving_users_check=surviving_users)
        
        # 2. Package and Publish (Base64 encode the byte shares)
        recovery_payload = {
            "b_u_shares": {cid: base64.b64encode(share).decode('utf-8') for cid, share in b_u_shares.items()},
            "s_sk_shares": {cid: base64.b64encode(share).decode('utf-8') for cid, share in s_sk_shares.items()}
        }
        
        payload = PayloadBuilder.build_round_3_payload(recovery_payload)
        topic = PayloadBuilder.build_topic(epoch=1, round_num=3, sender_id=self.client_id, is_broadcast=False)
        self.mqtt.publish(topic, payload)