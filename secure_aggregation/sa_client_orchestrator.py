import json
import logging
import base64
import time
import numpy as np
from crypto.interface import CryptoInterface

from secure_aggregation.flower_secagg_utils import quantize, flatten_ndarrays_to_list
from communication.payload_builder import PayloadBuilder


class SecureAggregationClient:
    def __init__(self, client_id: str, crypto_stack: CryptoInterface, mqtt_handler, ml_model,
                 metrics=None):
        self.client_id = client_id
        self.crypto    = crypto_stack
        self.mqtt      = mqtt_handler
        self.ml_model  = ml_model
        self.metrics   = metrics          # MetricsCollector | None
        self.round_number = 1

        # Cryptographic state
        self.public_keys        = {}
        self.active_users       = []
        self.shared_secrets     = {}
        self.my_b_u_seed        = None

        # Async coordination
        self.received_shares_from = set()
        self.pending_global_model = None

    # ---------------------------------------------------------------------- #
    #  MQTT dispatch                                                          #
    # ---------------------------------------------------------------------- #

    def process_mqtt_message(self, topic: str, payload: str):
        json_payload = json.loads(payload)
        meta     = json_payload.get("meta", {})
        data     = json_payload.get("data", {})
        msg_type = meta.get("msg_type")

        try:
            if msg_type == "ignition":
                self._execute_round_0(data)
            elif msg_type == "key_registry":
                self._execute_round_1_distribute(data)
            elif msg_type == "secret_shares":
                self._execute_round_1_receive(data, meta)
            elif msg_type == "global_model":
                self._execute_round_2(data)
            elif msg_type == "dropout_list":
                self._execute_round_3(data)
        except Exception as e:
            logging.error(f"[{self.client_id}] Error handling '{msg_type}': {e}", exc_info=True)

    # ---------------------------------------------------------------------- #
    #  ROUND 0 — Key generation                                              #
    # ---------------------------------------------------------------------- #

    def _execute_round_0(self, data):
        if data.get("command") != "ignite_fl":
            return

        self.received_shares_from.clear()
        _section_header(self.client_id, "ROUND 0 — KEY GENERATION")

        # Metrics: start the measurement window at the very beginning of the round
        if self.metrics:
            self.metrics.round_start(self.round_number)
            logging.info(
                f"[Metrics][{self.client_id}] Round {self.round_number} measurement started (R0 ignition)"
            )

        c_keys = self.crypto.generate_dh_encryption_keypair()
        s_keys = self.crypto.generate_dh_masking_keypair()

        pub_keys = {
            "cPK": base64.b64encode(c_keys["cPK"]).decode("utf-8"),
            "sPK": base64.b64encode(s_keys["sPK"]).decode("utf-8"),
        }

        payload = PayloadBuilder.build_round_0_payload(self.client_id, pub_keys)
        self._publish(PayloadBuilder.get_server_dropbox_topic(self.client_id), payload)
        logging.info(f"[{self.client_id}] DH keypairs generated. Public keys sent to server.")

    # ---------------------------------------------------------------------- #
    #  ROUND 1 — Shamir share distribution                                   #
    # ---------------------------------------------------------------------- #

    def _execute_round_1_distribute(self, data):
        if "all_public_keys" not in data or "t_threshold" not in data:
            return

        # Verify the server is running the same crypto stack before doing anything
        server_stack_id = data.get("stack_id")
        my_stack_id     = getattr(self.crypto, "STACK_ID", None)
        if server_stack_id and my_stack_id and server_stack_id != my_stack_id:
            logging.error(
                f"[{self.client_id}] STACK MISMATCH — server is Stack {server_stack_id}, "
                f"this client is Stack {my_stack_id}. Aborting round."
            )
            return

        _section_header(self.client_id, "ROUND 1 — SHARE DISTRIBUTION")

        self.public_keys = {
            cid: {
                "cPK": base64.b64decode(keys["cPK"]),
                "sPK": base64.b64decode(keys["sPK"]),
            }
            for cid, keys in data["all_public_keys"].items()
        }
        self.active_users = list(self.public_keys.keys())
        threshold    = data["t_threshold"]
        total_shares = len(self.active_users)

        logging.info(
            f"[{self.client_id}] Active users: {self.active_users}  |  "
            f"threshold: {threshold}/{total_shares}"
        )

        self.shared_secrets = self.crypto.compute_shared_secrets(self.public_keys)
        self.my_b_u_seed    = self.crypto.generate_self_mask_seed()
        shamir_shares       = self.crypto.generate_shamir_shares(threshold, total_shares)

        encrypted_shares_payload = {}
        for idx, target_id in enumerate(self.active_users):
            if target_id == self.client_id:
                continue
            b_u_share  = shamir_shares["b_u"][idx][1]
            s_sk_share = shamir_shares["s_sk"][idx][1]
            c_uv_key   = self.shared_secrets[target_id]["c_uv"]
            ciphertext = self.crypto.encrypt_shares_for_routing(target_id, b_u_share, s_sk_share, c_uv_key)
            encrypted_shares_payload[target_id] = base64.b64encode(ciphertext).decode("utf-8")

        payload = PayloadBuilder.build_round_1_payload(self.client_id, encrypted_shares_payload)
        self._publish(PayloadBuilder.get_server_dropbox_topic(self.client_id), payload)
        logging.info(
            f"[{self.client_id}] Encrypted Shamir shares sent to server for routing  "
            f"→  {list(encrypted_shares_payload.keys())}"
        )

    def _execute_round_1_receive(self, data, meta):
        source_id  = meta.get("client_id")
        b64_cipher = data.get("encrypted_shares", {}).get(self.client_id)
        if not b64_cipher:
            return

        ciphertext = base64.b64decode(b64_cipher)
        c_uv_key   = self.shared_secrets[source_id]["c_uv"]
        self.crypto.decrypt_incoming_shares(source_id, ciphertext, c_uv_key)
        self.received_shares_from.add(source_id)

        logging.info(
            f"[{self.client_id}] Share received and decrypted from {source_id}  "
            f"({len(self.received_shares_from)}/{len(self.active_users) - 1})"
        )
        self._check_and_execute_round_2()

    # ---------------------------------------------------------------------- #
    #  ROUND 2 — Masked input generation                                     #
    # ---------------------------------------------------------------------- #

    def _execute_round_2(self, data):
        if "global_weights" not in data:
            return
        self.pending_global_model = data
        self._check_and_execute_round_2()

    def _check_and_execute_round_2(self):
        if self.pending_global_model is None:
            return
        if len(self.received_shares_from) < len(self.active_users) - 1:
            return

        _section_header(self.client_id, "ROUND 2 — MASKED INPUT GENERATION")
        data = self.pending_global_model
        self.pending_global_model = None

        # Step 1 — Update local model with global weights (if any)
        global_weights_raw = data.get("global_weights", [])
        if global_weights_raw:
            global_weights = [np.array(w) for w in global_weights_raw]
            logging.info(f"[{self.client_id}] Global model received from server.")
            _log_weights(self.client_id, global_weights, label="Global model")
            self.ml_model.set_weights(global_weights)
        else:
            logging.info(f"[{self.client_id}] No global model yet — using local init weights.")

        # Step 2 — Get local weights
        time.sleep(2)
        local_weights = self.ml_model.get_weights()
        _log_weights(self.client_id, local_weights, label="Local weights (plaintext)")

        # Step 3 — Quantize and flatten
        quantized_w = quantize(local_weights, clipping_range=10.0, target_range=2**24)
        flat_weights = flatten_ndarrays_to_list(quantized_w)
        mask_length  = len(flat_weights)
        logging.info(f"[{self.client_id}] Weights quantized and flattened  →  {mask_length} integers.")

        # Step 4 — Generate masks and compute Y_u
        s_uv_seeds     = {cid: s["s_uv"] for cid, s in self.shared_secrets.items() if cid != self.client_id}
        b_u_vector     = self.crypto.generate_self_mask(self.my_b_u_seed, mask_length)
        pairwise_masks = self.crypto.generate_pairwise_masks(s_uv_seeds, mask_length)

        y_u = self.crypto.compute_masked_input(flat_weights, b_u_vector, pairwise_masks, self.active_users)

        logging.info(f"[{self.client_id}] Masks applied. Sending masked weights to server.")

        payload = PayloadBuilder.build_round_2_payload(self.client_id, y_u, mask_length)
        self._publish(PayloadBuilder.get_server_dropbox_topic(self.client_id), payload)
        logging.info(f"[{self.client_id}] Masked input Y_u published ✓")

    # ---------------------------------------------------------------------- #
    #  ROUND 3 — Unmasking / dropout recovery                               #
    # ---------------------------------------------------------------------- #

    def _execute_round_3(self, data):
        if "surviving_clients" not in data:
            return

        _section_header(self.client_id, "ROUND 3 — UNMASKING")
        surviving_users = data["surviving_clients"]
        dropped_users   = [u for u in self.active_users if u not in surviving_users]
        logging.info(
            f"[{self.client_id}] Survivors: {surviving_users}  |  "
            f"Dropped: {dropped_users if dropped_users else 'none'}"
        )

        b_u_shares  = self.crypto.provide_survivor_b_u_shares(surviving_users, dropped_users_check=dropped_users)
        s_sk_shares = self.crypto.provide_dropped_s_sk_shares(dropped_users, surviving_users_check=surviving_users)

        recovery_payload = {
            "b_u_shares":  {cid: base64.b64encode(s).decode("utf-8") for cid, s in b_u_shares.items()},
            "s_sk_shares": {cid: base64.b64encode(s).decode("utf-8") for cid, s in s_sk_shares.items()},
        }

        payload = PayloadBuilder.build_round_3_payload(self.client_id, recovery_payload)
        self._publish(PayloadBuilder.get_server_dropbox_topic(self.client_id), payload)
        logging.info(f"[{self.client_id}] Recovery shares sent to server ✓")

        # Metrics: end the measurement window — client's last action this round
        if self.metrics:
            self.metrics.round_end(self.round_number)
            logging.info(
                f"[Metrics][{self.client_id}] Round {self.round_number} measurement ended (R3 done)"
            )
        self.round_number += 1

    # ---------------------------------------------------------------------- #
    #  MQTT publish wrapper (tracks bandwidth)                                #
    # ---------------------------------------------------------------------- #

    def _publish(self, topic: str, payload: str):
        if self.metrics:
            self.metrics.record_bytes(len(payload.encode("utf-8")))
        self.mqtt.publish(topic, payload)


# ---------------------------------------------------------------------- #
#  Shared logging helpers                                                 #
# ---------------------------------------------------------------------- #

def _log_weights(client_id: str, weights: list, label: str = "Weights"):
    component_labels = ["coef", "intercept"]
    logging.info(f"[{client_id}] {label}:")
    for i, w in enumerate(weights):
        lbl = component_labels[i] if i < len(component_labels) else f"component_{i}"
        logging.info(f"  [{lbl}]  {np.round(w, 6)}")


def _section_header(client_id: str, title: str):
    bar = "─" * 60
    logging.info(f"\n{bar}")
    logging.info(f"  [{client_id}] {title}")
    logging.info(f"{bar}")