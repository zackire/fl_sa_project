import json
import logging
import base64
import time
import threading
from typing import List, Dict
import numpy as np

from crypto.interface import CryptoInterface
from cryptography.hazmat.primitives.asymmetric import x25519
from secure_aggregation.flower_secagg_utils import (
    combine_shares, dequantize, reshape_list_to_ndarrays
)
from communication.payload_builder import PayloadBuilder


class SecureAggregationServer:
    def __init__(
        self,
        mqtt_handler,
        t_threshold: int,
        expected_k: int,
        crypto_stack: CryptoInterface,
        model_dimensions,
        metrics=None,
    ):
        self.mqtt             = mqtt_handler
        self.t_threshold      = t_threshold
        self.expected_k       = expected_k
        self.crypto           = crypto_stack
        self.stack_id         = getattr(crypto_stack, "STACK_ID", "A")
        self.model_dimensions = model_dimensions   # e.g. [(10,), (1,)]
        self.metrics          = metrics            # MetricsCollector | None
        self.round_number     = 1

        self.current_global_weights: List[np.ndarray] = []
        self._reset_state_pools()

    # ---------------------------------------------------------------------- #
    #  State reset                                                            #
    # ---------------------------------------------------------------------- #

    def _reset_state_pools(self):
        self.active_clients       = set()
        self.surviving_clients    = set()
        self.public_keys_registry = {}
        self._known_mask_length   = None
        self.y_u_payloads:     Dict[str, List[float]] = {}
        self.b_u_shares_pool:  Dict[str, List[bytes]] = {}
        self.s_sk_shares_pool: Dict[str, List[bytes]] = {}
        self.r1_received   = set()
        self.r3_received   = set()
        self.r2_triggered  = False
        self.r3_triggered  = False
        self.finalized     = False

    # ---------------------------------------------------------------------- #
    #  MQTT dispatch                                                          #
    # ---------------------------------------------------------------------- #

    def process_mqtt_message(self, topic: str, payload: str):
        full_payload = json.loads(payload)
        meta = full_payload.get("meta", {})
        data = full_payload.get("data", {})

        try:
            client_id = meta.get("client_id", topic.split("/")[-2])
            round_num = meta.get("round")

            if round_num == 0:   self._execute_round_0(client_id, data)
            elif round_num == 1: self._execute_round_1(client_id, data)
            elif round_num == 2: self._execute_round_2(client_id, data)
            elif round_num == 3: self._execute_round_3(client_id, data)
        except Exception as e:
            logging.error(f"[Server] Error on topic {topic}: {e}", exc_info=True)

    # ---------------------------------------------------------------------- #
    #  ROUND 0 — Collect public keys                                         #
    # ---------------------------------------------------------------------- #

    def _execute_round_0(self, client_id: str, data: dict):
        if "public_keys" not in data:
            return

        # Metrics: start the round clock when the FIRST public key arrives
        # so the measurement window covers all 4 SA phases:
        #   R0 collect public keys → R1 route encrypted shares
        #   → R2 collect masked inputs → R3 collect recovery shares
        if len(self.active_clients) == 0 and self.metrics:
            self.metrics.round_start(self.round_number)
            logging.info(
                f"[Metrics] Round {self.round_number} measurement started "
                f"(first public key from {client_id})"
            )

        self.public_keys_registry[client_id] = data["public_keys"]
        self.active_clients.add(client_id)
        logging.info(
            f"[Server] R0 — Public keys received from {client_id}  "
            f"({len(self.active_clients)}/{self.expected_k})"
        )

        if len(self.active_clients) == self.expected_k:
            logging.info(
                f"[Server] All public keys collected. Broadcasting key registry "
                f"(Stack {self.stack_id})..."
            )
            time.sleep(1)
            payload = json.dumps({
                "meta": {"msg_type": "key_registry", "round": 1},
                "data": {
                    "all_public_keys": self.public_keys_registry,
                    "t_threshold": self.t_threshold,
                    "stack_id": self.stack_id,
                },
            })
            self._publish(PayloadBuilder.get_server_broadcast_topic(), payload)

    # ---------------------------------------------------------------------- #
    #  ROUND 1 — Route encrypted shares                                      #
    # ---------------------------------------------------------------------- #

    def _execute_round_1(self, source_id: str, data: dict):
        if "encrypted_shares" not in data:
            return

        recipients = list(data["encrypted_shares"].keys())
        for target_id, ciphertext_b64 in data["encrypted_shares"].items():
            routed = PayloadBuilder.build_round_1_payload(source_id, {target_id: ciphertext_b64})
            self._publish(PayloadBuilder.get_client_inbox_topic(target_id), routed)

        logging.info(
            f"[Server] R1 — Shares from {source_id} routed  →  {recipients}"
        )
        self.r1_received.add(source_id)

        if len(self.r1_received) == self.expected_k and not self.r2_triggered:
            self.r2_triggered = True
            self._trigger_round_2()

    def _trigger_round_2(self):
        _section_header(f"ROUND {self.round_number} — BROADCASTING GLOBAL MODEL")

        time.sleep(1)

        weights_to_send = [w.tolist() for w in self.current_global_weights]

        if self.current_global_weights:
            logging.info("[Server] Sending current global model to all clients.")
            _log_weights("Global model (broadcast)", self.current_global_weights)
        else:
            logging.info("[Server] No global model yet — clients will use their local init weights.")

        payload = json.dumps({
            "meta": {"msg_type": "global_model", "round": 2},
            "data": {"global_weights": weights_to_send},
        })
        self._publish(PayloadBuilder.get_server_broadcast_topic(), payload)

    # ---------------------------------------------------------------------- #
    #  ROUND 2 — Collect masked inputs                                       #
    # ---------------------------------------------------------------------- #

    def _execute_round_2(self, client_id: str, data: dict):
        if self.r3_triggered or "masked_weights" not in data:
            return

        self.y_u_payloads[client_id] = data["masked_weights"]
        self.surviving_clients.add(client_id)

        if self._known_mask_length is None:
            self._known_mask_length = data.get("mask_length", len(data["masked_weights"]))

        logging.info(
            f"[Server] R2 — Masked input received from {client_id}  "
            f"({len(self.surviving_clients)}/{self.expected_k})"
        )

        if len(self.surviving_clients) == self.expected_k and not self.r3_triggered:
            self.r3_triggered = True
            logging.info("[Server] All masked inputs collected. Requesting unmasking shares...")
            time.sleep(1)
            payload = json.dumps({
                "meta": {"msg_type": "dropout_list", "round": 3},
                "data": {"surviving_clients": list(self.surviving_clients)},
            })
            self._publish(PayloadBuilder.get_server_broadcast_topic(), payload)

    # ---------------------------------------------------------------------- #
    #  ROUND 3 — Collect recovery shares                                     #
    # ---------------------------------------------------------------------- #

    def _execute_round_3(self, client_id: str, data: dict):
        # PayloadBuilder.build_round_3_payload nests the dict under "recovery_payload"
        recovery = data.get("recovery_payload")

        if self.finalized or not recovery:
            logging.warning(f"[Server] R3 — Unexpected payload from {client_id}, skipping.")
            return

        self.r3_received.add(client_id)

        logging.info(
            f"[Server] R3 — Recovery shares received from {client_id}  "
            f"({len(self.r3_received)}/{len(self.surviving_clients)})"
        )

        for target_id, b64_share in recovery.get("b_u_shares", {}).items():
            share = base64.b64decode(b64_share) if isinstance(b64_share, str) else bytes(b64_share)
            self.b_u_shares_pool.setdefault(target_id, []).append(share)

        for target_id, b64_share in recovery.get("s_sk_shares", {}).items():
            share = base64.b64decode(b64_share) if isinstance(b64_share, str) else bytes(b64_share)
            self.s_sk_shares_pool.setdefault(target_id, []).append(share)

        if len(self.r3_received) == len(self.surviving_clients) and not self.finalized:
            self.finalized = True
            self._finalize_aggregation()

    # ---------------------------------------------------------------------- #
    #  Finalization — cryptographic unmasking + FedAvg                       #
    # ---------------------------------------------------------------------- #

    def _finalize_aggregation(self):
        _section_header(f"ROUND {self.round_number} — SECURE AGGREGATION")
        time.sleep(2)

        FIELD_MODULUS = 2**32
        mask_len      = self._known_mask_length
        num_survivors = len(self.surviving_clients)

        # Step 1 — Sum masked inputs (modular)
        logging.info(f"[Server] Summing {num_survivors} masked inputs (mod 2^32)...")
        masked_sum = [sum(x) % FIELD_MODULUS for x in zip(*self.y_u_payloads.values())]

        # Step 2 — Subtract survivor self-masks (b_u)
        logging.info("[Server] Removing self-masks (b_u) for each survivor...")
        for survivor_id in self.surviving_clients:
            shares     = self.b_u_shares_pool.get(survivor_id, [])
            b_u_seed   = combine_shares(shares[: self.t_threshold])
            b_u_vector = self.crypto.generate_self_mask(b_u_seed, mask_len)
            masked_sum = [(v - m) % FIELD_MODULUS for v, m in zip(masked_sum, b_u_vector)]

        # Step 3 — Remove pairwise masks for dropped clients (if any)
        dropped_clients = self.active_clients - self.surviving_clients
        if dropped_clients:
            logging.info(f"[Server] Removing pairwise masks for dropped clients: {dropped_clients}...")
            for dropped_id in dropped_clients:
                shares      = self.s_sk_shares_pool.get(dropped_id, [])
                s_sk_bytes  = combine_shares(shares[: self.t_threshold])
                dropped_sSK = x25519.X25519PrivateKey.from_private_bytes(s_sk_bytes)

                dropped_shared_seeds = {}
                for survivor_id in self.surviving_clients:
                    survivor_sPK_bytes = base64.b64decode(self.public_keys_registry[survivor_id]["sPK"])
                    survivor_sPK = x25519.X25519PublicKey.from_public_bytes(survivor_sPK_bytes)
                    dropped_shared_seeds[survivor_id] = dropped_sSK.exchange(survivor_sPK)

                pairwise_masks = self.crypto.generate_pairwise_masks(dropped_shared_seeds, mask_len)
                for survivor_id, mask_vec in pairwise_masks.items():
                    sign = 1 if survivor_id > dropped_id else -1
                    masked_sum = [(v - sign * m) % FIELD_MODULUS for v, m in zip(masked_sum, mask_vec)]

        # Step 4 — Dequantize: integer sum → float sum
        logging.info("[Server] Dequantizing integer sum to float weights...")
        dequantized_flat = dequantize(
            [np.array(masked_sum)],
            clipping_range=10.0,
            target_range=2**24,
            num_survivors=num_survivors,
        )[0]

        # Step 5 — Reshape flat vector → LR weight structure
        summed_arrays = reshape_list_to_ndarrays(dequantized_flat, self.model_dimensions)

        # Step 6 — FedAvg: divide by number of survivors
        logging.info(f"[Server] Applying FedAvg  (÷ K={num_survivors})...")
        self.current_global_weights = [arr / num_survivors for arr in summed_arrays]

        # Metrics: round ends once the global model is ready
        if self.metrics:
            self.metrics.round_end(self.round_number)

        # Round summary
        _section_header(f"ROUND {self.round_number} — RESULT")
        logging.info("[Server] New Global Model (FedAvg via SecAgg):")
        _log_weights("Global model", self.current_global_weights)

        self.round_number += 1
        self._schedule_next_round()

    # ---------------------------------------------------------------------- #
    #  Next-round scheduling                                                 #
    # ---------------------------------------------------------------------- #

    def _schedule_next_round(self):
        def auto_start():
            logging.info(f"[Server] Next round in 10 s  →  Round {self.round_number}")
            time.sleep(10)
            self._reset_state_pools()
            _section_header(f"ROUND {self.round_number} — START")
            payload = json.dumps({
                "meta": {"msg_type": "ignition", "round": 0},
                "data": {"command": "ignite_fl"},
            })
            self._publish(PayloadBuilder.get_server_broadcast_topic(), payload)

        threading.Thread(target=auto_start, daemon=True).start()

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

def _log_weights(source: str, weights: list, label: str = ""):
    component_labels = ["coef", "intercept"]
    for i, w in enumerate(weights):
        lbl = component_labels[i] if i < len(component_labels) else f"component_{i}"
        logging.info(f"  [{source}]  [{lbl}]  {np.round(w, 6)}")


def _section_header(title: str):
    bar = "─" * 60
    logging.info(f"\n{bar}")
    logging.info(f"  {title}")
    logging.info(f"{bar}")