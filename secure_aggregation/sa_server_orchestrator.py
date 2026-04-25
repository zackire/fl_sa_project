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
    ):
        self.mqtt             = mqtt_handler
        self.t_threshold      = t_threshold
        self.expected_k       = expected_k
        self.crypto           = crypto_stack
        self.model_dimensions = model_dimensions   # list of shapes, e.g. [(10,), (1,)]
        self.round_number     = 1

        # Global model memory (persists across rounds)
        self.current_global_weights: List[np.ndarray] = []

        self._reset_state_pools()

    # ---------------------------------------------------------------------- #
    #  State reset (called at start of every new round)                      #
    # ---------------------------------------------------------------------- #

    def _reset_state_pools(self):
        self.active_clients       = set()
        self.surviving_clients    = set()
        self.public_keys_registry = {}
        self._known_mask_length   = None
        self.y_u_payloads:    Dict[str, List[float]] = {}
        self.b_u_shares_pool: Dict[str, List[bytes]] = {}
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
            logging.error(f"[Server] Failure on topic {topic}: {e}", exc_info=True)

    # ---------------------------------------------------------------------- #
    #  ROUND 0 — Key registry collection                                     #
    # ---------------------------------------------------------------------- #

    def _execute_round_0(self, client_id: str, data: dict):
        if "public_keys" not in data:
            return

        self.public_keys_registry[client_id] = data["public_keys"]
        self.active_clients.add(client_id)
        logging.info(
            f"[Server] R0 — Keys from {client_id}. "
            f"({len(self.active_clients)}/{self.expected_k})"
        )

        if len(self.active_clients) == self.expected_k:
            logging.info("[Server] Quorum reached. Broadcasting key registry (Round 1)...")
            time.sleep(1)
            payload = json.dumps({
                "meta": {"msg_type": "key_registry", "round": 1},
                "data": {
                    "all_public_keys": self.public_keys_registry,
                    "t_threshold": self.t_threshold,
                },
            })
            self.mqtt.publish(PayloadBuilder.get_server_broadcast_topic(), payload)

    # ---------------------------------------------------------------------- #
    #  ROUND 1 — Postmaster (route encrypted shares to recipients)           #
    # ---------------------------------------------------------------------- #

    def _execute_round_1(self, source_id: str, data: dict):
        if "encrypted_shares" not in data:
            return

        for target_id, ciphertext_b64 in data["encrypted_shares"].items():
            routed = PayloadBuilder.build_round_1_payload(source_id, {target_id: ciphertext_b64})
            self.mqtt.publish(PayloadBuilder.get_client_inbox_topic(target_id), routed)
            logging.info(f"[Server] R1 — Routed share from {source_id} → {target_id}.")

        self.r1_received.add(source_id)

        if len(self.r1_received) == self.expected_k and not self.r2_triggered:
            self.r2_triggered = True
            self._trigger_round_2()

    def _trigger_round_2(self):
        logging.info("\n[Server] ====== ROUND 2: BROADCASTING GLOBAL MODEL ======")
        time.sleep(1)

        # First round: global weights are empty — clients will use their fixed init weights
        weights_to_send = [w.tolist() for w in self.current_global_weights]
        logging.info(f"[Server] Sending global model ({len(weights_to_send)} components).")

        if weights_to_send:
            self._log_weights("Current global model being broadcast", self.current_global_weights)

        payload = json.dumps({
            "meta": {"msg_type": "global_model", "round": 2},
            "data": {"global_weights": weights_to_send},
        })
        self.mqtt.publish(PayloadBuilder.get_server_broadcast_topic(), payload)

    # ---------------------------------------------------------------------- #
    #  ROUND 2 — Masked input collection                                     #
    # ---------------------------------------------------------------------- #

    def _execute_round_2(self, client_id: str, data: dict):
        if self.r3_triggered or "masked_weights" not in data:
            return

        self.y_u_payloads[client_id] = data["masked_weights"]
        self.surviving_clients.add(client_id)

        if self._known_mask_length is None:
            self._known_mask_length = data.get("mask_length", len(data["masked_weights"]))

        logging.info(
            f"[Server] R2 — Masked input Y_u from {client_id}. "
            f"({len(self.surviving_clients)}/{self.expected_k})"
        )
        logging.info(
            f"[Server]   Y_u first 5 elements: {self.y_u_payloads[client_id][:5]}"
        )

        if len(self.surviving_clients) == self.expected_k and not self.r3_triggered:
            self.r3_triggered = True
            logging.info("[Server] All masked inputs received. Requesting recovery shares (Round 3)...")
            time.sleep(1)
            payload = json.dumps({
                "meta": {"msg_type": "dropout_list", "round": 3},
                "data": {"surviving_clients": list(self.surviving_clients)},
            })
            self.mqtt.publish(PayloadBuilder.get_server_broadcast_topic(), payload)

    # ---------------------------------------------------------------------- #
    #  ROUND 3 — Unmasking & dropout recovery                               #
    # ---------------------------------------------------------------------- #

    def _execute_round_3(self, client_id: str, data: dict):
        if "recovery_payload" not in data:
            return

        self.r3_received.add(client_id)
        logging.info(
            f"[Server] R3 — Recovery shares from {client_id}. "
            f"({len(self.r3_received)}/{len(self.surviving_clients)})"
        )
        recovery = data["recovery_payload"]

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
        self._section_header(f"SECURE AGGREGATION — ROUND {self.round_number}")
        time.sleep(2)

        FIELD_MODULUS = 2**32
        mask_len      = self._known_mask_length

        # ------------------------------------------------------------------ #
        #  Step 1 — Sum masked inputs (modular)                               #
        # ------------------------------------------------------------------ #
        logging.info("\n[Server] === Step 1: Summing masked inputs Y_u (mod 2^32) ===")
        for cid, y_u in self.y_u_payloads.items():
            logging.info(f"  Y_u[{cid}] first 5: {y_u[:5]}")

        masked_sum = [sum(x) % FIELD_MODULUS for x in zip(*self.y_u_payloads.values())]
        logging.info(f"  Σ Y_u (first 5): {masked_sum[:5]}")

        # ------------------------------------------------------------------ #
        #  Step 2 — Subtract survivor self-masks (b_u)                       #
        # ------------------------------------------------------------------ #
        logging.info("\n[Server] === Step 2: Subtracting survivor self-masks (b_u) ===")
        for survivor_id in self.surviving_clients:
            shares    = self.b_u_shares_pool.get(survivor_id, [])
            b_u_seed  = combine_shares(shares[: self.t_threshold])
            b_u_vector = self.crypto.generate_self_mask(b_u_seed, mask_len)
            logging.info(f"  b_u[{survivor_id}] first 5: {b_u_vector[:5]}")
            masked_sum = [(v - m) % FIELD_MODULUS for v, m in zip(masked_sum, b_u_vector)]

        logging.info(f"  After b_u removal (first 5): {masked_sum[:5]}")

        # ------------------------------------------------------------------ #
        #  Step 3 — Subtract dropped client pairwise masks                   #
        # ------------------------------------------------------------------ #
        dropped_clients = self.active_clients - self.surviving_clients
        if dropped_clients:
            logging.info("\n[Server] === Step 3: Removing pairwise masks for dropped clients ===")
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
                logging.info(
                    f"  Removing pairwise mask: {dropped_id}↔{survivor_id} "
                    f"sign={'+' if sign == 1 else '-'} first 5: {mask_vec[:5]}"
                )
                masked_sum = [(v - sign * m) % FIELD_MODULUS for v, m in zip(masked_sum, mask_vec)]

        logging.info(f"  Clean integer sum (first 5): {masked_sum[:5]}")

        # ------------------------------------------------------------------ #
        #  Step 4 — Dequantize: integer sum → float sum                      #
        # ------------------------------------------------------------------ #
        logging.info("\n[Server] === Step 4: Dequantizing integer sum → float weights ===")
        num_survivors = len(self.surviving_clients)

        # dequantize works on a list-of-arrays; wrap masked_sum as one flat array
        dequantized_flat = dequantize(
            [np.array(masked_sum)],
            clipping_range=10.0,
            target_range=2**24,
            num_survivors=num_survivors,
        )[0]

        logging.info(f"  Dequantized flat sum (first 5): {np.round(dequantized_flat[:5], 6)}")

        # ------------------------------------------------------------------ #
        #  Step 5 — Reshape flat sum back to LR weight structure             #
        # ------------------------------------------------------------------ #
        logging.info("\n[Server] === Step 5: Reshaping flat vector → LR weight structure ===")
        summed_arrays = reshape_list_to_ndarrays(dequantized_flat, self.model_dimensions)

        component_labels = ["coef", "intercept"]
        for i, arr in enumerate(summed_arrays):
            lbl = component_labels[i] if i < len(component_labels) else f"component_{i}"
            logging.info(
                f"  [{lbl}] shape={arr.shape} | "
                f"sum-of-clients={np.round(arr, 6)} | "
                f"L2={np.linalg.norm(arr):.6f}"
            )

        # ------------------------------------------------------------------ #
        #  Step 6 — FedAvg: divide sum by K                                  #
        # ------------------------------------------------------------------ #
        logging.info(f"\n[Server] === Step 6: FedAvg — dividing by K={num_survivors} ===")
        self.current_global_weights = [arr / num_survivors for arr in summed_arrays]

        for i, (s, g) in enumerate(zip(summed_arrays, self.current_global_weights)):
            lbl = component_labels[i] if i < len(component_labels) else f"component_{i}"
            logging.info(f"\n  [{lbl}]")
            logging.info(f"    Σ        = {np.round(s, 6)}")
            logging.info(f"    Σ / {num_survivors}    = {np.round(g, 6)}")
            logging.info(f"    L2 norm  = {np.linalg.norm(g):.6f}")

        # ------------------------------------------------------------------ #
        #  Round summary                                                      #
        # ------------------------------------------------------------------ #
        self._section_header(f"ROUND {self.round_number} RESULTS")
        logging.info("[Server] Final Global Model (FedAvg via SecAgg):")
        self._log_weights("Global weights", self.current_global_weights)
        total_l2 = sum(np.linalg.norm(w) for w in self.current_global_weights)
        logging.info(f"[Server] Total L2 norm: {total_l2:.6f}")

        self.round_number += 1
        self._schedule_next_round()

    # ---------------------------------------------------------------------- #
    #  Next-round scheduling                                                  #
    # ---------------------------------------------------------------------- #

    def _schedule_next_round(self):
        def auto_start():
            logging.info(f"[Server] Reading time... Round {self.round_number} begins in 10 s.")
            time.sleep(10)
            self._reset_state_pools()
            self._section_header(f"STARTING ROUND {self.round_number}")
            payload = json.dumps({
                "meta": {"msg_type": "ignition", "round": 0},
                "data": {"command": "ignite_fl"},
            })
            self.mqtt.publish("fl/server/broadcast", payload)

        threading.Thread(target=auto_start, daemon=True).start()

    # ---------------------------------------------------------------------- #
    #  Logging helpers                                                        #
    # ---------------------------------------------------------------------- #

    def _log_weights(self, label: str, weights: list):
        component_labels = ["coef", "intercept"]
        logging.info(f"[Server] {label}:")
        for i, w in enumerate(weights):
            lbl = component_labels[i] if i < len(component_labels) else f"component_{i}"
            logging.info(
                f"  [{lbl}] shape={w.shape} | values={np.round(w, 6)} | "
                f"sum={np.sum(w):.6f} | L2={np.linalg.norm(w):.6f}"
            )

    @staticmethod
    def _section_header(title: str):
        bar = "=" * 58
        logging.info(f"\n{bar}")
        logging.info(f"  {title}")
        logging.info(f"{bar}")