import json
import logging
import threading
import time
import numpy as np
from fl_core.fedavg_logic import aggregate
from communication.payload_builder import PayloadBuilder


class VanillaFLServer:
    def __init__(self, mqtt_handler, expected_k: int):
        self.mqtt = mqtt_handler
        self.expected_k = expected_k

        self.active_clients    = set()
        self.received_weights  = {}          # {client_id: [coef_vec, intercept_vec]}
        self.current_global_weights = []
        self.round_number = 1

    # ---------------------------------------------------------------------- #
    #  MQTT interface                                                         #
    # ---------------------------------------------------------------------- #

    def process_mqtt_message(self, topic: str, payload: str):
        full_payload = json.loads(payload)
        meta = full_payload.get("meta", {})
        data = full_payload.get("data", {})

        client_id = meta.get("client_id", topic.split("/")[-2])
        msg_type  = meta.get("msg_type")

        if msg_type == "checkin":
            self._handle_checkin(client_id)
        elif msg_type == "raw_weights":
            self._handle_incoming_weights(client_id, data)

    # ---------------------------------------------------------------------- #
    #  Check-in / Ignition                                                   #
    # ---------------------------------------------------------------------- #

    def _handle_checkin(self, client_id: str):
        if client_id in self.active_clients:
            return

        self.active_clients.add(client_id)
        logging.info(
            f"[Server] Check-in: {client_id} ready. "
            f"({len(self.active_clients)}/{self.expected_k})"
        )

        if len(self.active_clients) == self.expected_k:
            logging.info("[Server] ALL CLIENTS CONNECTED — starting in 3 s...")
            time.sleep(3)
            self._broadcast_ignition()

    def _broadcast_ignition(self):
        self._section_header(f"STARTING ROUND {self.round_number}")
        payload = json.dumps({
            "meta": {"msg_type": "ignition", "round": self.round_number},
            "data": {}
        })
        self.mqtt.publish("fl/server/broadcast", payload)

    # ---------------------------------------------------------------------- #
    #  Receiving weights                                                      #
    # ---------------------------------------------------------------------- #

    def _handle_incoming_weights(self, client_id: str, data: dict):
        if "weights" not in data:
            return

        client_weights = [np.array(w) for w in data["weights"]]
        self.received_weights[client_id] = client_weights

        logging.info(f"\n[Server] ====== RECEIVED FROM {client_id} ======")
        self._log_weights(client_id, client_weights)

        if len(self.received_weights) == self.expected_k:
            time.sleep(1)
            self._aggregate_and_update()

    # ---------------------------------------------------------------------- #
    #  FedAvg aggregation                                                     #
    # ---------------------------------------------------------------------- #

    def _aggregate_and_update(self):
        self._section_header(f"FEDAVG AGGREGATION — ROUND {self.round_number}")
        time.sleep(2)

        K = self.expected_k
        all_weights = self.received_weights          # dict {cid: [coef, intercept]}
        num_components = len(next(iter(all_weights.values())))
        component_labels = ["coef", "intercept"]

        # ------------------------------------------------------------------ #
        #  Step 1 — show each client's contribution side-by-side             #
        # ------------------------------------------------------------------ #
        logging.info("\n[Server] === Step 1: Received weight vectors ===")
        for cid, weights in all_weights.items():
            self._log_weights(cid, weights)

        # ------------------------------------------------------------------ #
        #  Step 2 — element-wise summation                                    #
        # ------------------------------------------------------------------ #
        logging.info("\n[Server] === Step 2: Element-wise summation across clients ===")
        summed_weights = []

        for i in range(num_components):
            label = component_labels[i] if i < len(component_labels) else f"component_{i}"
            logging.info(f"\n  [{label}]  SUM:")

            component_sum = np.zeros_like(next(iter(all_weights.values()))[i], dtype=float)

            for cid, weights in all_weights.items():
                vec = weights[i]
                logging.info(f"    + {cid}: {np.round(vec, 6)}")
                component_sum += vec

            logging.info(f"    {'─'*50}")
            logging.info(f"    Σ         {np.round(component_sum, 6)}")
            logging.info(
                f"    sum={np.sum(component_sum):.6f} | "
                f"L2={np.linalg.norm(component_sum):.6f}"
            )
            summed_weights.append(component_sum)

        # ------------------------------------------------------------------ #
        #  Step 3 — divide by K (FedAvg)                                     #
        # ------------------------------------------------------------------ #
        logging.info(f"\n[Server] === Step 3: Divide by K={K} (FedAvg average) ===")

        self.current_global_weights = aggregate(summed_weights, K)

        for i, (s, g) in enumerate(zip(summed_weights, self.current_global_weights)):
            label = component_labels[i] if i < len(component_labels) else f"component_{i}"
            logging.info(f"\n  [{label}]")
            logging.info(f"    Σ / {K}  =  {np.round(s, 6)}  /  {K}")
            logging.info(f"    global  =  {np.round(g, 6)}")
            logging.info(
                f"    sum={np.sum(g):.6f} | "
                f"L2={np.linalg.norm(g):.6f}"
            )

        # ------------------------------------------------------------------ #
        #  Step 4 — round summary                                            #
        # ------------------------------------------------------------------ #
        self._section_header(f"ROUND {self.round_number} RESULTS")
        logging.info("[Server] Final Global Model (FedAvg output):")
        for i, g in enumerate(self.current_global_weights):
            label = component_labels[i] if i < len(component_labels) else f"component_{i}"
            logging.info(
                f"  [{label}] {np.round(g, 6)}  "
                f"| L2={np.linalg.norm(g):.6f}"
            )

        total_l2 = sum(np.linalg.norm(w) for w in self.current_global_weights)
        logging.info(f"[Server] Total L2 norm (all components): {total_l2:.6f}")

        self.round_number += 1
        self._prompt_next_round()

    # ---------------------------------------------------------------------- #
    #  Next-round scheduling                                                 #
    # ---------------------------------------------------------------------- #

    def _prompt_next_round(self):
        self.received_weights.clear()

        def auto_start():
            logging.info(
                f"[Server] Reading time... Round {self.round_number} begins in 10 s."
            )
            time.sleep(10)

            self._section_header(f"STARTING ROUND {self.round_number}")
            logging.info("[Server] Broadcasting new Global Model to all clients...")

            weights_to_send = [w.tolist() for w in self.current_global_weights]
            payload = json.dumps({
                "meta": {"msg_type": "global_model"},
                "data": {"global_weights": weights_to_send}
            })
            self.mqtt.publish("fl/server/broadcast", payload)

        threading.Thread(target=auto_start, daemon=True).start()

    # ---------------------------------------------------------------------- #
    #  Logging helpers                                                        #
    # ---------------------------------------------------------------------- #

    def _log_weights(self, source: str, weights: list):
        component_labels = ["coef", "intercept"]
        for i, w in enumerate(weights):
            label = component_labels[i] if i < len(component_labels) else f"component_{i}"
            logging.info(
                f"  [{source}][{label}] shape={w.shape} | "
                f"values={np.round(w, 6)} | "
                f"sum={np.sum(w):.6f} | "
                f"L2={np.linalg.norm(w):.6f}"
            )

    @staticmethod
    def _section_header(title: str):
        bar = "=" * 58
        logging.info(f"\n{bar}")
        logging.info(f"  {title}")
        logging.info(f"{bar}")