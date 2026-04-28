import json
import logging
import threading
import time
import numpy as np
from fl_core.fedavg_logic import aggregate


class VanillaFLServer:
    def __init__(self, mqtt_handler, expected_k: int, metrics=None):
        self.mqtt       = mqtt_handler
        self.expected_k = expected_k
        self.metrics    = metrics          # MetricsCollector | None

        self.active_clients         = set()
        self.received_weights       = {}   # {client_id: [coef_vec, intercept_vec]}
        self.current_global_weights = []
        self.round_number           = 1

    # ---------------------------------------------------------------------- #
    #  MQTT interface                                                         #
    # ---------------------------------------------------------------------- #

    def process_mqtt_message(self, topic: str, payload: str):
        if self.metrics:
            self.metrics.record_recv_bytes(len(payload.encode("utf-8")))
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
            f"[Server] Client connected: {client_id}  "
            f"({len(self.active_clients)}/{self.expected_k})"
        )

        if len(self.active_clients) == self.expected_k:
            logging.info("[Server] All clients connected. Starting in 3 s...")
            time.sleep(3)
            self._broadcast_ignition()

    def _broadcast_ignition(self):
        _section_header(f"ROUND {self.round_number} — START")

        if self.metrics:
            self.metrics.round_start(self.round_number)

        payload = json.dumps({
            "meta": {"msg_type": "ignition", "round": self.round_number},
            "data": {}
        })
        self._publish("fl/server/broadcast", payload)
        logging.info(f"[Server] Ignition broadcast sent to all clients.")

    # ---------------------------------------------------------------------- #
    #  Receiving weights                                                      #
    # ---------------------------------------------------------------------- #

    def _handle_incoming_weights(self, client_id: str, data: dict):
        if "weights" not in data:
            return

        client_weights = [np.array(w) for w in data["weights"]]
        self.received_weights[client_id] = client_weights

        _log_weights(f"Server ← {client_id}", client_weights, label="Received")
        logging.info(
            f"[Server] Weights received: {client_id}  "
            f"({len(self.received_weights)}/{self.expected_k})"
        )

        if len(self.received_weights) == self.expected_k:
            time.sleep(1)
            self._aggregate_and_update()

    # ---------------------------------------------------------------------- #
    #  FedAvg aggregation                                                     #
    # ---------------------------------------------------------------------- #

    def _aggregate_and_update(self):
        _section_header(f"ROUND {self.round_number} — FEDAVG AGGREGATION")

        K              = self.expected_k
        all_weights    = self.received_weights
        num_components = len(next(iter(all_weights.values())))

        logging.info("[Server] Client contributions:")
        for cid, weights in all_weights.items():
            _log_weights(cid, weights)

        logging.info(f"\n[Server] Computing FedAvg (averaging over K={K} clients)...")
        summed = [
            np.zeros_like(next(iter(all_weights.values()))[i], dtype=float)
            for i in range(num_components)
        ]
        for weights in all_weights.values():
            for i, vec in enumerate(weights):
                summed[i] += vec

        self.current_global_weights = aggregate(summed, K)

        logging.info("\n[Server] FedAvg result — New Global Model:")
        _log_weights("Global model", self.current_global_weights)

        # Metrics: round ends once the global model is computed
        if self.metrics:
            self.metrics.round_end(self.round_number)

        _section_header(f"ROUND {self.round_number} — COMPLETE")

        self.round_number += 1
        self._schedule_next_round()

    # ---------------------------------------------------------------------- #
    #  Next-round scheduling                                                 #
    # ---------------------------------------------------------------------- #

    def _schedule_next_round(self):
        self.received_weights.clear()

        def auto_start():
            logging.info(f"[Server] Next round in 5 min  →  Round {self.round_number}")
            time.sleep(300)

            _section_header(f"ROUND {self.round_number} — START")

            if self.metrics:
                self.metrics.round_start(self.round_number)

            logging.info("[Server] Broadcasting global model to all clients...")
            _log_weights("Global model (broadcast)", self.current_global_weights)

            weights_to_send = [w.tolist() for w in self.current_global_weights]
            payload = json.dumps({
                "meta": {"msg_type": "global_model"},
                "data": {"global_weights": weights_to_send}
            })
            self._publish("fl/server/broadcast", payload)

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

def _log_weights(source: str, weights: list, label: str = "Weights"):
    component_labels = ["coef", "intercept"]
    logging.info(f"  [{source}] {label}:")
    for i, w in enumerate(weights):
        lbl = component_labels[i] if i < len(component_labels) else f"component_{i}"
        logging.info(f"    [{lbl}]  {np.round(w, 6)}")


def _section_header(title: str):
    bar = "─" * 60
    logging.info(f"\n{bar}")
    logging.info(f"  {title}")
    logging.info(f"{bar}")